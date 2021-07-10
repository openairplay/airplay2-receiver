import struct
import socket
import hashlib
import threading

from hexdump import hexdump

import hkdf
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
import nacl.signing
from Crypto.Cipher import ChaCha20_Poly1305

from . import srp


class PairingMethod:
    PAIR_SETUP = b'\x00'
    PAIR_SETUP_AUTH = b'\x01'
    PAIR_VERIFY = b'\x02'
    ADD_PAIRING = b'\x03'
    REMOVE_PAIRING = b'\x04'
    LIST_PAIRINGS = b'\x05'


class PairingErrors:
    RESERVED = 0
    UNKNOWN = 1
    AUTHENTICATION = 2
    BACKOFF = 3
    MAXPEERS = 4
    MAXTRIES = 5
    UNAVAILABLE = 6
    BUSY = 7


class PairingFlags:
    TRANSIENT = b'\x10'


class PairingState:
    M1 = b'\x01'
    M2 = b'\x02'
    M3 = b'\x03'
    M4 = b'\x04'
    M5 = b'\x05'
    M6 = b'\x06'


class Tlv8:
    class Tag:
        METHOD = 0
        IDENTIFIER = 1
        SALT = 2
        PUBLICKEY = 3
        PROOF = 4
        ENCRYPTEDDATA = 5
        STATE = 6
        ERROR = 7
        RETRYDELAY = 8
        CERTIFICATE = 9
        SIGNATURE = 10
        PERMISSIONS = 11
        FRAGMENTDATA = 12
        FRAGMENTLAST = 13
        FLAGS = 19
        SEPARATOR = 255

    @staticmethod
    def decode(req, debug=True):
        res = {}
        ptr = 0
        while ptr < len(req):
            tag = req[ptr]
            length = req[ptr + 1]
            value = req[ptr + 2:ptr + 2 + length]
            # print("dec tag=%d length=%d value=%s" % (tag, length, value.hex()))
            if tag in res:
                res[tag] = res[tag] + value
            else:
                res[tag] = value
            ptr += 2 + length

        return res

    @staticmethod
    def encode(req):
        res = b""
        for i in range(0, len(req), 2):
            tag = req[i]
            value = req[i + 1]
            length = len(value)

            # print("enc tag=%d length=%d value=%s" % (tag, length, value.hex()))
            if length <= 255:
                res += bytes([tag]) + bytes([length]) + value
            else:
                for i in range(0, length // 255):
                    res += bytes([tag]) + b"\xff" + value[i * 255:(i + 1) * 255]
                left = length % 255
                res += bytes([tag]) + bytes([left]) + value[-left:]

        return res


class Hap:
    def __init__(self):
        self.transient = False
        self.encrypted = False
        self.pair_setup_steps_n = 5

    def request(self, req):
        req = Tlv8.decode(req)

        if req[Tlv8.Tag.METHOD] == PairingMethod.PAIR_SETUP_AUTH:
            res = self.pair_setup(req)
        return Tlv8.encode(res)

    def pair_setup(self, req):
        req = Tlv8.decode(req)

        if req[Tlv8.Tag.STATE] == PairingState.M1 and \
                req[Tlv8.Tag.METHOD] == PairingMethod.PAIR_SETUP and \
                Tlv8.Tag.FLAGS in req and \
                req[Tlv8.Tag.FLAGS] == PairingFlags.TRANSIENT:
            self.transient = True
            self.pair_setup_steps_n = 2

        if req[Tlv8.Tag.STATE] == PairingState.M1:
            print("-----\tPair-Setup [1/%d]" % self.pair_setup_steps_n)
            res = self.pair_setup_m1_m2()
        elif req[Tlv8.Tag.STATE] == PairingState.M3:
            print("-----\tPair-Setup [2/%d]" % self.pair_setup_steps_n)
            res = self.pair_setup_m3_m4(req[Tlv8.Tag.PUBLICKEY], req[Tlv8.Tag.PROOF])
            if self.transient:
                self.encrypted = True
        elif req[Tlv8.Tag.STATE] == PairingState.M5:
            res = self.pair_setup_m5_m6(req[Tlv8.Tag.ENCRYPTEDDATA])
        return Tlv8.encode(res)

    def pair_verify(self, req):
        req = Tlv8.decode(req)

        if req[Tlv8.Tag.STATE] == PairingState.M1:
            print("-----\tPair-Verify [1/2]")
            res = self.pair_verify_m1_m2(req[Tlv8.Tag.PUBLICKEY])
        elif req[Tlv8.Tag.STATE] == PairingState.M3:
            print("-----\tPair-Verify [2/2]")
            res = self.pair_verify_m3_m4(req[Tlv8.Tag.ENCRYPTEDDATA])
            self.encrypted = True
        return Tlv8.encode(res)

    def pair_setup_m1_m2(self):
        self.ctx = srp.SRPServer(b"Pair-Setup", b"3939")
        server_public = self.ctx.public_key
        salt = self.ctx.salt

        return [
            Tlv8.Tag.STATE, PairingState.M2,
            Tlv8.Tag.SALT, salt,
            Tlv8.Tag.PUBLICKEY, server_public
        ]

    def pair_setup_m3_m4(self, client_public, client_proof):
        self.ctx.set_client_public(client_public)
        assert self.ctx.verify(client_proof)

        self.accessory_shared_key = self.ctx.session_key
        server_proof = self.ctx.proof

        return [
            Tlv8.Tag.STATE, PairingState.M4,
            Tlv8.Tag.PROOF, server_proof
        ]

    def pair_setup_m5_m6(self, encrypted):
        print("-----\tPair-Setup [3/5]")
        dec_tlv, session_key = self.pair_setup_m5_m6_1(encrypted)
        print("-----\tPair-Setup [4/5]")
        self.pair_setup_m5_m6_2(dec_tlv)
        print("-----\tPair-Setup [5/5]")
        enc_tlv, tag = self.pair_setup_m5_m6_3(session_key)

        return [
            Tlv8.Tag.STATE, PairingState.M6,
            Tlv8.Tag.ENCRYPTEDDATA, enc_tlv + tag
        ]

    def pair_setup_m5_m6_1(self, encrypted):
        prk = hkdf.hkdf_extract(b"Pair-Setup-Encrypt-Salt", self.ctx.session_key)
        session_key = hkdf.hkdf_expand(prk, b"Pair-Setup-Encrypt-Info", 32)
        c = ChaCha20_Poly1305.new(key=session_key, nonce=b"PS-Msg05")
        enc_tlv = encrypted[:-16]
        tag = encrypted[-16:]
        dec_tlv = c.decrypt_and_verify(enc_tlv, tag)

        return Tlv8.decode(dec_tlv), session_key

    def pair_setup_m5_m6_2(self, dec_tlv):
        self.device_id = dec_tlv[Tlv8.Tag.IDENTIFIER]
        self.device_ltpk = dec_tlv[Tlv8.Tag.PUBLICKEY]
        device_sig = dec_tlv[Tlv8.Tag.SIGNATURE]

        prk = hkdf.hkdf_extract(b"Pair-Setup-Controller-Sign-Salt", self.ctx.session_key)
        device_x = hkdf.hkdf_expand(prk, b"Pair-Setup-Controller-Sign-Info", 32)
        device_info = device_x + self.device_id + self.device_ltpk

        verify_key = nacl.signing.VerifyKey(self.device_ltpk)
        verify_key.verify(device_info, device_sig)

    def pair_setup_m5_m6_3(self, session_key):
        prk = hkdf.hkdf_extract(b"Pair-Setup-Accessory-Sign-Salt", self.ctx.session_key)
        accessory_x = hkdf.hkdf_expand(prk, b"Pair-Setup-Accessory-Sign-Info", 32)

        self.accessory_ltsk = nacl.signing.SigningKey.generate()
        self.accessory_ltpk = bytes(self.accessory_ltsk.verify_key)

        self.accessory_id = b"00000000-0000-0000-0000-f0989d7cbbab"

        accessory_info = accessory_x + self.accessory_id + self.accessory_ltpk
        accessory_signed = self.accessory_ltsk.sign(accessory_info)
        accessory_sig = accessory_signed.signature

        dec_tlv = Tlv8.encode([
            Tlv8.Tag.IDENTIFIER, self.accessory_id,
            Tlv8.Tag.PUBLICKEY, self.accessory_ltpk,
            Tlv8.Tag.SIGNATURE, accessory_sig
        ])

        c = ChaCha20_Poly1305.new(key=session_key, nonce=b"PS-Msg06")
        enc_tlv, tag = c.encrypt_and_digest(dec_tlv)

        return enc_tlv, tag

    def pair_verify_m1_m2(self, client_public):
        self.client_curve_public = client_public

        self.accessory_curve = x25519.X25519PrivateKey.generate()
        self.accessory_curve_public = self.accessory_curve.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        self.accessory_shared_key = self.accessory_curve.exchange(x25519.X25519PublicKey.from_public_bytes(client_public))

        accessory_info = self.accessory_curve_public + self.accessory_id + client_public
        accessory_signed = self.accessory_ltsk.sign(accessory_info)
        accessory_sig = accessory_signed.signature

        sub_tlv = Tlv8.encode([
            Tlv8.Tag.IDENTIFIER, self.accessory_id,
            Tlv8.Tag.SIGNATURE, accessory_sig
        ])

        prk = hkdf.hkdf_extract(b"Pair-Verify-Encrypt-Salt", self.accessory_shared_key)
        session_key = hkdf.hkdf_expand(prk, b"Pair-Verify-Encrypt-Info", 32)

        c = ChaCha20_Poly1305.new(key=session_key, nonce=b"PV-Msg02")
        enc_tlv, tag = c.encrypt_and_digest(sub_tlv)

        return [
            Tlv8.Tag.STATE, PairingState.M2,
            Tlv8.Tag.PUBLICKEY, self.accessory_curve_public,
            Tlv8.Tag.ENCRYPTEDDATA, enc_tlv + tag
        ]

    def pair_verify_m3_m4(self, encrypted):
        prk = hkdf.hkdf_extract(b"Pair-Verify-Encrypt-Salt", self.accessory_shared_key)
        session_key = hkdf.hkdf_expand(prk, b"Pair-Verify-Encrypt-Info", 32)

        c = ChaCha20_Poly1305.new(key=session_key, nonce=b"PV-Msg03")
        enc_tlv = encrypted[:-16]
        tag = encrypted[-16:]
        dec_tlv = c.decrypt_and_verify(enc_tlv, tag)

        sub_tlv = Tlv8.decode(dec_tlv)
        device_id = sub_tlv[Tlv8.Tag.IDENTIFIER]
        device_sig = sub_tlv[Tlv8.Tag.SIGNATURE]

        device_info = self.client_curve_public + device_id + self.accessory_curve_public
        verify_key = nacl.signing.VerifyKey(self.device_ltpk)
        verify_key.verify(device_info, device_sig)

        return [
            Tlv8.Tag.STATE, PairingState.M4
        ]


#
# Inspired from HAP-Python: https://github.com/ikalchev/HAP-python
#
class HAPSocket:
    """A socket implementing the HAP crypto. Just feed it as if it is a normal socket.
    This implementation is something like a Proxy pattern - some calls to socket
    methods are wrapped and some are forwarded as is.
    @note: HAP requires something like HTTP push. This implies we can have regular HTTP
    response and an outbound HTTP push at the same time on the same socket - a race
    condition. Thus, HAPSocket implements exclusive access to send and sendall to deal
    with this situation.
    """

    MAX_BLOCK_LENGTH = 0x400
    LENGTH_LENGTH = 2

    CIPHER_SALT = b"Control-Salt"
    OUT_CIPHER_INFO = b"Control-Read-Encryption-Key"
    IN_CIPHER_INFO = b"Control-Write-Encryption-Key"

    def __init__(self, sock, shared_key):
        """Initialise from the given socket."""
        self.socket = sock

        self.shared_key = shared_key
        self.out_count = 0
        self.in_count = 0
        self.out_lock = threading.RLock()  # for locking send operations

        self._set_ciphers()
        self.curr_in_total = None  # Length of the current incoming block
        self.num_in_recv = None  # Number of bytes received from the incoming block
        self.curr_in_block = None  # Bytes of the current incoming block

    def __getattr__(self, attribute_name):
        """Defer unknown behaviour to the socket"""
        return getattr(self.socket, attribute_name)

    def _get_io_refs(self):
        """Get `socket._io_refs`."""
        return self.socket._io_refs

    def _set_io_refs(self, value):
        """Set `socket._io_refs`."""
        self.socket._io_refs = value

    _io_refs = property(_get_io_refs, _set_io_refs)
    """`socket.makefile` uses a `SocketIO` to wrap the socket stream. Internally,
    this uses `socket._io_refs` directly to determine if a socket object needs to be
    closed when its FileIO object is closed.
    Because `_io_refs` is assigned as part of this process, it bypasses getattr. To get
    around this, let's make _io_refs our property and proxy calls to the socket.
    """

    def makefile(self, *args, **kwargs):
        """Return a file object that reads/writes to this object.
        We need to implement this, otherwise the socket's makefile will use the socket
        object and we won't en/decrypt.
        """
        return socket.socket.makefile(self, *args, **kwargs)

    def _set_ciphers(self):
        """Generate out/inbound encryption keys and initialise respective ciphers."""

        prk = hkdf.hkdf_extract(self.CIPHER_SALT, self.shared_key)
        self.outgoing_key = hkdf.hkdf_expand(prk, self.OUT_CIPHER_INFO, 32)

        prk = hkdf.hkdf_extract(self.CIPHER_SALT, self.shared_key)
        self.incoming_key = hkdf.hkdf_expand(prk, self.IN_CIPHER_INFO, 32)

    def _with_out_lock(func):
        """Return a function that acquires the outbound lock and executes func."""

        def _wrapper(self, *args, **kwargs):
            with self.out_lock:
                return func(self, *args, **kwargs)

        return _wrapper

    def recv_into(self, buffer, nbytes=1042, flags=0):
        """Receive and decrypt up to nbytes in the given buffer."""
        data = self.recv(nbytes, flags)
        for i, b in enumerate(data):
            buffer[i] = b
        return len(data)

    def recv(self, buflen=1042, flags=0):
        """Receive up to buflen bytes.
        The received full cipher blocks are decrypted and returned and partial cipher blocks are buffered locally.
        """
        assert not flags and buflen > self.LENGTH_LENGTH

        result = b""

        while buflen > 1:
            if self.curr_in_block is None:
                if buflen < self.LENGTH_LENGTH:
                    return result

                block_length_bytes = self.socket.recv(self.LENGTH_LENGTH)
                if not block_length_bytes:
                    return result

                assert len(block_length_bytes) == self.LENGTH_LENGTH

                self.curr_in_total = \
                    struct.unpack("H", block_length_bytes)[0] + 16
                self.num_in_recv = 0
                self.curr_in_block = b""
                buflen -= self.LENGTH_LENGTH
            else:
                part = self.socket.recv(min(buflen,
                                            self.curr_in_total - self.num_in_recv))
                actual_len = len(part)
                self.curr_in_block += part
                buflen -= actual_len
                self.num_in_recv += actual_len

                if self.num_in_recv == self.curr_in_total:
                    nonce = struct.pack("Q", self.in_count).rjust(12, b"\x00")

                    block_length = self.curr_in_total - 16
                    in_cipher = ChaCha20_Poly1305.new(key=self.incoming_key, nonce=nonce)
                    in_cipher.update(struct.pack("H", block_length))
                    dec = in_cipher.decrypt_and_verify(self.curr_in_block[:-16], self.curr_in_block[-16:])
                    result += dec
                    self.in_count += 1
                    self.curr_in_block = None
                    break

        return result

    @_with_out_lock
    def send(self, data, flags=0):
        """Encrypt and send the given data."""
        return self.sendall(data, flags)

    @_with_out_lock
    def sendall(self, data, flags=0):
        """Encrypt and send the given data."""
        assert not flags
        result = b""
        offset = 0
        total = len(data)
        while offset < total:
            length = min(total - offset, self.MAX_BLOCK_LENGTH)
            length_bytes = struct.pack("H", length)
            block = bytearray(data[offset: offset + length])
            nonce = struct.pack("Q", self.out_count).rjust(12, b"\x00")

            out_cipher = ChaCha20_Poly1305.new(key=self.outgoing_key, nonce=nonce)
            out_cipher.update(struct.pack("H", length))
            enc, tag = out_cipher.encrypt_and_digest(block)
            ciphertext = length_bytes + enc + tag
            offset += length
            self.out_count += 1
            result += ciphertext
        self.socket.sendall(result)
        return total
