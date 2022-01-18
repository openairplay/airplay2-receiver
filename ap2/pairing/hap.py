import struct
import socket
import hashlib
import threading
import os
import traceback
from os import path

import hkdf
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography import exceptions
from cryptography.hazmat.primitives import serialization
# import nacl.signing
# from nacl.utils import random
from Crypto.Cipher import ChaCha20_Poly1305  # PyCryptodome
from ..utils import get_screen_logger

from . import srp
# for JSON
import json
import base64
from enum import IntFlag

PAIRING_STORE = "./pairings/"
PAIRING_FILE = "pairings.txt"
LTSK_FILE = "ltsk.txt"
DEV_PROPS = "device_properties.txt"
ACCESSORY_SECRET = "accessory-secret"


class MFiUnhandledException(Exception):
    pass


class PairingMethod:
    PAIR_SETUP = b'\x00'
    PAIR_SETUP_AUTH = b'\x01'
    PAIR_VERIFY = b'\x02'
    ADD_PAIRING = b'\x03'
    REMOVE_PAIRING = b'\x04'
    LIST_PAIRINGS = b'\x05'


class PairingErrors:
    RESERVED = b'\x00'
    UNKNOWN = b'\x01'
    AUTHENTICATION = b'\x02'
    BACKOFF = b'\x03'
    MAXPEERS = b'\x04'
    MAXTRIES = b'\x05'
    UNAVAILABLE = b'\x06'
    BUSY = b'\x07'


class PairingFlags(IntFlag):
    TRANSIENT = 0x00000010  # 1<<4
    SPLIT = 0x01000000  # 1<<24


class PairingState:
    M1 = b'\x01'
    M2 = b'\x02'
    M3 = b'\x03'
    M4 = b'\x04'
    M5 = b'\x05'
    M6 = b'\x06'


class HomeKitPermissions:
    User = b'\x00'
    Admin = b'\x01'


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
            # print(f"dec tag={tag} length={length} value={value.hex()}")
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
            # print(f"enc tag={tag} length={length} value={value.hex()}")
            if length <= 255:
                res += bytes([tag]) + bytes([length])
                if value:
                    res += value
            else:
                for i in range(0, length // 255):
                    res += bytes([tag]) + b"\xff" + value[i * 255:(i + 1) * 255]
                left = length % 255
                res += bytes([tag]) + bytes([left]) + value[-left:]

        return res


class JSON_Store():
    # This class handles the read and write of the JSON store which holds the pairings
    @staticmethod
    def load_json(path: str):
        # should read once at start-up
        if not (os.path.exists(path)
                and os.path.getsize(path) > 0):
            return {}
        with open(path, mode="r", encoding="utf-8") as f:
            return json.load(f)

    @staticmethod
    def save_json(store, path: str):
        with open(path, mode="w", encoding="utf-8") as f:
            # logger = get_screen_logger(__name__, 'INFO')
            # logger.debug(store)
            json.dump(store, f)

    def __init__(self, path: str):
        self.path  = path
        self.store = self.load_json(self.path)

    def get_store(self):
        return self.store

    def put_store(self, data):
        self.store = data
        self.save_store()

    def save_store(self):
        self.save_json(self.store, self.path)


class CRUD_Store:
    # Logic
    def has_entry(self, _id: bytes):
        if _id.decode() in self.store:
            return True
        else:
            return False

    def create_entry(self, _id: bytes, _which: str, _val):
        if not self.has_entry(_id):
            self.store[_id.decode()] = {
                f'{_which}': _val
            }
        else:
            self.update_entry(_id, _which, _val)
        self.json_handler.put_store(self.store)

    def update_entry(self, _id: bytes, _which: str, _val):
        # Update k:v under pairing_id
        self.store[_id.decode()].update({
            f'{_which}': _val
        })
        self.json_handler.put_store(self.store)

    def read_entry(self, _id: bytes, _which: str):
        return self.store[_id.decode()][_which]

    def delete_entry(self, _id: bytes, _which=None):
        if not _which:
            _val = self.store.pop(_id.decode())
            self.json_handler.put_store(self.store)
            return _val
        else:
            ret = self.store[_id.decode()].pop(
                f'{_which}'
            )
            self.json_handler.put_store(self.store)
            return ret

    # Higher logic
    def set_bytes(self, _id: bytes, _which: str, _val: bytes):
        if _val is not None:
            self.create_entry(
                _id,
                _which,
                base64.standard_b64encode(
                    _val
                ).decode()
            )
        else:
            self.delete_entry(
                _id,
                _which,
            )

    def get_bytes(self, _id: bytes, _which: str):
        return base64.standard_b64decode(
            self.read_entry(_id, _which)
        )

    def set_string(self, _id: bytes, _which: str, _val: str):
        if _val is None or _val == '':
            self.delete_entry(
                _id,
                _which,
            )
        else:
            self.create_entry(
                _id,
                _which,
                _val
            )

    def get_string(self, _id: bytes, _which: str):
        return self.read_entry(_id, _which)

    def get_ltpk(self, _id: bytes):
        return self.get_bytes(_id, 'LTPK')

    def set_ltpk(self, _id: bytes, _value: bytes):
        self.set_bytes(_id, 'LTPK', _value)

    def get_permissions(self, _id: bytes):
        try:
            return self.get_bytes(_id, 'permissions')
        except KeyError:
            return None

    def set_permissions(self, _id: bytes, _value: bytes):
        self.set_bytes(_id, 'permissions', _value)

    def get_ltpk_and_permissions(self, _id):
        return self.get_ltpk(_id), self.get_permissions(_id)

    def set_ltpk_and_permissions(self, _id: bytes, _ltpk: bytes, _perms: bytes):
        self.set_ltpk(_id, _ltpk)
        self.set_permissions(_id, _perms)


class Pairings(CRUD_Store):
    def __init__(self, _id):
        """
        Each Pairings {ID} can contain:
        -LTPK
        -Permissions
        optionally:
        -LTSK
        """
        super(Pairings, self).__init__()
        self.json_handler = JSON_Store(PAIRING_STORE + PAIRING_FILE)
        self.store = self.json_handler.get_store()
        self._id  = _id

    def list_pairings(self):
        # skip our own ID when we list_pairings. HomeKit devices don't like it.
        # list_pairings should not be used for LTSK stuff, however.
        return [k.encode() for k in self.store.keys() if k != self._id]

    def delete_pairing(self, _id: bytes):
        return self.delete_entry(_id)


class LTSK(CRUD_Store):
    def __init__(self, _id):
        """
        Each LTSK {ID} should contain:
        -LTPK
        -LTSK
        optionally:
        -Permissions
        """
        super(LTSK, self).__init__()
        self.json_handler = JSON_Store(PAIRING_STORE + LTSK_FILE)
        self.store = self.json_handler.get_store()
        self._id  = _id

    # More customized functions - but still common to LTSK and Pairings
    def get_ltsk(self, _id: bytes):
        return self.get_bytes(_id, 'LTSK')

    def set_ltsk(self, _id: bytes, _value: bytes):
        self.set_bytes(_id, 'LTSK', _value)
        # Attempt to prevent crash when HK lists pairings, and for some reason
        # you happen to have CRUD_Store in use for both pairings and LTSK, instead
        # of the subclasses.
        self.set_permissions(_id, HomeKitPermissions.Admin)


class LTPK():
    # Long Term Public Key - get it from the hap module.
    def __init__(self, _id, isDebug=False):
        # Ensure the identifier string is binary (utf8)
        if not isinstance(_id, (bytes, bytearray)):
            _id = _id.encode('utf8')
        announce_id, self.ltpk = Hap(_id, isDebug).configure()
        self.public_int = int.from_bytes(self.ltpk, byteorder='big')
        # builds a 64 char hex string, for the 32 byte pub key
        self.public_string = str.lower("{0:0>4X}".format(self.public_int))

    def get_pub_string(self):
        return self.public_string

    def get_pub_bytes(self):
        return self.ltpk


class DeviceProperties(CRUD_Store):
    """
    This object persists ap2-receiver device properties (the mDNS property)
    as set by HomeKit
    """
    def __init__(self, _id, isDebug=False):
        self.isDebug = isDebug
        if not isinstance(_id, (bytes, bytearray)):
            _id = _id.encode('utf8')
        self._id = _id
        """
        Each DeviceProperties {ID} can contain:
        -Name
        -Password
        -ACLPermissions
        """
        super(DeviceProperties, self).__init__()
        self.json_handler = JSON_Store(PAIRING_STORE + DEV_PROPS)
        self.store = self.json_handler.get_store()
        self._id = _id

    def getDeviceName(self):
        try:
            return self.get_string(self._id, 'deviceName')
        except KeyError:
            return None

    def setDeviceName(self, _value=None):
        name = self.set_string(self._id, 'deviceName', _value)
        # return _value

    def isHKACLEnabled(self):
        try:
            return self.get_string(self._id, 'Enable_HK_Access_Control')
        except KeyError:
            return None

    def setHKACL(self, _value=None):
        hkacl = self.set_string(self._id, 'Enable_HK_Access_Control', _value)

    def getDevicePassword(self):
        try:
            return self.get_string(self._id, 'devicePassword')
        except KeyError:
            return None

    def setDevicePassword(self, _value=None):
        try:
            pw = self.set_string(self._id, 'devicePassword', _value)
        except KeyError:
            pass

    def getDeviceACL(self):
        try:
            return self.get_permissions(self._id).decode()
        except KeyError:
            return None

    def setDeviceACL(self, _value=None):
        if isinstance(_value, (int)):
            _value = int.to_bytes(_value, 1, 'big')
        acl = self.set_permissions(self._id, _value)
        # return _value


# noinspection PyMethodMayBeStatic
class Hap:
    def __init__(self, identifier, isDebug=False):
        self.isDebug = isDebug
        self.transient = False
        self.encrypted = False
        self.mfi_setup = False
        self.pair_setup_steps_n = 5
        if self.isDebug:
            self.logger = get_screen_logger('HAP', level='DEBUG')
        else:
            self.logger = get_screen_logger('HAP', level='INFO')
        # Ensure the identifier string is binary (utf8)
        if not isinstance(identifier, (bytes, bytearray)):
            identifier = identifier.encode('utf8')

        """
        TODO: controller_id is (meant to be) evident from the HAP connection,
        but ap2-receiver handles only 1 simultaneous connection, whereas the
        HAP spec mandates eight (8).
        """
        self.controller_id = None

        # self.device_ltpk = None  # Device is e.g. the iPhone.
        self.accessory_pairing_id = identifier  # accessory is the AP2-receiver.

        self.pairings = Pairings(self.accessory_pairing_id)
        self.ltsk = LTSK(self.accessory_pairing_id)

        if self.ltsk.has_entry(self.accessory_pairing_id):
            self.logger.debug(f'Loading ed25519 keypair for own ID: {self.accessory_pairing_id.decode("utf-8")}')
            self.accessory_ltsk = ed25519.Ed25519PrivateKey.from_private_bytes(
                self.ltsk.get_ltsk(self.accessory_pairing_id)
            )
            self.accessory_ltpk = self.ltsk.get_ltpk(self.accessory_pairing_id)

            # NaCl way of doing it:
            # accessory_secret = random(nacl.bindings.crypto_sign_SEEDBYTES)
            # self.accessory_ltsk = nacl.signing.SigningKey(accessory_secret)

            # self.accessory_ltsk = nacl.signing.SigningKey(self.ltsk.get_ltsk(self.accessory_pairing_id), encoder=nacl.encoding.RawEncoder)
            # self.accessory_ltpk = bytes(self.accessory_ltsk.verify_key)

        else:
            # Generate new private+public key pair
            self.logger.debug(f'Generating new ed25519 keypair for own ID: {self.accessory_pairing_id}')

            # NaCl way of doing it:
            # accessory_secret = random(nacl.bindings.crypto_sign_SEEDBYTES)
            # self.accessory_ltsk = nacl.signing.SigningKey(accessory_secret)

            self.accessory_ltsk = ed25519.Ed25519PrivateKey.generate()
            self.accessory_ltpk = self.accessory_ltsk.public_key(
            ).public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            # Add the keypair to our handy ltsk store
            self.ltsk.set_ltsk(
                self.accessory_pairing_id,
                # self.accessory_ltsk
                self.accessory_ltsk.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
            self.ltsk.set_ltpk(
                self.accessory_pairing_id,
                self.accessory_ltpk
            )

    def request(self, req):
        req = Tlv8.decode(req)

        if req[Tlv8.Tag.METHOD] == PairingMethod.PAIR_SETUP_AUTH:
            res = self.pair_setup(req)
        return Tlv8.encode(res)

    def pair_setup(self, req):
        req = Tlv8.decode(req)
        """
        2.2.1.1 Pair Setup: Pair Setup is a one-time operation that creates a
        valid pairing between an iOS device and an accessory by securely
        exchanging public keys with an iOS device and an accessory. Pair Setup
        requires the customer to enter an eight-digit setup code on their iOS
        device. The setup code is provided by the accessory via a label or
        display.
        """

        """ 5.6.1 M1: iOS Device -> Accessory – ‘SRP Start Requestʼ

        When the iOS device performs authentication as part of the Pair Setup
        procedure, it sends a request to the accessory with the following TLV
        items:

        kTLVType_State <M1>
        kTLVType_Method <Pair Setup with Authentication>

        When the iOS device performs Pair Setup with a separate optional
        authentication procedure, it sends a request to the accessory with the
        following TLV items:

        kTLVType_State <M1>
        kTLVType_Method <Pair Setup>
        kTLVType_Flags <Pairing Type Flags>

        Mask | Bit | Description

        0x00000010 | 4 | BitMask (1 « 4) Transient Pair-Setup
        (kPairingFlag_Transient) Pair Setup M1 - M4 without exchanging public keys

        0x01000000 | 24| BitMask (1 « 24) Split-Pair Setup (kPairingFlag_Split)

        When set with kPairingFlag_Transient save the SRP Verifier used in this
        session. And, when only kPairingFlag_Split is set, use the saved SRP
        verifier from previous session.
        """
        if Tlv8.Tag.FLAGS in req:
            flags = int.from_bytes(req[Tlv8.Tag.FLAGS], byteorder='big')
        if req[Tlv8.Tag.STATE] == PairingState.M1 and \
                req[Tlv8.Tag.METHOD] == PairingMethod.PAIR_SETUP and \
                Tlv8.Tag.FLAGS in req and \
                PairingFlags(flags) == PairingFlags.TRANSIENT:
            self.transient = True
            self.pair_setup_steps_n = 2
        elif req[Tlv8.Tag.STATE] == PairingState.M1 and \
                req[Tlv8.Tag.METHOD] == PairingMethod.PAIR_SETUP_AUTH and \
                Tlv8.Tag.FLAGS in req and \
                PairingFlags(flags) == PairingFlags.TRANSIENT:
            """MFi setup - bitflag 51 was enabled
            result will be wrong, but we can safely set these params.
            """
            self.pair_setup_steps_n = 2
            self.transient = True
            self.mfi_setup = True

        if req[Tlv8.Tag.STATE] == PairingState.M1:
            self.logger.debug(f"-----\tPair-Setup [1/{self.pair_setup_steps_n}]")
            res = self.pair_setup_m1_m2()
        elif req[Tlv8.Tag.STATE] == PairingState.M3:
            self.logger.debug(f"-----\tPair-Setup [2/{self.pair_setup_steps_n}]")
            res = self.pair_setup_m3_m4(req[Tlv8.Tag.PUBLICKEY], req[Tlv8.Tag.PROOF])
            if self.transient:
                self.encrypted = True
            if self.mfi_setup:
                try:
                    raise MFiUnhandledException()
                except MFiUnhandledException:
                    self.logger.error("MFi setup is not yet possible.")
        elif req[Tlv8.Tag.STATE] == PairingState.M5:
            res = self.pair_setup_m5_m6(req[Tlv8.Tag.ENCRYPTEDDATA])
        return Tlv8.encode(res)

    def pair_verify(self, req):
        req = Tlv8.decode(req)
        """
        2.2.1.2 Pair Verify: Pair Verify is performed for every HomeKit
        Accessory Protocol session. Pair Verify verifies the pairing between an
        iOS device and an accessory and establishes an ephemeral shared secret
        used to secure the HomeKit Accessory Protocol session.
        """

        """
        The iOS device generates a new, random Curve25519 key pair and sends a
        request to the accessory with the following TLV items:

        kTLVType_State <M1>
        kTLVType_PublicKey <iOS device’s Curve25519 public key>
        """

        if req[Tlv8.Tag.STATE] == PairingState.M1:
            self.logger.debug("-----\tPair-Verify [1/2]")
            res = self.pair_verify_m1_m2(req[Tlv8.Tag.PUBLICKEY])
        elif req[Tlv8.Tag.STATE] == PairingState.M3:
            self.logger.debug("-----\tPair-Verify [2/2]")
            status, res = self.pair_verify_m3_m4(req[Tlv8.Tag.ENCRYPTEDDATA])
            if status:
                self.encrypted = True
        return Tlv8.encode(res)

    def pair_add(self, req):
        req = Tlv8.decode(req)
        res = []

        if(req[Tlv8.Tag.STATE] == PairingState.M1
           and req[Tlv8.Tag.METHOD] == PairingMethod.ADD_PAIRING
           and req[Tlv8.Tag.IDENTIFIER]
           and req[Tlv8.Tag.PUBLICKEY]
           and req[Tlv8.Tag.PERMISSIONS]):
            self.logger.debug("-----\tPair-Add [1/1]")
            res = self.pair_add_m1_m2(req)
            self.encrypted = True
            self.controller_id = req[Tlv8.Tag.IDENTIFIER]
        else:
            self.logger.debug("-----\tPair-Add")
            self.logger.debug(f"Unexpected data received: {req}")
        return Tlv8.encode(res)

    def pair_add_m1_m2(self, req):
        _id = req[Tlv8.Tag.IDENTIFIER]
        device_ltpk = req[Tlv8.Tag.PUBLICKEY]
        permissions = req[Tlv8.Tag.PERMISSIONS]

        if permissions != HomeKitPermissions.Admin:
            """
            2. Verify that the controller sending the request has the admin bit
            set in the local pairings list. If not, accessory must abort and
            respond with the following TLV items:
            kTLVType_State <M2>
            kTLVType_Error kTLVError_Authentication
            """
            self.logger.debug('Controller does not have admin bit set in local pairings list')
            return [
                Tlv8.Tag.STATE, PairingState.M2,
                Tlv8.Tag.ERROR, PairingErrors.AUTHENTICATION
            ]

        if self.pairings.has_entry(_id):
            ltpk = self.pairings.get_ltpk(_id)
            """
            3. If a pairing for AdditionalControllerPairingIdentifier exists, it
             must perform the following steps:
            (a) If the AdditionalControllerLTPK does not match the stored
             long-term public key for AdditionalControllerPairingIdentifier, respond
             with the following TLV items:
                kTLVType_State <M2>
                kTLVType_Error kTLVError_Unknown
            (b) Update the permissions of the controller to match
             AdditionalControllerPermissions.
            """
            if device_ltpk != ltpk:
                self.logger.debug('Device LTPK does not match stored LTPK')
                return [
                    Tlv8.Tag.STATE, PairingState.M2,
                    Tlv8.Tag.ERROR, PairingErrors.UNKNOWN
                ]
            else:
                # Update the permissions of the controller to match AdditionalControllerPermissions
                self.pairings.set_permissions(_id, permissions)
        else:
            """
            4. Otherwise, if a pairing for AdditionalControllerPairingIdentifier
             does not exist, it must perform the following steps:
            (a) Check if the accessory has space to support an additional pairing;
             the minimum number of supported pairings is 16 pairings. If not,
              accessory must abort and respond with the following TLV items:
                kTLVType_State <M2>
                kTLVType_Error kTLVError_MaxPeers
            (b) Save the additional controllerʼs
             AdditionalControllerPairingIdentifier,
             AdditionalControllerLTPK and
             AdditionalControllerPermissions
             to a persistent store. If an error
             occurs while saving, accessory must abort and respond with the following TLV items:
                kTLVType_State <M2>
                kTLVType_Error kTLVError_Unknown
            """
            # TODO: 4a. Check for free space :)

            # No pairing exists, write new pairing
            try:
                self.pairings.set_ltpk_and_permissions(_id, device_ltpk, permissions)
            except (PermissionError, ValueError) as e:
                # If an error occurs while saving, accessory must abort and respond with:
                self.logger.debug('pair-add was unable to save pairing data to persistent store:')
                traceback.print_exception(type(e), e, e.__traceback__)
                return [
                    Tlv8.Tag.STATE, PairingState.M2,
                    Tlv8.Tag.ERROR, PairingErrors.UNKNOWN
                ]

        self.controller_id = _id
        """
        5. Construct a response with the following TLV items:
            kTLVType_State <M2>

        6. Send the response over the HAP session established via ”5.7 Pair Verify” (page 39),
         which provides bidirectional, authenticated encryption.
        """
        return [
            Tlv8.Tag.STATE, PairingState.M2
        ]

    def pair_remove(self, req):
        req = Tlv8.decode(req)
        res = []
        teardown = False

        if(req[Tlv8.Tag.STATE] == PairingState.M1
           and req[Tlv8.Tag.METHOD] == PairingMethod.REMOVE_PAIRING
           and req[Tlv8.Tag.IDENTIFIER]):
            self.logger.debug("-----\tPair-Remove [1/1]")
            res = self.pair_remove_m1_m2(req)
            self.encrypted = True
        else:
            self.logger.debug("-----\tPair-Remove")
            self.logger.debug(f"Unexpected data received: {req}")
        return Tlv8.encode(res)

    def pair_remove_m1_m2(self, req):
        _id = req[Tlv8.Tag.IDENTIFIER]
        """
        2. Verify that the controller sending the request has the admin bit set
         in the local pairings list. If not, accessory must abort and respond
          with the following TLV items:
            kTLVType_State <M2>
            kTLVType_Error kTLVError_Authentication
        """
        # Note: this may not be the ID of the "controller sending the request".
        # It's a controller sending a request for a specific ID.
        if self.pairings.get_permissions(_id) != HomeKitPermissions.Admin:
            return [
                Tlv8.Tag.STATE, PairingState.M2,
                Tlv8.Tag.ERROR, PairingErrors.AUTHENTICATION
            ]
        """
        3. If the pairing exists, remove
         RemovedControllerPairingIdentifier and its corresponding long-term
         public key from persistent storage. If a pairing for
         RemovedControllerPairingIdentifier does not exist, the accessory must
         return success. Otherwise, if an error occurs during removal, accessory
         must abort and respond with the following TLV items:
            kTLVType_State <M2>
            kTLVType_Error kTLVError_Unknown
        """

        if self.pairings.has_entry(_id):
            try:
                self.pairings.delete_pairing(_id)
            except PermissionError as e:
                # If an error occurs while removing, accessory must abort and respond with:
                self.logger.error('pair-remove was unable to delete pairing data:')
                traceback.print_exception(type(e), e, e.__traceback__)
                return [
                    Tlv8.Tag.STATE, PairingState.M2,
                    Tlv8.Tag.ERROR, PairingErrors.UNKNOWN
                ]
        """
        4. Construct a response with the following TLV items:
         kTLVType_State <M2>

        5. Send the response over the HAP session established via ”5.7 Pair
        Verify”, which provides bidirectional, authenticated encryption.

        6. If the controller requested the accessory to remove its own pairing
        the accessory must invalidate the HAP session immediately after the
        response is sent.

        7. If there are any established HAP sessions with the controller that
        was removed, then these connections must be immediately torn down and
        any associated data stream (e.g. RTP, HDS) must be stopped and
        removed.
        """
        return [
            Tlv8.Tag.STATE, PairingState.M2
        ]

    def pair_list(self, req):
        req = Tlv8.decode(req)
        res = []

        if(req[Tlv8.Tag.STATE] == PairingState.M1
           and req[Tlv8.Tag.METHOD] == PairingMethod.LIST_PAIRINGS):
            self.logger.debug("-----\tPair-List [1/1]")
            res = self.pair_list_m1_m2(req)
            self.encrypted = True
        else:
            self.logger.debug("-----\tPair-List")
            self.logger.debug(f"Unexpected data received: {req}")
        return Tlv8.encode(res)

    def pair_list_m1_m2(self, req):
        """ 5.12.2 M2: Accessory -> iOS Device – ‘List Pairings Responseʼ
        When the accessory receives the request, it must perform the following steps:

        1. Validate the received data against the established HAP session as
        described in the transport-specific chapters.

        2. Verify that the controller sending the request has the admin bit set
        in the local pairings list. If not, abort and respond with the
        following TLV items:

        kTLVType_State <M2>
        kTLVType_Error kTLVError_Authentication
        """
        # cont_perm = self.pairings.get_permissions(self.controller_id)
        # if cont_perm != HomeKitPermissions.Admin:
        #     return [
        #         Tlv8.Tag.STATE, PairingState.M2,
        #         Tlv8.Tag.ERROR, PairingErrors.AUTHENTICATION
        #     ]
        """
        3. Construct a response with the following TLV items:

        kTLVType_State <M2>
        kTLVType_Identifier <Pairing Identifier of Controller 1>
        kTLVType_PublicKey <Ed25519 long-term public key of Controller 1>
        kTLVType_Permissions <Bit value describing permissions of Controller 1>

        If another pairing follows a pairing, it must be separated using a
        separator item:

        kTLVType_Separator <No value>

        Additional pairings must contain the following TLV items:

        kTLVType_Identifier <Pairing Identifier of Controller N>
        kTLVType_PublicKey <Ed25519 long-term public key of Controller N>
        kTLVType_Permissions <Bit value describing permissions of Controller N>

        4. Send the response over the HAP session established via ”5.7 Pair
        Verify”, which provides bidirectional, authenticated
        encryption.
        """

        res = [
            Tlv8.Tag.STATE, PairingState.M2
        ]

        for x in self.pairings.list_pairings():
            """ <...>
            Each pairing entry must be comprised of the following TLV items:
            kTLVType_Identifier <Pairing Identifier of Controller 1>
            kTLVType_PublicKey <Ed25519 long-term public key of Controller 1>
            kTLVType_Permissions <Bit value describing permissions of Controller 1>
            """
            _p = self.pairings.get_permissions(x)
            if not _p:
                continue
            res.extend([Tlv8.Tag.SEPARATOR, b''])
            res.extend([Tlv8.Tag.IDENTIFIER, x,
                        Tlv8.Tag.PUBLICKEY, self.pairings.get_ltpk(x),
                        Tlv8.Tag.PERMISSIONS, _p])
        return res

    def configure(self):
        return self.accessory_pairing_id, self.accessory_ltpk

    def pair_setup_m1_m2(self):
        """ 5.6.2 M2: Accessory -> iOS Device – ‘SRP Start Responseʼ
        When the accessory receives <M1>, it must perform the following steps:

        1. If the accessory is already paired, it must respond with the
        following TLV items:

        kTLVType_State <M2>
        kTLVType_Error <kTLVError_Unavailable>

        2. If the accessory has received more than 100 unsuccessful
        authentication attempts, it must respond with the following TLV items:

        kTLVType_State <M2>
        kTLVType_Error <kTLVError_MaxTries>

        3. If the accessory is currently performing a Pair Setup procedure with
        a different controller, it must respond with the following TLV items:

        kTLVType_State <M2>
        kTLVType_Error <kTLVError_Busy>

        4. Create new SRP session with SRP_new (SRP6a_server_method()).

        5. Set SRP username to Pair-Setup with SRP_set_username().

        6. Generate 16 bytes of random salt and set it with SRP_set_params().

        7. If the accessory received the M1 (SRP StartRequest) without
        kTLVType_Flags or if the kTLVType_Flags were set as
        kPairingFlag_Transient and kPairingFlag_Split then:

        • If the accessory can display a random setup code, it must generate a
          random setup code, save the SRP verifier for that setup code, use
          that setup code for the next Pair Setup procedure with
          kPairingFlag_Split, and set it with SRP_set_auth_password().
        • If the accessory cannot display a random setup code, it must retrieve
          the SRP verifier for the setup code, e.g. from an EEPROM, and set the
          verifier with SRP_set_authenticator().
        • The accessory must include the received kTLVType_Flags in its M2
          response.

        If the accessory received the M1 (SRP Start Request) with the
        kTLVType_Flags set as kPairingFlag_Split then:

        • If the accessory has saved SRP verifier it must retrieve the saved SRP
          verifier for the setup code, e.g. from an EEPROM, and set the
          verifier with SRP_set_authenticator(). The accessory must also
          include the received kTLVType_Flags in its M2 response.
        • If the accessory does not have a saved SRP verifier, it must respond
          with the following TLV items:

        kTLVType_State <M2>
        kTLVType_Error <kTLVError_Authentication>

        The setup code must conform to the format XXX-XX-XXX where each X is a
        0-9 digit and dashes are required. To learn more, see ”4.2.1 Setup
        Code” (page 29).

        8. If the accessory has generated a setup code, it must present the
        setup code to the user, e.g. display it on the accessoryʼs screen. If
        the accessory doesnʼt have a screen then the setup code may be on a
        printed label.

        9. Generate an SRP publickey with SRP_gen_pub().

        10. Respond to the iOS deviceʼs request with the following TLV items:

        kTLVType_State <M2>
        kTLVType_PublicKey <Accessory’s SRP public key>
        kTLVType_Salt <16 byte salt generated in Step 6>
        kTLVType_Flags <Pairing Type Flags> (Optional as per Step 7)
        """
        self.ctx = srp.SRPServer(b"Pair-Setup", b"3939")
        server_public = self.ctx.public_key
        salt = self.ctx.salt

        return [
            Tlv8.Tag.STATE, PairingState.M2,
            Tlv8.Tag.SALT, salt,
            Tlv8.Tag.PUBLICKEY, server_public
        ]
        """ 5.6.3 M3: iOS Device -> Accessory – ‘SRP Verify Requestʼ

        When the iOS device receives <M2>, it will check for kTLVType_Error. If
        present, the iOS device will abort the setup process and report the
        error to the user.

        If kTLVType_Error is not present and the controller is performing only a
        split pair setup (that is, kPairingFlag_Split was set and
        kPairingFlag_Transient was not set in M2), the controller will reuse
        the setup code from the previous Transient + Split Setup session.
        Otherwise, the user is prompted to enter the setup code provided by the
        accessory.
        """

    def pair_setup_m3_m4(self, client_public, client_proof):
        """ 5.6.4 M4: Accessory -> iOS Device – ‘SRP Verify Responseʼ

        When the accessory receives <M3>, it must perform the following steps:

        1. Use the iOS deviceʼs SRP public key to compute the SRP shared secret
        key with SRP_compute_key().

        2. Verify the iOS deviceʼs SRP proof with SRP_verify(). If verification
        fails, the accessory must respond with the following TLV items:

        kTLVType_State <M4>
        kTLVType_Error kTLVError_Authentication

        3. Generate the accessory-side SRP proof with SRP_respond().

        4. Construct the response with the following TLV items:

        kTLVType_State <M4>
        kTLVType_Proof <Accessory’s SRP proof>

        5. Send the response to the iOS device.

        6. If the accessory is performing a transient pair setup
        (i.e. kTLVType_Method is <Pair Setup> and the kPairingFlag_Transient is
        set in kTLVType_Flags), then Pair Setup is complete for the accessory
        and the accessory must enable session security with the Pair-Setup
        session keys generated in Step 4.
        """
        self.ctx.set_client_public(client_public)
        assert self.ctx.verify(client_proof)

        self.accessory_shared_key = self.ctx.session_key
        server_proof = self.ctx.proof

        return [
            Tlv8.Tag.STATE, PairingState.M4,
            Tlv8.Tag.PROOF, server_proof
        ]
        """ 5.6.5 M5: iOS Device -> Accessory – ‘Exchange Requestʼ
        5.6.5.1 <M4> Verification

        When the iOS device receives <M4>, it performs the following steps: ...

        5.6.5.2 <M5> Request Generation ...

        Once <M4> Verification is complete, and the controller is performing a
        non-transient pair-setup the iOS device performs the following steps to
        generate the <M5> request: ...
        """

    def pair_setup_m5_m6(self, encrypted):
        """ 5.6.6 M6: Accessory -> iOS Device – ‘Exchange Responseʼ

        5.6.6.1 <M5> Verification
        """

        self.logger.debug("-----\tPair-Setup [3/5]")
        dec_tlv, session_key = self.pair_setup_m5_m6_1(encrypted)
        self.logger.debug("-----\tPair-Setup [4/5]")
        self.pair_setup_m5_m6_2(dec_tlv)
        self.logger.debug("-----\tPair-Setup [5/5]")
        enc_tlv, tag = self.pair_setup_m5_m6_3(session_key)
        """
        7. Send the response to the iOS device with the following TLV items:

        kTLVType_State <M6>
        kTLVType_EncryptedData <encryptedData with authTag appended>
        """
        return [
            Tlv8.Tag.STATE, PairingState.M6,
            Tlv8.Tag.ENCRYPTEDDATA, enc_tlv + tag
        ]

        """ 5.6.6.3 <M6> Verification by iOS Device
        When the iOS device receives <M6>, it performs the following steps:

        1. Verifies authTag, which is appended to the encryptedData and
        contained within the kTLVType_EncryptedData TLV item, from
        encryptedData. If this fails, the setup process will be aborted and an
        error will be reported to the user.

        2. Decrypts the sub-TLV in encryptedData. If this fails, the setup
        process will be aborted and an error will be reported to the user.

        3. Uses Ed25519 to verify the signature of AccessoryInfo using
        AccessoryLTPK. If this fails, the setup process will be aborted and an
        error will be reported to the user.

        4. Persistently saves AccessoryPairingID and AccessoryLTPK as a pairing.

        The Pair Setup procedure is now complete.
        """

    def pair_setup_m5_m6_1(self, encrypted):
        """
        When the accessory receives <M5>, it must perform the following steps:

        1. Verify the iOS deviceʼs authTag, which is appended to the
        encryptedData and contained within the kTLVType_EncryptedData TLV item,
        from encryptedData. If verification fails, the accessory must respond
        with the following TLV items:

        kTLVType_State <M6>
        kTLVType_Error kTLVError_Authentication

        2. Decrypt the sub-TLV in encryptedData. If decryption fails, the
        accessory must respond with the following TLV items:

        kTLVType_State <M6>
        kTLVType_Error kTLVError_Authentication
        """
        prk = hkdf.hkdf_extract(b"Pair-Setup-Encrypt-Salt", self.ctx.session_key)
        session_key = hkdf.hkdf_expand(prk, b"Pair-Setup-Encrypt-Info", 32)
        c = ChaCha20_Poly1305.new(key=session_key, nonce=b"PS-Msg05")
        enc_tlv = encrypted[:-16]
        tag = encrypted[-16:]
        try:
            dec_tlv = c.decrypt_and_verify(enc_tlv, tag)
        except ValueError:
            return [
                Tlv8.Tag.STATE, PairingState.M6,
                Tlv8.Tag.ERROR, PairingErrors.AUTHENTICATION
            ]

        return Tlv8.decode(dec_tlv), session_key

    def pair_setup_m5_m6_2(self, dec_tlv):
        """
        3. Derive iOSDeviceX from the SRP shared secret by using HKDF-SHA-512
        with the following parameters:

        InputKey = <SRP shared secret>
        Salt = ”Pair-Setup-Controller-Sign-Salt”
        Info = ”Pair-Setup-Controller-Sign-Info”
        OutputSize = 32 bytes

        4. Construct iOSDeviceInfo by concatenating iOSDeviceX with the
        iOSdeviceʼs PairingIdentifier, iOSDevicePairingID, from the decrypted
        sub-TLV and the iOS deviceʼs long-term public key, iOSDeviceLTPK from
        the decrypted sub-TLV. The data must be concatenated in order such that
        the final data is iOSDeviceX, iOSDevicePairingID, iOSDeviceLTPK.
        """
        device_id = dec_tlv[Tlv8.Tag.IDENTIFIER]
        device_ltpk = dec_tlv[Tlv8.Tag.PUBLICKEY]
        device_sig = dec_tlv[Tlv8.Tag.SIGNATURE]

        self.controller_id = device_id

        prk = hkdf.hkdf_extract(b"Pair-Setup-Controller-Sign-Salt", self.ctx.session_key)
        device_x = hkdf.hkdf_expand(prk, b"Pair-Setup-Controller-Sign-Info", 32)
        device_info = device_x + device_id + device_ltpk

        # NaCl way of doing things:
        # verify_key = nacl.signing.VerifyKey(device_ltpk)
        # verify_key.verify(device_info, device_sig)
        verify_key = ed25519.Ed25519PublicKey.from_public_bytes(device_ltpk)
        """
        5. Use Ed25519 to verify the signature of the constructed iOSDeviceInfo
        with the iOSDeviceLTPK from the decrypted sub-TLV. If signature
        verification fails, the accessory must respond with the following TLV
        items:

        kTLVType_State <M6>
        kTLVType_Error kTLVError_Authentication
        """
        try:
            verify_key.verify(signature=device_sig, data=device_info)
        except exceptions.InvalidSignature:
            self.logger.debug('Invalid Signature')
            return [
                Tlv8.Tag.STATE, PairingState.M6,
                Tlv8.Tag.ERROR, PairingErrors.AUTHENTICATION
            ]

        """
        6. Persistently save the iOSDevicePairingID and iOSDeviceLTPK as a
        pairing. If the accessory cannot accept any additional pairings, it
        must respond with the following TLV items:

        kTLVType_State <M6>
        kTLVType_Error kTLVError_MaxPeers
        """
        self.pairings.set_ltpk(device_id, device_ltpk)

    def pair_setup_m5_m6_3(self, session_key):
        """ 5.6.6.2 <M6> Response Generation

        Once <M5> Verification is complete, the accessory must perform the
        following steps to generate the <M6> response:

        1. Generate its Ed25519 long-term public key, AccessoryLTPK, and
        long-term secret key, AccessoryLTSK, if they donʼt exist.

        2. Derive AccessoryX from the SRP shared secret by using HKDF-SHA-512
        with the following parameters:

        InputKey = <SRP shared secret>
        Salt = ”Pair-Setup-Accessory-Sign-Salt”
        Info = ”Pair-Setup-Accessory-Sign-Info”
        OutputSize = 32 bytes
        """
        prk = hkdf.hkdf_extract(b"Pair-Setup-Accessory-Sign-Salt", self.ctx.session_key)
        accessory_x = hkdf.hkdf_expand(prk, b"Pair-Setup-Accessory-Sign-Info", 32)

        """
        3. Concatenate AccessoryX with the accessoryʼs Pairing Identifier,
        AccessoryPairingID, and its long-term public key, AccessoryLTPK. The
        data must be concatenated in order such that the final data is
        AccessoryX, AccessoryPairingID, AccessoryLTPK. The concatenated value
        will be referred to as AccessoryInfo.

        4. Use Ed25519 to generate AccessorySignature by signing AccessoryInfo
        with its long-term secret key, AccessoryLTSK.
        """
        accessory_info = accessory_x + self.accessory_pairing_id + self.accessory_ltpk
        accessory_sig = self.accessory_ltsk.sign(accessory_info)
        """
        5. Construct the sub-TLV with the following TLV items:

        kTLVType_Identifier <AccessoryPairingID>
        kTLVType_PublicKey <AccessoryLTPK>
        kTLVType_Signature <AccessorySignature>
        """
        dec_tlv = Tlv8.encode([
            Tlv8.Tag.IDENTIFIER, self.accessory_pairing_id,
            Tlv8.Tag.PUBLICKEY, self.accessory_ltpk,
            Tlv8.Tag.SIGNATURE, accessory_sig
        ])
        """
        6. Encrypt the sub-TLV, encryptedData, and generate the 16 byte authtag,
        authTag. This uses the ChaCha20-Poly1305 AEAD algorithm with the
        following parameters:

        encryptedData, authTag = ChaCha20-Poly1305 (SessionKey, Nonce=”PS-Msg06”,
        AAD=<none>, Msg=<Sub-TLV>)
        """
        c = ChaCha20_Poly1305.new(key=session_key, nonce=b"PS-Msg06")
        enc_tlv, tag = c.encrypt_and_digest(dec_tlv)

        return enc_tlv, tag

    def pair_verify_m1_m2(self, client_public):
        self.client_curve_public = client_public
        """ 5.7.2 M2: Accessory -> iOS Device – ‘Verify Start Responseʼ
        When the accessory receives <M1>, it must perform the following steps:

        1. Generate new, random Curve25519 keypair.

        2. Generate the shared secret, SharedSecret, from its Curve25519 secret
        key and the iOS deviceʼs Curve25519 public key.

        3. Construct AccessoryInfo by concatenating the following items in order:
        (a) Accessoryʼs Curve25519 publickey.
        (b) Accessoryʼs Pairing Identifier, AccessoryPairingID.
        (c) iOSdeviceʼs Curve25519 public key from the received <M1> TLV.

        4. Use Ed25519 to generate AccessorySignature by signing AccessoryInfo
        with its long-term secret key, AccessoryLTSK.

        5. Construct a sub-TLV with the following items:

        kTLVType_Identifier <AccessoryPairingID>
        kTLVType_Signature <AccessorySignature>

        6. Derive the symmetric session encryption key, SessionKey, from the
        Curve25519 shared secret by using HKDF-SHA-512 with the following
        parameters:

        InputKey = <Curve25519 shared secret>
        Salt = ”Pair-Verify-Encrypt-Salt”
        Info = ”Pair-Verify-Encrypt-Info”
        OutputSize = 32 bytes

        7. Encrypt the sub-TLV, encryptedData, and generate the 16-byte authtag,
        authTag. This uses the ChaCha20-Poly1305 AEAD algorithm with the
        following parameters:

        encryptedData, authTag = ChaCha20-Poly1305(SessionKey, Nonce=”PV-Msg02”,
        AAD=<none>, Msg=<Sub-TLV>)

        8. Construct the response with the following TLV items:

        kTLVType_State <M2>
        kTLVType_PublicKey <Accessory’s Curve25519 public key>
        kTLVType_EncryptedData <encryptedData with authTag appended>

        9. Send the response to the iOS device.
        """

        self.accessory_random = x25519.X25519PrivateKey.generate()
        self.accessory_random_public = self.accessory_random.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        self.accessory_shared_key = self.accessory_random.exchange(x25519.X25519PublicKey.from_public_bytes(client_public))

        accessory_info = self.accessory_random_public + self.accessory_pairing_id + client_public
        accessory_sig = self.accessory_ltsk.sign(accessory_info)

        sub_tlv = Tlv8.encode([
            Tlv8.Tag.IDENTIFIER, self.accessory_pairing_id,
            Tlv8.Tag.SIGNATURE, accessory_sig
        ])

        prk = hkdf.hkdf_extract(b"Pair-Verify-Encrypt-Salt", self.accessory_shared_key)
        session_key = hkdf.hkdf_expand(prk, b"Pair-Verify-Encrypt-Info", 32)

        c = ChaCha20_Poly1305.new(key=session_key, nonce=b"PV-Msg02")
        enc_tlv, tag = c.encrypt_and_digest(sub_tlv)

        return [
            Tlv8.Tag.STATE, PairingState.M2,
            Tlv8.Tag.PUBLICKEY, self.accessory_random_public,
            Tlv8.Tag.ENCRYPTEDDATA, enc_tlv + tag
        ]

    def pair_verify_m3_m4(self, encrypted):
        prk = hkdf.hkdf_extract(b"Pair-Verify-Encrypt-Salt", self.accessory_shared_key)
        session_key = hkdf.hkdf_expand(prk, b"Pair-Verify-Encrypt-Info", 32)

        """ 5.7.4 M4: Accessory -> iOS Device – ‘Verify Finish Responseʼ

        When the accessory receives <M3>, it must perform the following steps:

        1. Verify the iOS deviceʼs authTag, which is appended to the
        encryptedData and contained within the kTLVType_EncryptedData TLV item,
        against encryptedData. If verification fails, the accessory must
        respond with the following TLV items:

        kTLVType_State <M4>
        kTLVType_Error kTLVError_Authentication

        2. Decrypt the sub-TLV in encryptedData. If decryption fails, the
        accessory must respond with the following TLV items:

        kTLVType_State <M4>
        kTLVType_Error kTLVError_Authentication

        3. Use the iOS deviceʼs Pairing Identifier, iOSDevicePairingID, to look
        up the iOS deviceʼs long-term public key, iOSDeviceLTPK, in its list of
        paired controllers. If not found, the accessory must respond with the
        following TLV items:

        kTLVType_State <M4>
        kTLVType_Error kTLVError_Authentication

        4. Use Ed25519 to verify iOSDeviceSignature using iOSDeviceLTPK against
        iOSDeviceInfo contained in the decrypted sub-TLV. If decryption fails,
        the accessory must respond with the following TLV items:

        kTLVType_State <M4>
        kTLVType_Error kTLVError_Authentication

        5. Send the response to the iOS device with the following TLV items:

        kTLVType_State <M4>

        When the iOS device receives <M4>, the Pair Verify procedure is
        complete. If a subsequent Pair Verify request from another controller
        occurs in the middle of a Pair Verify transaction the accessory must
        honor both Pair Verify requests and maintain separate secure sessions
        for each controller. If a subsequent Pair Verify request from the same
        controller occurs in the middle of the Pair Verify procedure then the
        accessory must immediately tear down the existing session with the
        controller and must accept the newest request.
        """

        c = ChaCha20_Poly1305.new(key=session_key, nonce=b"PV-Msg03")
        enc_tlv = encrypted[:-16]
        tag = encrypted[-16:]
        try:
            dec_tlv = c.decrypt_and_verify(enc_tlv, tag)
        except ValueError:
            return False, [
                Tlv8.Tag.STATE, PairingState.M4,
                Tlv8.Tag.ERROR, PairingErrors.AUTHENTICATION
            ]

        sub_tlv = Tlv8.decode(dec_tlv)
        device_id = sub_tlv[Tlv8.Tag.IDENTIFIER]
        device_sig = sub_tlv[Tlv8.Tag.SIGNATURE]

        self.controller_id = device_id

        device_info = self.client_curve_public + device_id + self.accessory_random_public

        if self.pairings.has_entry(device_id):
            device_ltpk = self.pairings.get_ltpk(device_id)

            # NaCl way of doing things:
            # verify_key = nacl.signing.VerifyKey(device_ltpk)
            # Ed25519 way:
            verify_key = ed25519.Ed25519PublicKey.from_public_bytes(device_ltpk)
            try:
                verify_key.verify(signature=device_sig, data=device_info)
            except exceptions.InvalidSignature:
                self.logger.debug('Invalid Signature')
                return False, [
                    Tlv8.Tag.STATE, PairingState.M4,
                    Tlv8.Tag.ERROR, PairingErrors.AUTHENTICATION
                ]
            return True, [
                Tlv8.Tag.STATE, PairingState.M4
            ]
        else:
            return False, [
                Tlv8.Tag.STATE, PairingState.M4,
                Tlv8.Tag.ERROR, PairingErrors.AUTHENTICATION
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
        self.logger = get_screen_logger(__name__, level='INFO')

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

                try:
                    block_length_bytes = self.socket.recv(self.LENGTH_LENGTH)
                    if not block_length_bytes:
                        return result
                    assert len(block_length_bytes) == self.LENGTH_LENGTH
                except (ConnectionResetError, UnboundLocalError):
                    self.logger.error('HAP connection destroyed (unexpectedly).')
                    break

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
