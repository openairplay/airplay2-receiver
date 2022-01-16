from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto import Random
import base64
from .utils import get_screen_logger
from ap2.fairplay3 import Fairplay3


AIRPORT_PRIVATE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpQIBAAKCAQEA59dE8qLieItsH1WgjrcFRKj6eUWqi+bGLOX1HL3U3GhC/j0Qg90u3sG/1CUt\n"
    "wC5vOYvfDmFI6oSFXi5ELabWJmT2dKHzBJKa3k9ok+8t9ucRqMd6DZHJ2YCCLlDRKSKv6kDqnw4U\n"
    "wPdpOMXziC/AMj3Z/lUVX1G7WSHCAWKf1zNS1eLvqr+boEjXuBOitnZ/bDzPHrTOZz0Dew0uowxf\n"
    "/+sG+NCK3eQJVxqcaJ/vEHKIVd2M+5qL71yJQ+87X6oV3eaYvt3zWZYD6z5vYTcrtij2VZ9Zmni/\n"
    "UAaHqn9JdsBWLUEpVviYnhimNVvYFZeCXg/IdTQ+x4IRdiXNv5hEewIDAQABAoIBAQDl8Axy9XfW\n"
    "BLmkzkEiqoSwF0PsmVrPzH9KsnwLGH+QZlvjWd8SWYGN7u1507HvhF5N3drJoVU3O14nDY4TFQAa\n"
    "LlJ9VM35AApXaLyY1ERrN7u9ALKd2LUwYhM7Km539O4yUFYikE2nIPscEsA5ltpxOgUGCY7b7ez5\n"
    "NtD6nL1ZKauw7aNXmVAvmJTcuPxWmoktF3gDJKK2wxZuNGcJE0uFQEG4Z3BrWP7yoNuSK3dii2jm\n"
    "lpPHr0O/KnPQtzI3eguhe0TwUem/eYSdyzMyVx/YpwkzwtYL3sR5k0o9rKQLtvLzfAqdBxBurciz\n"
    "aaA/L0HIgAmOit1GJA2saMxTVPNhAoGBAPfgv1oeZxgxmotiCcMXFEQEWflzhWYTsXrhUIuz5jFu\n"
    "a39GLS99ZEErhLdrwj8rDDViRVJ5skOp9zFvlYAHs0xh92ji1E7V/ysnKBfsMrPkk5KSKPrnjndM\n"
    "oPdevWnVkgJ5jxFuNgxkOLMuG9i53B4yMvDTCRiIPMQ++N2iLDaRAoGBAO9v//mU8eVkQaoANf0Z\n"
    "oMjW8CN4xwWA2cSEIHkd9AfFkftuv8oyLDCG3ZAf0vrhrrtkrfa7ef+AUb69DNggq4mHQAYBp7L+\n"
    "k5DKzJrKuO0r+R0YbY9pZD1+/g9dVt91d6LQNepUE/yY2PP5CNoFmjedpLHMOPFdVgqDzDFxU8hL\n"
    "AoGBANDrr7xAJbqBjHVwIzQ4To9pb4BNeqDndk5Qe7fT3+/H1njGaC0/rXE0Qb7q5ySgnsCb3DvA\n"
    "cJyRM9SJ7OKlGt0FMSdJD5KG0XPIpAVNwgpXXH5MDJg09KHeh0kXo+QA6viFBi21y340NonnEfdf\n"
    "54PX4ZGS/Xac1UK+pLkBB+zRAoGAf0AY3H3qKS2lMEI4bzEFoHeK3G895pDaK3TFBVmD7fV0Zhov\n"
    "17fegFPMwOII8MisYm9ZfT2Z0s5Ro3s5rkt+nvLAdfC/PYPKzTLalpGSwomSNYJcB9HNMlmhkGzc\n"
    "1JnLYT4iyUyx6pcZBmCd8bD0iwY/FzcgNDaUmbX9+XDvRA0CgYEAkE7pIPlE71qvfJQgoA9em0gI\n"
    "LAuE4Pu13aKiJnfft7hIjbK+5kyb3TysZvoyDnb3HOKvInK7vXbKuU4ISgxB2bB3HcYzQMGsz1qJ\n"
    "2gG0N5hvJpzwwhbhXqFKA4zaaSrw622wDniAK5MlIE0tIAKKP4yxNGjoD2QYjhBGuhvkWKY=\n"
    "-----END RSA PRIVATE KEY-----"
)


class FairPlayAES():
    def __init__(self,
                 rsaaeskeyb64=None,  # either RSA
                 fpaeskeyb64=None, aesivb64=None,  # or b64 encoded key+iv
                 fpaeskey=None, aesiv=None,  # or binary key+iv
                 keymsg=None,  # Needed to decrypt the FP AES keys
                 ):
        self.logger = get_screen_logger(__name__, 'DEBUG')
        self.aesiv = None
        if rsaaeskeyb64:
            airportkey = RSA.importKey(AIRPORT_PRIVATE_KEY)
            cipher = PKCS1_OAEP.new(airportkey)

            binkey = decodeb64(rsaaeskeyb64)
            """
            Decoded RSA keys are 256 bytes
            """
            self.aeskey = cipher.decrypt(binkey)
            """
            AES keys obtained are 16 bytes
            """
            if len(self.aeskey) == 16:
                self.logger.info('Got RSA AES key (base64)')
        elif fpaeskeyb64:
            self.fairplay3 = Fairplay3()
            self.logger.info('Got FP AES key (base64)')
            self.aeskey = decodeb64(fpaeskeyb64)
            """
            Decoded AES keys are 72 bytes long starting:
            'FPLY...'
            Note: they are not yet decrypted (MFi)
            """
            # Now decrypt the AES key:
            self.aeskey = self.fairplay3.decryptAESKey(keymsg, self.aeskey)
        elif fpaeskey:
            self.fairplay3 = Fairplay3()
            self.logger.info('Got FP AES key')
            self.aeskey = self.fairplay3.decryptAESKey(keymsg, fpaeskey)

        # Handle AES IV
        if aesivb64:
            self.aesiv = decodeb64(aesivb64)
            self.logger.info('Got AES IV (base64)')
        elif aesiv:
            self.aesiv = aesiv
            self.logger.info('Got AES IV')

    def getAESKey(self):
        return self.aeskey

    def getAESIV(self):
        return self.aesiv


def decodeb64(_input):
    return base64.standard_b64decode(_input + '==')


def encodeb64(_input):
    b64 = base64.standard_b64encode(_input)
    if b64[-2:] == b"==":
        b64 = b64[:-2]

    return b64


# ===========


class PlayFair:
    MODES = 4
    MODE_POSITON = 14
    TYPE_POSITION = 5
    SEQ_POSITION = 6
    SETUP_MESSAGE_TYPE = 1
    DECRYPT_MESSAGE_TYPE = 2
    SETUP1_MESSAGE_SEQ = 1
    SETUP2_MESSAGE_SEQ = 3
    SETUP1_RESPONSE_LENGTH = 142
    SETUP2_RESPONSE_LENGTH = 32
    SETUP2_RESPONSE_SUFFIX_LENGTH = 20

    # Single buffer of 4x 142 byte long reply sequences
    reply_message = [
        b'\x46\x50\x4c\x59\x03\x01\x02\x00\x00\x00\x00\x82\x02\x00\x0f\x9f\x3f\x9e\x0a\x25\x21\xdb\xdf\x31\x2a\xb2\xbf\xb2\x9e\x8d\x23\x2b\x63\x76\xa8\xc8\x18\x70\x1d\x22\xae\x93\xd8\x27\x37\xfe\xaf\x9d\xb4\xfd\xf4\x1c\x2d\xba\x9d\x1f\x49\xca\xaa\xbf\x65\x91\xac\x1f\x7b\xc6\xf7\xe0\x66\x3d\x21\xaf\xe0\x15\x65\x95\x3e\xab\x81\xf4\x18\xce\xed\x09\x5a\xdb\x7c\x3d\x0e\x25\x49\x09\xa7\x98\x31\xd4\x9c\x39\x82\x97\x34\x34\xfa\xcb\x42\xc6\x3a\x1c\xd9\x11\xa6\xfe\x94\x1a\x8a\x6d\x4a\x74\x3b\x46\xc3\xa7\x64\x9e\x44\xc7\x89\x55\xe4\x9d\x81\x55\x00\x95\x49\xc4\xe2\xf7\xa3\xf6\xd5\xba',
        b'\x46\x50\x4c\x59\x03\x01\x02\x00\x00\x00\x00\x82\x02\x01\xcf\x32\xa2\x57\x14\xb2\x52\x4f\x8a\xa0\xad\x7a\xf1\x64\xe3\x7b\xcf\x44\x24\xe2\x00\x04\x7e\xfc\x0a\xd6\x7a\xfc\xd9\x5d\xed\x1c\x27\x30\xbb\x59\x1b\x96\x2e\xd6\x3a\x9c\x4d\xed\x88\xba\x8f\xc7\x8d\xe6\x4d\x91\xcc\xfd\x5c\x7b\x56\xda\x88\xe3\x1f\x5c\xce\xaf\xc7\x43\x19\x95\xa0\x16\x65\xa5\x4e\x19\x39\xd2\x5b\x94\xdb\x64\xb9\xe4\x5d\x8d\x06\x3e\x1e\x6a\xf0\x7e\x96\x56\x16\x2b\x0e\xfa\x40\x42\x75\xea\x5a\x44\xd9\x59\x1c\x72\x56\xb9\xfb\xe6\x51\x38\x98\xb8\x02\x27\x72\x19\x88\x57\x16\x50\x94\x2a\xd9\x46\x68\x8a',
        b'\x46\x50\x4c\x59\x03\x01\x02\x00\x00\x00\x00\x82\x02\x02\xc1\x69\xa3\x52\xee\xed\x35\xb1\x8c\xdd\x9c\x58\xd6\x4f\x16\xc1\x51\x9a\x89\xeb\x53\x17\xbd\x0d\x43\x36\xcd\x68\xf6\x38\xff\x9d\x01\x6a\x5b\x52\xb7\xfa\x92\x16\xb2\xb6\x54\x82\xc7\x84\x44\x11\x81\x21\xa2\xc7\xfe\xd8\x3d\xb7\x11\x9e\x91\x82\xaa\xd7\xd1\x8c\x70\x63\xe2\xa4\x57\x55\x59\x10\xaf\x9e\x0e\xfc\x76\x34\x7d\x16\x40\x43\x80\x7f\x58\x1e\xe4\xfb\xe4\x2c\xa9\xde\xdc\x1b\x5e\xb2\xa3\xaa\x3d\x2e\xcd\x59\xe7\xee\xe7\x0b\x36\x29\xf2\x2a\xfd\x16\x1d\x87\x73\x53\xdd\xb9\x9a\xdc\x8e\x07\x00\x6e\x56\xf8\x50\xce',
        b'\x46\x50\x4c\x59\x03\x01\x02\x00\x00\x00\x00\x82\x02\x03\x90\x01\xe1\x72\x7e\x0f\x57\xf9\xf5\x88\x0d\xb1\x04\xa6\x25\x7a\x23\xf5\xcf\xff\x1a\xbb\xe1\xe9\x30\x45\x25\x1a\xfb\x97\xeb\x9f\xc0\x01\x1e\xbe\x0f\x3a\x81\xdf\x5b\x69\x1d\x76\xac\xb2\xf7\xa5\xc7\x08\xe3\xd3\x28\xf5\x6b\xb3\x9d\xbd\xe5\xf2\x9c\x8a\x17\xf4\x81\x48\x7e\x3a\xe8\x63\xc6\x78\x32\x54\x22\xe6\xf7\x8e\x16\x6d\x18\xaa\x7f\xd6\x36\x25\x8b\xce\x28\x72\x6f\x66\x1f\x73\x88\x93\xce\x44\x31\x1e\x4b\xe6\xc0\x53\x51\x93\xe5\xef\x72\xe8\x68\x62\x33\x72\x9c\x22\x7d\x82\x0c\x99\x94\x45\xd8\x92\x46\xc8\xc3\x59']

    fp_header = b'\x46\x50\x4c\x59\x03\x01\x04\x00\x00\x00\x00\x14'

    fply_1 = b'\x46\x50\x4c\x59\x02\x01\x01\x00\x00\x00\x00\x04\x02\x00\x02\xbb'

    class fairplay_s:
        def __init__(self):
            logger = None
            keymsg = None
            keymsglen = 0  # type int

    def fairplay_setup(self, fp, request):
        if request[4] != 3:
            # Unsupported fairplay version
            return None

        type = request[self.TYPE_POSITION]
        seq = request[self.SEQ_POSITION]
        # fp.keymsglen = 0;

        if type == self.SETUP_MESSAGE_TYPE:
            if seq == self.SETUP1_MESSAGE_SEQ:
                mode = request[self.MODE_POSITON]
                response = self.reply_message[mode]
            elif seq == self.SETUP2_MESSAGE_SEQ:
                response = self.fp_header
                response = response + request[len(request) - self.SETUP2_RESPONSE_SUFFIX_LENGTH:len(request)]
            return response
        else:
            return None
