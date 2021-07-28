import os
import sys
import time
import struct
import socket
import argparse
import tempfile
import multiprocessing

import pprint

import http.server
import socketserver

import netifaces as ni
from hexdump import hexdump
from Crypto.Cipher import ChaCha20_Poly1305, AES
from zeroconf import IPVersion, ServiceInfo, Zeroconf
from biplist import readPlistFromString, writePlistToString

from ap2.connections.audio import RTPBuffer
from ap2.playfair import PlayFair
from ap2.utils import get_volume, set_volume, set_volume_pid
from ap2.pairing.hap import Hap, HAPSocket
from ap2.connections.event import Event
from ap2.connections.stream import Stream
from ap2.dxxp import parse_dxxp
from enum import IntFlag


"""
# No Auth - coreutils, PairSetupMfi
# MFi Verify fail error after pair-setup[2/5]
FEATURES = 0x88340405f8a00
# No Auth - HK and coreutils
# Stops after pairing (setup [5/5] verify [2/2])with no supported auth error
FEATURES = 0xc340405f8a00
# No Auth = HK, coreutils, PairSetupMFi
# MFi Verify fail error after pair-setup[2/5]
FEATURES = 0x8c340405f8a00
# Mfi Auth - HK and coreutils
# All encrypt after pairing (setup [5/5] verify [2/2])
FEATURES = 0xc340445f8a00
# FairPlay - HK and coreutils
# Stops after pairing (setup [5/5] verify [2/2])with no supported auth error
FEATURES = 0xc340405fca00
# FairPlay - HK and coreutils and transient
# fp-setup after pair-setup[2/5]
FEATURES = 0x1c340405fca00
# MFi - HK and coreutils and transient
# auth-setup after pair-setup[2/5]
FEATURES = 0x1c340445f8a00
# No Auth - No enc - PairSetupMFi
# Works!!
FEATURES = 0x8030040780a00
# No Auth - No enc
# No supported authentication types.
# FEATURES = 0x30040780a00
# FEATURES = 0x8030040780a00 | (1 << 27)

FEATURES = 0x1c340405fca00
"""


class Feat(IntFlag):
    # https://emanuelecozzi.net/docs/airplay2/features/
    # https://openairplay.github.io/airplay-spec/features.html
    # https://nto.github.io/AirPlay.html
    # 07: seems to need NTP
    Ft00Video            = 0x0000000000000001  # 1<<0
    Ft01Photo            = 0x0000000000000002  # 1<<1
    Ft02VideoFairPlay    = 0x0000000000000004  # 1<<2
    Ft03VideoVolumeCtrl  = 0x0000000000000008  # 1<<3
    Ft04VideoHTTPLiveStr = 0x0000000000000010  # 1<<4
    Ft05Slideshow        = 0x0000000000000020  # 1<<5
    # Ft06 = 0x40  # 1<<6
    Ft07ScreenMirroring  = 0x0000000000000080  # 1<<7
    Ft08ScreenRotate     = 0x0000000000000100  # 1<<8
    # Ft09 is necessary for iPhones/Music: audio
    Ft09AirPlayAudio     = 0x0000000000000200  # 1<<9
    Ft10Unknown          = 0x0000000000000400  # 1<<10
    Ft11AudRedundant     = 0x0000000000000800  # 1<<11
    # Feat12: iTunes4Win ends ANNOUNCE with rsaaeskey, does not attempt FPLY auth.
    # also coerces frequent OPTIONS packets (keepalive) from iPhones.
    Ft12FPSAPv2p5_AES_GCM = 0x0000000000001000  # 1<<12
    # 13-14 seem to be MFi stuff. 13: prevents assoc.
    Ft13MFiHardware      = 0x0000000000002000  # 1<<13
    # Music on iPhones needs this to stream audio
    Ft14MFiSoftware      = 0x0000000000004000  # 1<<14
    # 15-17 not mandatory -  faster pairing without
    Ft15AudioMetaCovers  = 0x0000000000008000  # 1<<15
    Ft16AudioMetaProgres = 0x0000000000010000  # 1<<16
    Ft17AudioMetaTxtDAAP = 0x0000000000020000  # 1<<17
    # macOS needs 18 to pair
    Ft18RcvAudPCM        = 0x0000000000040000  # 1<<18
    # macOS needs 19
    Ft19RcvAudALAC       = 0x0000000000080000  # 1<<19
    # iOS needs 20
    Ft20RcvAudAAC_LC     = 0x0000000000100000  # 1<<20
    Ft21Unknown          = 0x0000000000200000  # 1<<21
    # Try Ft22 without Ft40 - ANNOUNCE + SDP
    Ft22AudioUnencrypted = 0x0000000000400000  # 1<<22
    Ft23RSAAuth          = 0x0000000000800000  # 1<<23
    # Unknown             = #1<<24-#1<<25
    # Pairing stalls with longer /auth-setup string w/26
    # Ft25 seems to require ANNOUNCE
    Ft25iTunes4WEncrypt  = 0x0000000002000000  # 1<<25
    # try Ft26 without Ft40. Ft26 = crypt audio? mutex w/Ft22?
    Ft26AudioMfi         = 0x0000000004000000  # 1<<26
    # 27: connects and works OK
    Ft27LegacyPairing    = 0x0000000008000000  # 1<<27
    Ft29plistMetaData    = 0x0000000020000000  # 1<<29
    Ft30UnifiedAdvertInf = 0x0000000040000000  # 1<<30
    # Reserved?           =  # 1<<31
    # 32: iOS music does not see AP with this flag, but macOS sees video - car HUD?
    Ft32CarPlay          = 0x0000000100000000  # 1<<32
    # Ft33AirPlayVidPlayQ  = 0x0000000200000000  # 1<<33
    # Ft34AirPlayFromCloud = 0x0000000400000000  # 1<<34
    # Ft35TLS_PSK          = 0x0000000800000000  # 1<<35
    # Ft36Unknown          = 0x0000001000000000  # 1<<36
    Ft37CarPlayCtrl      = 0x0000002000000000  # 1<<37
    Ft38CtrlChanEncrypt  = 0x0000004000000000  # 1<<38
    # 40 absence: requires ANNOUNCE method
    Ft40BufferedAudio    = 0x0000010000000000  # 1<<40
    Ft41_PTPClock        = 0x0000020000000000  # 1<<41
    # Ft42ScreenMultiCodec= 0x00040000000000  # 1<<42
    # 43: sends system sounds thru also(?) - setup fails with iOS/macOS
    Ft43SystemPairing    = 0x0000080000000000  # 1<<43
    # 45: macOS wont connect, iOS will, but dies on play. 45<->41 seem mut.ex.
    # 45 triggers stream type:96 - 41, stream type:103
    Ft45_NTPClock        = 0x0000200000000000  # 1<<45
    Ft46HKPairing        = 0x0000400000000000  # 1<<46
    Ft47PeerMgmt         = 0x0000800000000000  # 1<<47
    Ft48TransientPairing = 0x0001000000000000  # 1<<48
    Ft49AirPlayVideoV2   = 0x0002000000000000  # 1<<49
    Ft50NowPlayingInfo   = 0x0004000000000000  # 1<<50
    Ft51MfiPairSetup     = 0x0008000000000000  # 1<<51
    Ft52PeersExtMsg      = 0x0010000000000000  # 1<<52
    # Ft54APSync           = 0x40000000000000  # 1<<54
    Ft60AudioMediaDataCt = 0x1000000000000000  # 1<<60
    """
    Ft51 - macOS sits for a while. Perhaps trying a closed connection port or medium?;
     iOS just fails at Pair-Setup [2/5]
    """


# # FEATURES = 0x1c340405fca00 equals the below mask
# FEATURES = (
#     Feat.Ft48TransientPairing | Feat.Ft47PeerMgmt | Feat.Ft46HKPairing
#     | Feat.Ft41_PTPClock | Feat.Ft40BufferedAudio | Feat.Ft38CtrlChanEncrypt
#     | Feat.Ft30UnifiedAdvertInf | Feat.Ft22AudioUnencrypted
#     | Feat.Ft20RcvAudAAC_LC | Feat.Ft19RcvAudALAC | Feat.Ft18RcvAudPCM
#     | Feat.Ft17AudioMetaTxtDAAP | Feat.Ft16AudioMetaProgres | Feat.Ft15AudioMetaCovers
#     | Feat.Ft14MFiSoftware | Feat.Ft11AudExtra | Feat.Ft09AirPlayAudio
# )

FEATURES = (
    Feat.Ft48TransientPairing | Feat.Ft47PeerMgmt | Feat.Ft46HKPairing
    | Feat.Ft41_PTPClock
    | Feat.Ft40BufferedAudio
    | Feat.Ft30UnifiedAdvertInf
    | Feat.Ft22AudioUnencrypted
    | Feat.Ft20RcvAudAAC_LC | Feat.Ft19RcvAudALAC | Feat.Ft18RcvAudPCM
    | Feat.Ft17AudioMetaTxtDAAP
    | Feat.Ft16AudioMetaProgres
    # | Feat.Ft15AudioMetaCovers
    | Feat.Ft14MFiSoftware | Feat.Ft09AirPlayAudio
)


# PI = Public ID (can be GUID, MAC, some string)
PI = b'aa5cb8df-7f14-4249-901a-5e748ce57a93'


class LTPK():
    # Long Term Public Key - get it from the hap module.
    def __init__(self):
        announce_id, self.ltpk = Hap(PI).configure()
        self.public_int = int.from_bytes(self.ltpk, byteorder='big')
        # builds a 64 char hex string, for the 32 byte pub key
        self.public_string = str.lower("{0:0>4X}".format(self.public_int))

    def get_pub_string(self):
        return self.public_string

    def get_pub_bytes(self):
        return self.ltpk


DEVICE_ID = None
IPV4 = None
IPV6 = None

SERVER_VERSION = "366.0"
HTTP_CT_BPLIST = "application/x-apple-binary-plist"
HTTP_CT_OCTET = "application/octet-stream"
HTTP_CT_PARAM = "text/parameters"
HTTP_CT_IMAGE = "image/jpeg"
HTTP_CT_DMAP = "application/x-dmap-tagged"
HTTP_CT_PAIR = "application/pairing+tlv8"
"""
X-Apple-HKP:
Values 0,2,3,4,6 seen.
 0 = Unauth. When Ft48TransientPairing and Ft43SystemPairing are absent
 2 = (pair-setup complete, pair-verify starts)
 3 = SystemPairing (with Ft43SystemPairing)
 4 = Transient
 6 = HomeKit
"""
HTTP_X_A_HKP = "X-Apple-HKP"
HTTP_X_A_CN = "X-Apple-Client-Name"
HTTP_X_A_PD = "X-Apple-PD"
LTPK = LTPK()


def setup_global_structs(args):
    global device_info
    global device_setup
    global device_setup_data
    global second_stage_info
    global mdns_props

    device_info = {
        # 'OSInfo': 'Linux 3.10.53',
        # 'PTPInfo': 'OpenAVNU ArtAndLogic-aPTP-changes a5d7f94-0.0.1',
        'audioLatencies': [
            {
                'inputLatencyMicros': 0,
                'outputLatencyMicros': 400000,
                'type': 100
            },
            {
                'audioType': 'default',
                'inputLatencyMicros': 0,
                'outputLatencyMicros': 400000,
                'type': 100},
            {
                'audioType': 'media',
                'inputLatencyMicros': 0,
                'outputLatencyMicros': 400000,
                'type': 100},
            {
                'audioType': 'media',
                'inputLatencyMicros': 0,
                'outputLatencyMicros': 400000,
                'type': 102
            }
        ],
        # 'build': '16.0',
        'deviceID': DEVICE_ID,
        'features': FEATURES,
        # 'features': 496155769145856, # Sonos One
        # 'firmwareBuildDate': 'Nov  5 2019',
        # 'firmwareRevision': '53.3-71050',
        # 'hardwareRevision': '1.21.1.8-2',
        'keepAliveLowPower': True,
        'keepAliveSendStatsAsBody': True,
        'manufacturer': 'OpenAirplay',
        'model': 'Receiver',
        'name': args.mdns,
        'nameIsFactoryDefault': False,
        'pi': 'ba5cb8df-7f14-4249-901a-5e748ce57a93',  # UUID generated casually..
        'protocolVersion': '1.1',
        'sdk': 'AirPlay;2.0.2',
        'sourceVersion': '366.0',
        'statusFlags': 4,
        # 'statusFlags': 0x404 # Sonos One
    }

    if DISABLE_VM:
        volume = 0
    else:
        volume = get_volume()
    second_stage_info = {
        "initialVolume": volume,
    }

    device_setup = {
        'eventPort': 0  # AP2 receiver event server
    }
    if not DISABLE_PTP_MASTER:
        device_setup['timingPort'] = 0
        device_setup['timingPeerInfo'] = {
            'Addresses': [
                IPV4, IPV6
            ],
            'ID': IPV4
        }

    device_setup_data = {
        'streams': [
            {
                'type': 96,
                'dataPort': 0,    # AP2 receiver data server
                'controlPort': 0  # AP2 receiver control server
            }
        ]
    }

    mdns_props = {
        "srcvers": SERVER_VERSION,
        "deviceid": DEVICE_ID,  # typically MAC addr
        "features": "%s,%s" % (hex(FEATURES & 0xffffffff), hex(FEATURES >> 32 & 0xffffffff)),
        "flags": "0x4",
        # "name": "GINO", # random
        "model": "Airplay2-Receiver",  # random
        # "manufacturer": "Pino", # random
        # "serialNumber": "01234xX321", # random
        "protovers": "1.1",
        "acl": "0",  # Access ControL. 0,1,2 == anon,users,admin(?)
        # These are found under the <deviceid>@<name> mDNS record.
        # "am": "One",  # Model
        # "cn": "0",  # CompressioN. 0,1,2,3 == (None aka) PCM, ALAC, AAC, AAC_ELD
        # "da": "true",  # Digest Auth(?) support
        # "et": "3",  # Encryption Types. 0,1,3,4,5 == None, RSA, FairPlay, Mfi, FairPlay SAPv2.5
        # "et": "0,1,3,4,5",  # Audio Encryption Types(?).
        # "md": "0,1,2",  # MetaData(?) 0,1,2 == Text, Gfx, Progress
        # "sf": "0x804",  # Status Flags?
        # "tp": "UDP",  # TransPort for media? csv of transports?
        # "vs": "366",  # Source version?
        "rsf": "0x0",  # bitmask: required sender features(?)
        "fv": "p20.78000.12",  # Firmware version. p20 == AirPlay Src revision?
        "pi": PI,   # Pairing UUID (generated casually)
        "gid": "5dccfd20-b166-49cc-a593-6abd5f724ddb",  # Group UUID (generated casually)
        "gcgl": "0",  # Group Contains Group Leader.
        # "isGroupLeader": "0"  # See gcgl
        # "vn": "65537",  # (Airplay) version number (supported) 16.16, 65537 == 1.1
        "pk": LTPK.get_pub_string()  # Ed25519 PubKey
    }


class AP2Handler(http.server.BaseHTTPRequestHandler):

    pp = pprint.PrettyPrinter()

    # Maps paths to methods a la HAP-python
    HANDLERS = {
        "POST": {
            "/command": "handle_command",
            "/feedback": "handle_feedback",
            "/audioMode": "handle_audiomode",
            "/auth-setup": "handle_auth_setup",
            "/fp-setup": "handle_fp_setup",
            "/fp-setup2": "handle_auth_setup",
            "/pair-setup": "handle_pair_setup",
            "/pair-verify": "handle_pair_verify",
            "/pair-add": "handle_pair_add",
            "/pair-remove": "handle_pair_remove",
            "/pair-list": "handle_pair_list",
            "/configure": "handle_configure",
        },
        "GET": {
            "/info": "handle_info",
        },
        "PUT": {"/xyz": "handle_xyz"},
    }

    def dispatch(self):
        """Dispatch the request to the appropriate handler method."""
        print(f'{self.command}: {self.path}')
        print(self.headers)
        try:
            getattr(self, self.HANDLERS[self.command][self.path])()
        except KeyError:
            self.send_error(
                404,
                ": Method %s Path %s endpoint not implemented" % (self.command, self.path),
            )
            self.server.hap = None

    def parse_request(self):
        self.raw_requestline = self.raw_requestline.replace(b"RTSP/1.0", b"HTTP/1.1")

        r = http.server.BaseHTTPRequestHandler.parse_request(self)
        self.protocol_version = "RTSP/1.0"
        self.close_connection = 0
        return r

    def process_info(self, device_name):
        print('Process info called')
        device_info["name"] = "TODO"

    def send_response(self, code, message=None):
        if message is None:
            if code in self.responses:
                message = self.responses[code][0]
            else:
                message = b''

        response = "%s %d %s\r\n" % (self.protocol_version, code, message)
        self.wfile.write(response.encode())

    def version_string(self):
        return "AirTunes/%s" % SERVER_VERSION

    def do_GET(self):
        self.dispatch()

    def do_OPTIONS(self):
        print(self.headers)

        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.send_header("Public",
                         "ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH"
                         "FLUSHBUFFERED, TEARDOWN, OPTIONS, POST, GET, PUT"
                         "SETPEERSX"
                         )
        self.end_headers()

    def do_FLUSHBUFFERED(self):
        print("FLUSHBUFFERED")
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

        if self.headers["Content-Type"] == HTTP_CT_BPLIST:
            content_len = int(self.headers["Content-Length"])
            if content_len > 0:
                body = self.rfile.read(content_len)

                plist = readPlistFromString(body)
                flush_from_seq = 0
                if "flushFromSeq" in plist:
                    flush_from_seq = plist["flushFromSeq"]
                if "flushUntilSeq" in plist:
                    flush_until_seq = plist["flushUntilSeq"]
                    self.server.streams[0].audio_connection.send("flush_from_until_seq-%i-%i" % (flush_from_seq, flush_until_seq))
                self.pp.pprint(plist)

    def do_POST(self):
        self.dispatch()

    def do_SETUP(self):
        dacp_id = self.headers.get("DACP-ID")
        active_remote = self.headers.get("Active-Remote")
        ua = self.headers.get("User-Agent")
        print("SETUP %s" % self.path)
        print(self.headers)
        if self.headers["Content-Type"] == HTTP_CT_BPLIST:
            content_len = int(self.headers["Content-Length"])
            if content_len > 0:
                body = self.rfile.read(content_len)

                plist = readPlistFromString(body)
                self.pp.pprint(plist)
                if "streams" not in plist:
                    print("Sending EVENT:")
                    event_port, self.event_proc = Event.spawn()
                    device_setup["eventPort"] = event_port
                    print("[+] eventPort=%d" % event_port)

                    self.pp.pprint(device_setup)
                    res = writePlistToString(device_setup)
                    self.send_response(200)
                    self.send_header("Content-Length", len(res))
                    self.send_header("Content-Type", HTTP_CT_BPLIST)
                    self.send_header("Server", self.version_string())
                    self.send_header("CSeq", self.headers["CSeq"])
                    self.end_headers()
                    self.wfile.write(res)
                else:
                    print("Sending CONTROL/DATA:")
                    buff = 8388608  # determines how many CODEC frame size 1024 we can hold
                    stream = Stream(plist["streams"][0], buff)
                    set_volume_pid(stream.data_proc.pid)
                    self.server.streams.append(stream)
                    device_setup_data["streams"][0]["controlPort"] = stream.control_port
                    device_setup_data["streams"][0]["dataPort"] = stream.data_port

                    print("[+] controlPort=%d dataPort=%d" % (stream.control_port, stream.data_port))
                    if stream.type == Stream.BUFFERED:
                        device_setup_data["streams"][0]["type"] = stream.type
                        device_setup_data["streams"][0]["audioBufferSize"] = buff

                    self.pp.pprint(device_setup_data)
                    res = writePlistToString(device_setup_data)

                    self.send_response(200)
                    self.send_header("Content-Length", len(res))
                    self.send_header("Content-Type", HTTP_CT_BPLIST)
                    self.send_header("Server", self.version_string())
                    self.send_header("CSeq", self.headers["CSeq"])
                    self.end_headers()
                    self.wfile.write(res)
                return
        self.send_error(404)

    def do_GET_PARAMETER(self):
        print("GET_PARAMETER %s" % self.path)
        print(self.headers)
        params_res = {}
        content_len = int(self.headers["Content-Length"])
        if content_len > 0:
            body = self.rfile.read(content_len)

            params = body.splitlines()
            for p in params:
                if p == b"volume":
                    print("GET_PARAMETER: %s" % p)
                    if not DISABLE_VM:
                        params_res[p] = str(get_volume()).encode()
                    else:
                        print("Volume Management is disabled")
                else:
                    print("Ops GET_PARAMETER: %s" % p)
        if DISABLE_VM:
            res = b"volume: 0" + b"\r\n"
        else:
            res = b"\r\n".join(b"%s: %s" % (k, v) for k, v in params_res.items()) + b"\r\n"
        self.send_response(200)
        self.send_header("Content-Length", len(res))
        self.send_header("Content-Type", HTTP_CT_PARAM)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()
        hexdump(res)
        self.wfile.write(res)

    def do_SET_PARAMETER(self):
        print("SET_PARAMETER %s" % self.path)
        print(self.headers)
        params_res = {}
        content_type = self.headers["Content-Type"]
        content_len = int(self.headers["Content-Length"])
        if content_type == HTTP_CT_PARAM:
            if content_len > 0:
                body = self.rfile.read(content_len)

                params = body.splitlines()
                for p in params:
                    pp = p.split(b":")
                    if pp[0] == b"volume":
                        print("SET_PARAMETER: %s => %s" % (pp[0], pp[1]))
                        if not DISABLE_VM:
                            set_volume(float(pp[1]))
                        else:
                            print("Volume Management is disabled")
                    elif pp[0] == b"progress":
                        print("SET_PARAMETER: %s => %s" % (pp[0], pp[1]))
                    else:
                        print("Ops SET_PARAMETER: %s" % p)
        elif content_type == HTTP_CT_IMAGE:
            if content_len > 0:
                fname = None
                with tempfile.NamedTemporaryFile(prefix="artwork", dir=".", delete=False, suffix=".jpg") as f:
                    f.write(self.rfile.read(content_len))
                    fname = f.name
                print("Artwork saved to %s" % fname)
        elif content_type == HTTP_CT_DMAP:
            if content_len > 0:
                parse_dxxp(self.rfile.read(content_len))
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def do_RECORD(self):
        print("RECORD %s" % self.path)
        print(self.headers)
        if self.headers["Content-Type"] == HTTP_CT_BPLIST:
            content_len = int(self.headers["Content-Length"])
            if content_len > 0:
                body = self.rfile.read(content_len)

                plist = readPlistFromString(body)
                self.pp.pprint(plist)
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def do_SETRATEANCHORTIME(self):
        print("SETRATEANCHORTIME %s" % self.path)
        print(self.headers)
        if self.headers["Content-Type"] == HTTP_CT_BPLIST:
            content_len = int(self.headers["Content-Length"])
            try:
                if content_len > 0:
                    body = self.rfile.read(content_len)

                    plist = readPlistFromString(body)
                    if plist["rate"] == 1:
                        self.server.streams[0].audio_connection.send("play-%i" % plist["rtpTime"])
                    if plist["rate"] == 0:
                        self.server.streams[0].audio_connection.send("pause")
                    self.pp.pprint(plist)
            except IndexError:
                # Fixes some disconnects
                print('Cannot process request; streams torn down already.')
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def do_TEARDOWN(self):
        print("TEARDOWN %s" % self.path)
        print(self.headers)
        if self.headers["Content-Type"] == HTTP_CT_BPLIST:
            content_len = int(self.headers["Content-Length"])
            if content_len > 0:
                body = self.rfile.read(content_len)

                plist = readPlistFromString(body)
                if "streams" in plist:
                    stream_id = plist["streams"][0]["streamID"]
                    stream = self.server.streams[stream_id]
                    stream.teardown()
                    del self.server.streams[stream_id]
                else:
                    for stream in self.server.streams:
                        stream.teardown()
                    self.server.streams.clear()
                self.pp.pprint(plist)
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

        # Erase the hap() instance, otherwise reconnects fail
        self.server.hap = None

        # terminate the forked event_proc, otherwise a zombie process consumes 100% cpu
        self.event_proc.terminate()

    def do_SETPEERS(self):
        print("SETPEERS %s" % self.path)
        print(self.headers)
        content_len = int(self.headers["Content-Length"])
        if content_len > 0:
            body = self.rfile.read(content_len)

            plist = readPlistFromString(body)
            self.pp.pprint(plist)
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def do_SETPEERSX(self):
        # extended message format for setting PTP clock peers
        # Requires Ft52PeersExtMsg (bit 52)
        # Note: this method does not require defining in do_OPTIONS

        # Content-Type: /peer-list-changed-x
        # Contains [] array of:
        # {'Addresses': ['fe80::fb:97fb:2fb3:34bc',
        #         '192.168.19.110'],
        #   'ClockID': 000000000000000000,
        #   'ClockPorts': {GUID1: port,
        #                  GUID2: port,
        #                  GUIDN: port},
        #   'DeviceType': 0,
        #   'ID': GUID,
        #   'SupportsClockPortMatchingOverride': T/F}

        # SETPEERSX may require more logic when PTP is finished.
        print("SETPEERSX %s" % self.path)
        print(self.headers)
        content_len = int(self.headers["Content-Length"])
        if content_len > 0:
            body = self.rfile.read(content_len)

            plist = readPlistFromString(body)
            self.pp.pprint(plist)
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def do_FLUSH(self):
        print("FLUSH %s" % self.path)
        print(self.headers)
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def handle_command(self):
        if self.headers["Content-Type"] == HTTP_CT_BPLIST:
            content_len = int(self.headers["Content-Length"])
            if content_len > 0:
                body = self.rfile.read(content_len)

                plist = readPlistFromString(body)
                newin = []
                if "mrSupportedCommandsFromSender" in plist["params"]:
                    for p in plist["params"]["mrSupportedCommandsFromSender"]:
                        iplist = readPlistFromString(p)
                        newin.append(iplist)
                    plist["params"]["mrSupportedCommandsFromSender"] = newin
                if "params" in plist["params"] and "kMRMediaRemoteNowPlayingInfoArtworkData" in plist["params"]["params"]:
                    plist["params"]["params"]["kMRMediaRemoteNowPlayingInfoArtworkData"] = "<redacted ..too long>"
                self.pp.pprint(plist)
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def handle_feedback(self):
        self.handle_generic()

    def handle_audiomode(self):
        self.handle_generic()

    def handle_generic(self):
        if self.headers["Content-Type"] == HTTP_CT_BPLIST:
            content_len = int(self.headers["Content-Length"])
            if content_len > 0:
                body = self.rfile.read(content_len)

                plist = readPlistFromString(body)
                self.pp.pprint(plist)

        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def handle_auth_setup(self):
        self.handle_X_setup('auth')

    def handle_fp_setup(self):
        self.handle_X_setup('fp')

    def handle_X_setup(self, op: str = ''):
        content_len = int(self.headers["Content-Length"])
        if content_len > 0:
            body = self.rfile.read(content_len)
            if op == 'fp':
                pf = PlayFair()
                pf_info = PlayFair.fairplay_s()
                response = pf.fairplay_setup(pf_info, body)
            hexdump(body)

        self.send_response(200)
        self.send_header("Content-Length", len(response))
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()
        if op == 'fp':
            self.wfile.write(response)

    def handle_pair_setup(self):
        self.handle_pair_SV('setup')

    def handle_pair_verify(self):
        self.handle_pair_SV('verify')

    def handle_pair_SV(self, op):
        body = self.rfile.read(int(self.headers["Content-Length"]))

        if not self.server.hap:
            self.server.hap = Hap(PI)
        if op == 'verify':
            res = self.server.hap.pair_verify(body)
        elif op == 'setup':
            res = self.server.hap.pair_setup(body)

        self.send_response(200)
        self.send_header("Content-Length", len(res))
        self.send_header("Content-Type", self.headers["Content-Type"])
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()
        self.wfile.write(res)

        if self.server.hap.encrypted:
            hexdump(self.server.hap.accessory_shared_key)
            self.upgrade_to_encrypted(self.server.hap.accessory_shared_key)

    def handle_pair_add(self):
        self.handle_pair_ARL('add')

    def handle_pair_remove(self):
        self.handle_pair_ARL('remove')

    def handle_pair_list(self):
        self.handle_pair_ARL('list')

    def handle_pair_ARL(self, op):
        print("pair-%s %s" % (op, self.path))
        print(self.headers)
        content_len = int(self.headers["Content-Length"])
        if content_len > 0:
            body = self.rfile.read(content_len)
            if op == 'add':
                res = self.server.hap.pair_add(body)
            elif op == 'remove':
                res = self.server.hap.pair_remove(body)
            elif op == 'list':
                res = self.server.hap.pair_list(body)
            hexdump(res)
            self.send_response(200)
            self.send_header("Content-Type", self.headers["Content-Type"])
            self.send_header("Content-Length", len(res))
            self.send_header("Server", self.version_string())
            self.send_header("CSeq", self.headers["CSeq"])
            self.end_headers()
            self.wfile.write(res)

    def handle_configure(self):
        acl_s = 'Access_Control_Level'
        acl = 0
        cd_s = 'ConfigurationDictionary'
        dn = 'NEWBORNE'
        dn_s = 'Device_Name'
        hkac = False
        hkac_s = 'Enable_HK_Access_Control'
        pw = ''
        pw_s = 'Password'
        print("configure %s" % self.path)
        print(self.headers)
        content_len = int(self.headers["Content-Length"])
        if content_len > 0:
            body = self.rfile.read(content_len)
            plist = readPlistFromString(body)
            self.pp.pprint(plist)
            if acl_s in plist[cd_s]:
                # 0 == Everyone on the LAN
                # 1 == Home members
                # 2 == Admin members
                acl = int(plist[cd_s][acl_s])
            if dn_s in plist[cd_s]:
                dn = plist[cd_s][dn_s]
            if hkac_s in plist[cd_s]:
                hkac = bool(plist[cd_s][hkac_s])
            if pw_s in plist[cd_s]:
                pw = plist[cd_s][pw_s]

        accessory_id, accessory_ltpk = self.server.hap.configure()
        configure_info = {
            'Identifier': accessory_id.decode('utf-8'),
            'Enable_HK_Access_Control': hkac,
            'PublicKey': accessory_ltpk,
            'Device_Name': dn,
            'Access_Control_Level': acl
        }
        if pw != '':
            configure_info['Password'] = pw

        res = writePlistToString(configure_info)
        self.pp.pprint(configure_info)

        self.send_response(200)
        self.send_header("Content-Length", len(res))
        self.send_header("Content-Type", HTTP_CT_BPLIST)
        self.send_header("Server", self.version_string())

        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()
        self.wfile.write(res)

    def handle_info(self):
        if "Content-Type" in self.headers:
            if self.headers["Content-Type"] == HTTP_CT_BPLIST:
                content_len = int(self.headers["Content-Length"])
                if content_len > 0:
                    body = self.rfile.read(content_len)

                    plist = readPlistFromString(body)
                    self.pp.pprint(plist)
                    if "qualifier" in plist and "txtAirPlay" in plist["qualifier"]:
                        print("Sending:")
                        self.pp.pprint(device_info)
                        res = writePlistToString(device_info)

                        self.send_response(200)
                        self.send_header("Content-Length", len(res))
                        self.send_header("Content-Type", HTTP_CT_BPLIST)
                        self.send_header("Server", self.version_string())
                        self.send_header("CSeq", self.headers["CSeq"])
                        self.end_headers()
                        self.wfile.write(res)
                    else:
                        print("No txtAirPlay")
                        self.send_error(404)
                        return
                else:
                    print("No content")
                    self.send_error(404)
                    return
            else:
                print("Content-Type: %s | Not implemented" % self.headers["Content-Type"])
                self.send_error(404)
        else:
            res = writePlistToString(device_info)
            self.send_response(200)
            self.send_header("Content-Length", len(res))
            self.send_header("Content-Type", HTTP_CT_BPLIST)
            self.send_header("Server", self.version_string())
            self.send_header("CSeq", self.headers["CSeq"])
            self.end_headers()
            self.wfile.write(res)

    def upgrade_to_encrypted(self, shared_key):
        self.request = self.server.upgrade_to_encrypted(
            self.client_address,
            shared_key)
        self.connection = self.request
        self.rfile = self.connection.makefile('rb', self.rbufsize)
        self.wfile = self.connection.makefile('wb')
        self.is_encrypted = True
        print("----- ENCRYPTED CHANNEL -----")


def register_mdns(receiver_name):
    addresses = []
    for ifen in ni.interfaces():
        ifenaddr = ni.ifaddresses(ifen)
        if ni.AF_INET in ifenaddr:
            addresses.append(socket.inet_pton(
                ni.AF_INET,
                ifenaddr[ni.AF_INET][0]["addr"])
            )
        if ni.AF_INET6 in ifenaddr:
            addresses.append(socket.inet_pton(
                ni.AF_INET6,
                ifenaddr[ni.AF_INET6][0]["addr"].split("%")[0])
            )

    info = ServiceInfo(
        "_airplay._tcp.local.",
        "%s._airplay._tcp.local." % receiver_name,
        # addresses=[socket.inet_aton("127.0.0.1")],
        addresses=addresses,
        port=7000,
        properties=mdns_props,
        server="%s.local." % receiver_name,
    )

    zeroconf = Zeroconf(ip_version=IPVersion.V4Only)
    zeroconf.register_service(info)
    print("mDNS service registered")
    return (zeroconf, info)


def unregister_mdns(zeroconf, info):
    print("Unregistering...")
    zeroconf.unregister_service(info)
    zeroconf.close()


def get_free_port():
    free_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    free_socket.bind(('0.0.0.0', 0))
    free_socket.listen(5)
    port = free_socket.getsockname()[1]
    free_socket.close()
    return port


class AP2Server(socketserver.TCPServer):
    # Fixes 99% of scenarios on restart after we terminate uncleanly/crash
    # and port was not closed before crash (is still open).
    # AP2 client connects from random port.
    allow_reuse_address = True

    def __init__(self, addr_port, handler):
        super().__init__(addr_port, handler)
        self.connections = {}
        self.hap = None
        self.enc_layer = False
        self.streams = []

    # Override
    def get_request(self):
        client_socket, client_addr = super().get_request()
        print("Got connection with %s:%d" % client_addr)
        self.connections[client_addr] = client_socket
        return (client_socket, client_addr)

    def upgrade_to_encrypted(self, client_address, shared_key):
        client_socket = self.connections[client_address]
        hap_socket = HAPSocket(client_socket, shared_key)
        self.connections[client_address] = hap_socket
        return hap_socket


def list_network_interfaces():
    print("Available network interfaces:")
    for interface in ni.interfaces():
        print(f'  Interface: "{interface}"')
        addresses = ni.ifaddresses(interface)
        for address_family in addresses:
            if address_family in [ni.AF_INET, ni.AF_INET6]:
                for ak in addresses[address_family]:
                    for akx in ak:
                        if str(akx) == 'addr':
                            print(f"    {'IPv4' if address_family == ni.AF_INET else 'IPv6'}: {str(ak[akx])}")


def list_available_flags():
    print(f'[?] Available feature names:')
    for ft in Feat:
        print(f' {ft.name}')
    print('[?] Choose named features via their numbers. E.g. for Ft07, write: 7')


if __name__ == "__main__":

    multiprocessing.set_start_method("spawn")
    parser = argparse.ArgumentParser(prog='AirPlay 2 receiver')
    mutexgroup = parser.add_mutually_exclusive_group()

    parser.add_argument("-m", "--mdns", help="mDNS name to announce", default="myap2")
    parser.add_argument("-n", "--netiface", help="Network interface to bind to. Use the --list-interfaces option to list available interfaces.")
    parser.add_argument("-nv", "--no-volume-management", help="Disable volume management", action='store_true')
    parser.add_argument("-npm", "--no-ptp-master", help="Stops this receiver from being announced as the PTP Master",
                        action='store_true')
    mutexgroup.add_argument("-f", "--features", help="Features: a hex representation of Airplay features. Note: mutex with -ft(xxx)")
    mutexgroup.add_argument(
        "-ft", nargs='+', type=int, metavar='F',
        help="Explicitly enable individual Airplay feature bits. Use 0 for help.")
    mutexgroup.add_argument(
        "-ftnot", nargs='+', type=int, metavar='F',
        help="Bitwise NOT toggle individual Airplay feature bits from the default. Use 0 for help.")
    mutexgroup.add_argument(
        "-ftand", nargs='+', type=int, metavar='F',
        help="Bitwise AND toggle individual Airplay feature bits from the default. Use 0 for help.")
    mutexgroup.add_argument(
        "-ftor", nargs='+', type=int, metavar='F',
        help="Bitwise OR toggle individual Airplay feature bits from the default. Use 0 for help.")
    mutexgroup.add_argument(
        "-ftxor", nargs='+', type=int, metavar='F',
        help="Bitwise XOR toggle individual Airplay feature bits from the default. Use 0 for help.")
    parser.add_argument("--list-interfaces", help="Prints available network interfaces and exits.", action='store_true')

    args = parser.parse_args()

    if args.list_interfaces:
        list_network_interfaces()
        exit(0)

    if args.netiface is None:
        print("[!] Missing --netiface argument. See below for a list of valid interfaces")
        list_network_interfaces()
        exit(-1)

    try:
        IFEN = args.netiface
        ifen = ni.ifaddresses(IFEN)
    except Exception:
        print("[!] Network interface not found.")
        list_network_interfaces()
        exit(-1)

    DISABLE_VM = args.no_volume_management
    DISABLE_PTP_MASTER = args.no_ptp_master
    if args.features:
        # Old way. Leave for those who use this way.
        try:
            FEATURES = int(args.features, 16)
        except Exception:
            print("[!] Error with feature arg - hex format required")
            exit(-1)

    bitwise = args.ft or args.ftnot or args.ftor or args.ftxor or args.ftand
    # This param is mutex with args.features
    if bitwise:
        if (bitwise == [0]):
            list_available_flags()
            exit(0)
        else:
            try:
                flags = 0
                for ft in bitwise:
                    if ft > 64:
                        raise Exception
                    flags |= (1 << int(ft))
                if args.ft:
                    FEATURES = Feat(flags)
                elif args.ftnot:
                    FEATURES = Feat(~flags)
                elif args.ftand:
                    FEATURES &= Feat(flags)
                elif args.ftor:
                    FEATURES |= Feat(flags)
                elif args.ftxor:
                    FEATURES ^= Feat(flags)
                print(f'Chosen features: {flags:016x}')
                print(Feat(flags))
            except Exception:
                print("[!] Incorrect flags/mask.")
                print(f"[!] Proceeding with defaults.")
    print(f'Enabled features: {FEATURES:016x}')
    print(FEATURES)

    DEVICE_ID = None
    IPV4 = None
    IPV6 = None
    if ifen.get(ni.AF_LINK):
        DEVICE_ID = ifen[ni.AF_LINK][0]["addr"]
    if ifen.get(ni.AF_INET):
        IPV4 = ifen[ni.AF_INET][0]["addr"]
    if ifen.get(ni.AF_INET6):
        IPV6 = ifen[ni.AF_INET6][0]["addr"].split("%")[0]

    setup_global_structs(args)

    # Rudimentary check for whether v4/6 are still None (no IP found)
    if IPV4 is None and IPV6 is None:
        print("[!] No IP found on chosen interface.")
        list_network_interfaces()
        exit(-1)

    print("Interface: %s" % IFEN)
    print("IPv4: %s" % IPV4)
    print("IPv6: %s" % IPV6)
    print()

    mdns = register_mdns(args.mdns)
    print("Starting RTSP server, press Ctrl-C to exit...")
    try:
        PORT = 7000
        if IPV6 and not IPV4:
            with AP2Server((IPV6, PORT), AP2Handler) as httpd:
                print("serving at port", PORT)
                httpd.serve_forever()
        else:  # i.e. (IPV4 and not IPV6) or (IPV6 and IPV4)
            with AP2Server((IPV4, PORT), AP2Handler) as httpd:
                print("serving at port", PORT)
                httpd.serve_forever()

    except KeyboardInterrupt:
        pass
    except ConnectionResetError:
        # Weird client termination at the other end.
        pass
    finally:
        print("Shutting down mDNS...")
        unregister_mdns(*mdns)
