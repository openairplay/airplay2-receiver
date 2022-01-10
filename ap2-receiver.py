import os
import sys
import time
import struct
import socket
import logging
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

from ap2.playfair import PlayFair, FairPlayAES
from ap2.utils import get_volume, set_volume, set_volume_pid, get_screen_logger
from ap2.pairing.hap import Hap, HAPSocket
from ap2.connections.event import EventGeneric
from ap2.connections.audio import AudioSetup
from ap2.connections.stream import Stream
from ap2.dxxp import parse_dxxp
from enum import IntFlag, Enum


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
    Ft06_Unknown         = 0x0000000000000040  # 1<<6
    Ft07ScreenMirroring  = 0x0000000000000080  # 1<<7
    Ft08ScreenRotate     = 0x0000000000000100  # 1<<8
    # Ft09 is necessary for iPhones/Music: audio
    Ft09AirPlayAudio     = 0x0000000000000200  # 1<<9
    Ft10Unknown          = 0x0000000000000400  # 1<<10
    Ft11AudRedundant     = 0x0000000000000800  # 1<<11
    # Feat12: iTunes4Win ends ANNOUNCE with rsaaeskey, does not attempt FPLY auth.
    # also coerces frequent OPTIONS packets (keepalive) from iPhones.
    Ft12FPSAPv2p5_AES_GCM = 0x0000000000001000  # 1<<12
    # 13-14 MFi stuff.
    Ft13MFiHardware      = 0x0000000000002000  # 1<<13
    # Music on iPhones needs this to stream audio
    Ft14MFiSoft_FairPlay = 0x0000000000004000  # 1<<14
    # 15-17 not mandatory - faster pairing without
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
    Ft23RSA_Auth         = 0x0000000000800000  # 1<<23
    Ft24Unknown          = 0x0000000001000000  # 1<<24
    # Pairing stalls with longer /auth-setup string w/26
    # Ft25 seems to require ANNOUNCE
    Ft25iTunes4WEncrypt  = 0x0000000002000000  # 1<<25
    # try Ft26 without Ft40. Ft26 = crypt audio? mutex w/Ft22?
    Ft26Audio_AES_Mfi    = 0x0000000004000000  # 1<<26
    # 27: connects and works OK
    Ft27LegacyPairing    = 0x0000000008000000  # 1<<27
    Ft28_Unknown         = 0x0000000010000000  # 1<<28
    Ft29plistMetaData    = 0x0000000020000000  # 1<<29
    Ft30UnifiedAdvertInf = 0x0000000040000000  # 1<<30
    # Bit 31 Reserved     =  # 1<<31
    Ft32CarPlay          = 0x0000000100000000  # 1<<32
    Ft33AirPlayVidPlayQ  = 0x0000000200000000  # 1<<33
    Ft34AirPlayFromCloud = 0x0000000400000000  # 1<<34
    Ft35TLS_PSK          = 0x0000000800000000  # 1<<35
    Ft36_Unknown         = 0x0000001000000000  # 1<<36
    Ft37CarPlayCtrl      = 0x0000002000000000  # 1<<37
    # 38 seems to be implicit with other flags; works with or without 38.
    Ft38CtrlChanEncrypt  = 0x0000004000000000  # 1<<38
    Ft39_Unknown         = 0x0000008000000000  # 1<<39
    # 40 absence: requires ANNOUNCE method
    Ft40BufferedAudio    = 0x0000010000000000  # 1<<40
    Ft41_PTPClock        = 0x0000020000000000  # 1<<41
    Ft42ScreenMultiCodec = 0x0000040000000000  # 1<<42
    # 43
    Ft43SystemPairing    = 0x0000080000000000  # 1<<43
    Ft44APValeriaScrSend = 0x0000100000000000  # 1<<44
    # 45: macOS wont connect, iOS will, but dies on play. 45<->41 seem mut.ex.
    # 45 triggers stream type:96 (without ft41, PTP)
    Ft45_NTPClock        = 0x0000200000000000  # 1<<45
    Ft46HKPairing        = 0x0000400000000000  # 1<<46
    Ft47PeerMgmt         = 0x0000800000000000  # 1<<47
    Ft48TransientPairing = 0x0001000000000000  # 1<<48
    Ft49AirPlayVideoV2   = 0x0002000000000000  # 1<<49
    Ft50NowPlayingInfo   = 0x0004000000000000  # 1<<50
    Ft51MfiPairSetup     = 0x0008000000000000  # 1<<51
    Ft52PeersExtMsg      = 0x0010000000000000  # 1<<52
    Ft53_Unknown         = 0x0020000000000000  # 1<<53
    Ft54SupportsAPSync   = 0x0040000000000000  # 1<<54
    Ft55SupportsWoL      = 0x0080000000000000  # 1<<55
    Ft56SupportsWoL      = 0x0100000000000000  # 1<<56
    Ft57_Unknown         = 0x0200000000000000  # 1<<57
    Ft58HangdogRemote    = 0x0400000000000000  # 1<<58
    Ft59AudStreamConnStp = 0x0800000000000000  # 1<<59
    Ft60AudMediaDataCtrl = 0x1000000000000000  # 1<<60
    Ft61RFC2198Redundant = 0x2000000000000000  # 1<<61
    Ft62_Unknown         = 0x4000000000000000  # 1<<62
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
#     | Feat.Ft14MFiSoft_FairPlay | Feat.Ft11AudExtra | Feat.Ft09AirPlayAudio
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
    | Feat.Ft14MFiSoft_FairPlay | Feat.Ft09AirPlayAudio
)


class StatusFlags(IntFlag):
    StatusNone         = 0x00000  # 0
    ProblemsExist      = 0x00001  # 1<< 0
    # Probably a WAC (wireless accessory ctrl) thing:
    Unconfigured       = 0x00002  # 1<< 1
    # Audio cable attached (legacy): all is well.
    AudioLink          = 0x00004  # 1<< 2
    PINmode            = 0x00008  # 1<< 3
    PINentry           = 0x00010  # 1<< 4
    PINmatch           = 0x00020  # 1<< 5
    StatusUnknown6     = 0x00040  # 1<< 6
    # Need password to use
    PasswordNeeded     = 0x00080  # 1<< 7
    StatusUnknown8     = 0x00100  # 1<< 8
    # need PIN to pair
    PairingPIN         = 0x00200  # 1<< 9
    # was set up for HK Access ctrl
    HKAccessControl    = 0x00400  # 1<<10
    # RCR opens up interesting behaviours
    RemoteControlRelay = 0x00800  # 1<<11


STATUS_FLAGS = (
    StatusFlags.AudioLink
    # we must handle stream type 130 for RCR
    # | StatusFlags.RemoteControlRelay
)

# PI = Public ID (can be GUID, MAC, some string)
PI = b'aa5cb8df-7f14-4249-901a-5e748ce57a93'
DEBUG = False


class LTPK():
    # Long Term Public Key - get it from the hap module.
    def __init__(self, isDebug=False):
        announce_id, self.ltpk = Hap(PI, isDebug).configure()
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
HTTP_X_A_AT = "X-Apple-AbsoluteTime"  # Unix timestamp for current system date/time.
HTTP_X_A_ET = "X-Apple-ET"  # Encryption Type

#
AIRPLAY_BUFFER = 8388608  # 0x800000 i.e. 1024 * 8192 - how many CODEC frame size 1024 we can hold


def get_hex_bitmask(in_features):
    """
    prepares the feature bits into text form
    """
    if in_features.bit_length() <= 32:
        # print(f"{hex(in_features)}")
        return f"{hex(in_features)}"
    else:
        # print(f'feature bit length: {in_features.bit_length()} ')
        # print(f"{hex(in_features & 0xffffffff)},{hex(in_features >> 32 & 0xffffffff)}")
        return f"{hex(in_features & 0xffffffff)},{hex(in_features >> 32 & 0xffffffff)}"


def setup_global_structs(args, isDebug=False):
    global device_info
    global device_setup
    global device_setup_data
    global second_stage_info
    global mdns_props
    global LTPK
    LTPK = LTPK(isDebug)

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
        # features: can send in hex() also
        'features': int(FEATURES),
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
        'statusFlags': get_hex_bitmask(STATUS_FLAGS),
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
        if IPV6 and not IPV4:
            addr = [
                IPV6
            ]
        else:
            # Prefer (only) IPV4
            addr = [
                IPV4
            ]
        device_setup['timingPort'] = 0  # Seems like legacy, non PTP setting
        device_setup['timingPeerInfo'] = {
            'Addresses': addr,
            'ID': DEVICE_ID
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
        # Airplay flags
        # Access ControL. 0,1,2 == anon,users,admin(?)
        "acl": "0",
        "deviceid": DEVICE_ID,  # device MAC addr
        # Features, aka ft - see Feat class.
        "features": get_hex_bitmask(FEATURES),
        # flags (bitmask)
        "flags": get_hex_bitmask(STATUS_FLAGS),
        # Group Contains Group Leader.
        "gcgl": "0",
        # Group UUID (generated casually)
        "gid": "5dccfd20-b166-49cc-a593-6abd5f724ddb",
        # isGroupLeader: See gcgl
        # "isGroupLeader": "0",
        # "manufacturer": "Pino",
        "model": "Airplay2-Receiver",
        # "name": "GINO",
        "protovers": "1.1",
        # Required Sender Features (bitmask)
        "rsf": "0x0",
        # "serialNumber": "01234xX321",
        # Source Version (airplay SDK?): absence triggers AP1 ANNOUNCE behaviour.
        "srcvers": SERVER_VERSION,

        # RAOP Flags - (XX)
        # These are found under the <deviceid>@<name> mDNS record.
        # Apple Model (name)
        # "am": "One",
        # (amount of audio) CHannels
        "ch": "2",
        # CompressioN. 0,1,2,3 == (None aka) PCM, ALAC, AAC, AAC_ELD
        "cn": "0,1,2",
        # Digest Auth RFC-2617 support
        # "da": "true",
        # Encryption Key
        # "ek": "1",
        # Encryption Types. 0,1,3,4,5 == None, RSA, FairPlay, Mfi, FairPlay SAPv2.5
        # "et": "3",
        # "et": "0,1",
        # "et": "0,1,3,4,5",
        # Firmware version. p20 == AirPlay Src revision?
        # "fv": "p20.78000.12",
        # MetaData(?) 0,1,2 == Text, Gfx, Progress (only needed for pre iOS7 senders)
        # "md": "0,1,2",
        # Pairing UUID (generated casually)
        "pi": PI,
        # Ed25519 PubKey
        "pk": LTPK.get_pub_string(),
        # "protovers": "1.1",
        # PassWord enabled: 0/false off, 1/true on.
        # -This requires Method POST Path /pair-pin-start endpoint
        # "pw": "false",
        # Status Flags (bitmask): see StatusFlags class.
        # "sf": get_hex_bitmask(STATUS_FLAGS),
        # Software Mute (whether needed)
        # "sm": "false",
        # Sample Rate
        # "sr": "44100",
        # Sample Size
        # "ss": "16",
        # Software Volume (whether needed)
        # "sv": "false",
        # TransPort for media. CSV of capables transports for audio
        # "tp": "TCP,UDP",
        # (Airplay) version number (supported) 16bit.16bit, 65537 == 1.1
        # "vn": "65537",
        # Source version
        # "vs": "366",
    }


class SDPHandler():
    # systemcrash 2021
    class SDPAudioFormat(Enum):
        (
            UNSUPPORTED,
            PCM,
            ALAC,
            AAC,
            AAC_ELD,
            OPUS,
        ) = range(6)

    def __init__(self, sdp=''):
        from ap2.connections.audio import AirplayAudFmt

        self.sdp = sdp.splitlines()
        self.has_mfi = False
        self.has_rsa = False
        self.has_fp = False
        self.last_media = ''
        self.has_audio = False
        self.has_video = False
        self.audio_format = self.SDPAudioFormat.UNSUPPORTED
        self.minlatency = 11025
        self.maxlatency = 11025
        self.spf = 0
        for k in self.sdp:
            if 'v=' in k:
                self.ver_line = k
            elif 'o=' in k:
                self.o_line = k
            elif 's=' in k:
                self.subj_line = k
            elif 'c=' in k:
                self.conn_line = k
            elif 't=' in k:
                self.t_line = k
            elif 'm=audio' in k:
                self.has_audio = True
                self.last_media = 'audio'
                self.m_aud_line = k
                start = self.m_aud_line.find('AVP ') + 4
                self.audio_media_type = int(self.m_aud_line[start:])
            elif 'a=rtpmap:' in k and self.last_media == 'audio':
                self.audio_rtpmap = k.split(':')[1]
                start = self.audio_rtpmap.find(':') + 1
                mid = self.audio_rtpmap.find(' ') + 1
                self.payload_type = self.audio_rtpmap[start:mid - 1]  # coerce to int later
                self.audio_encoding = self.audio_rtpmap[mid:]
                if self.audio_encoding == 'AppleLossless':
                    self.audio_format = self.SDPAudioFormat.ALAC
                elif 'mpeg4-generic/' in self.audio_encoding:
                    self.audio_format = self.SDPAudioFormat.AAC
                    discard, self.audio_format_sr, self.audio_format_ch = self.audio_encoding.split('/')
                    self.audio_format_bd = 16
                else:
                    self.audio_format = self.SDPAudioFormat.PCM
                    self.audio_format_bd, self.audio_format_sr, self.audio_format_ch = self.audio_encoding.split('/')
                    self.audio_format_bd = ''.join(filter(str.isdigit, self.audio_format_bd))
            elif 'a=fmtp:' in k and self.payload_type in k:
                self.audio_fmtp = k.split(':')[1]
                self.afp = self.audio_fmtp.split(' ')  # audio format params
                if self.audio_format == self.SDPAudioFormat.ALAC:
                    self.spf = self.afp[1]  # samples per frame
                    # a=fmtp:96 352 0 16 40 10 14 2 255 0 0 44100
                    self.params = AudioSetup(
                        codec_tag='alac',
                        ver=0,
                        spf=self.afp[1],
                        compat_ver=self.afp[2],
                        ss=self.afp[3],  # bitdepth
                        hist_mult=self.afp[4],
                        init_hist=self.afp[5],
                        rice_lmt=self.afp[6],
                        cc=self.afp[7],
                        max_run=self.afp[8],
                        mcfs=self.afp[9],
                        abr=self.afp[10],
                        sr=self.afp[11],
                    )
                    self.audio_format_bd = self.afp[3]
                    self.audio_format_ch = self.afp[7]
                    self.audio_format_sr = self.afp[11]
                    self.audio_desc = 'ALAC'
                elif self.audio_format == self.SDPAudioFormat.AAC:
                    self.audio_desc = 'AAC_LC'
                elif self.audio_format == self.SDPAudioFormat.PCM:
                    self.audio_desc = 'PCM'
                elif self.audio_format == self.SDPAudioFormat.OPUS:
                    self.audio_desc = 'OPUS'
                if 'mode=' in self.audio_fmtp:
                    self.audio_format = self.SDPAudioFormat.AAC_ELD
                    for x in self.afp:
                        if 'constantDuration=' in x:
                            start = x.find('constantDuration=') + len('constantDuration=')
                            self.constantDuration = int(x[start:].rstrip(';'))
                            self.spf = self.constantDuration
                        elif 'mode=' in x:
                            start = x.find('mode=') + len('mode=')
                            self.aac_mode = x[start:].rstrip(';')
                    self.audio_desc = 'AAC_ELD'
                for f in AirplayAudFmt:
                    if(self.audio_desc in f.name
                        and self.audio_format_bd in f.name
                        and self.audio_format_sr in f.name
                        and self.audio_format_ch in f.name
                       ):
                        self.AirplayAudFmt = f.value
                        self.audio_format_bd = int(self.audio_format_bd)
                        self.audio_format_ch = int(self.audio_format_ch)
                        self.audio_format_sr = int(self.audio_format_sr)
                        break
                # video fmtp not needed, it seems.
            elif 'a=mfiaeskey:' in k:
                self.has_mfi = True
                self.aeskey = k.split(':')[1]
            elif 'a=rsaaeskey:' in k:
                self.has_rsa = True
                # RSA - Use Feat.Ft12FPSAPv2p5_AES_GCM
                self.aeskey = k.split(':')[1]
            elif 'a=fpaeskey:' in k:
                self.has_fp = True
                # FairPlay (v3?) AES key
                self.aeskey = k.split(':')[1]
            elif 'a=aesiv:' in k:
                self.aesiv = k.split(':')[1]
            elif 'a=min-latency:' in k:
                self.minlatency = k.split(':')[1]
            elif 'a=max-latency:' in k:
                self.maxlatency = k.split(':')[1]
            elif 'm=video' in k:
                self.has_video = True
                self.last_media = 'video'
                self.m_video_line = k
                start = self.m_video_line.find('AVP ') + 4
                self.video_media_type = int(self.m_video_line[start:])
            elif 'a=rtpmap:' in k and self.last_media == 'video':
                self.video_rtpmap = k.split(':')[1]
                start = self.video_rtpmap.find(':') + 1
                mid = self.video_rtpmap.find(' ') + 1
                self.video_payload = int(self.video_rtpmap[start:mid - 1])
                self.video_encoding = self.video_rtpmap[mid:]


class AP2Handler(http.server.BaseHTTPRequestHandler):
    aeskeyobj = None
    pp = pprint.PrettyPrinter()
    ntp_port, ptp_port = 0, 0
    ntp_proc, ptp_proc = None, None

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
        path = self.path
        paramStr = ''
        if '?' in self.path:
            path = self.path.split('?')[0]
            paramStr = self.path.split('?')[1]

        SCR_LOG.debug(f'{self.command}: {path}')
        SCR_LOG.debug(f'!Dropped parameters: {paramStr}') if paramStr else SCR_LOG.debug('')
        SCR_LOG.debug(self.headers)
        try:
            # pass additional paramArray:
            # getattr(self, self.HANDLERS[self.command][path])(paramArray)
            # Note: handle_* signatures need e.g. (self, *args, **kwargs)
            getattr(self, self.HANDLERS[self.command][path])()
        except KeyError:
            self.send_error(
                404,
                f": Method {self.command} Path {path} endpoint not implemented"
            )
            self.server.hap = None

    def parse_request(self):
        self.raw_requestline = self.raw_requestline.replace(b"RTSP/1.0", b"HTTP/1.1")

        r = http.server.BaseHTTPRequestHandler.parse_request(self)
        self.protocol_version = "RTSP/1.0"
        self.close_connection = 0
        return r

    def process_info(self, device_name):
        SCR_LOG.info('Process info called')
        device_info["name"] = "TODO"

    def send_response(self, code, message=None):
        if message is None:
            if code in self.responses:
                message = self.responses[code][0]
            else:
                message = b''

        response = f"{self.protocol_version} {code} {message}\r\n"
        self.wfile.write(response.encode())

    def version_string(self):
        return f"AirTunes/{SERVER_VERSION}"

    def do_GET(self):
        self.dispatch()

    def do_OPTIONS(self):
        SCR_LOG.debug(self.headers)

        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.send_header("Public",
                         "ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH"
                         "FLUSHBUFFERED, TEARDOWN, OPTIONS, POST, GET, PUT"
                         "SETPEERSX"
                         )
        self.end_headers()

    def do_ANNOUNCE(self):
        # Enable Feature bit 12: Ft12FPSAPv2p5_AES_GCM: this uses only RSA
        # Enabling Feat bit 25 and iTunes4win attempts AES - cannot yet decrypt.
        SCR_LOG.info(f'{self.command}: {self.path}')
        SCR_LOG.debug(self.headers)

        if self.headers["Content-Type"] == 'application/sdp':
            content_len = int(self.headers["Content-Length"])
            if content_len > 0:
                sdp_body = self.rfile.read(content_len).decode('utf-8')
                SCR_LOG.debug(sdp_body)
                sdp = SDPHandler(sdp_body)
                self.aud_params = sdp.params
                if sdp.has_mfi:
                    SCR_LOG.warning("MFi not possible on this hardware.")
                    self.send_response(404)
                    self.server.hap = None
                else:
                    if(sdp.audio_format is SDPHandler.SDPAudioFormat.ALAC
                       and int((FEATURES & Feat.Ft19RcvAudALAC)) == 0):
                        SCR_LOG.warning("This receiver not configured for ALAC (set flag 19).")
                        self.send_response(404)
                        self.server.hap = None
                    elif (sdp.audio_format is SDPHandler.SDPAudioFormat.AAC
                          and int((FEATURES & Feat.Ft20RcvAudAAC_LC)) == 0):
                        SCR_LOG.warning("This receiver not configured for AAC (set flag 20).")
                        self.send_response(404)
                        self.server.hap = None
                    elif (sdp.audio_format is SDPHandler.SDPAudioFormat.AAC_ELD
                          and int((FEATURES & Feat.Ft20RcvAudAAC_LC)) == 0):
                        SCR_LOG.warning("This receiver not configured for AAC (set flag 20/21).")
                        self.send_response(404)
                        self.server.hap = None
                    else:
                        if sdp.has_fp and self.fairplay_keymsg:
                            self.aeskeyobj = FairPlayAES(fpaeskeyb64=sdp.aeskey, aesivb64=sdp.aesiv, keymsg=self.fairplay_keymsg)
                        elif sdp.has_rsa:
                            self.aeskeyobj = FairPlayAES(rsaaeskeyb64=sdp.aeskey, aesivb64=sdp.aesiv)
                        self.send_response(200)
                        self.send_header("Server", self.version_string())
                        self.send_header("CSeq", self.headers["CSeq"])
                        self.end_headers()
                self.sdp = sdp

    def do_FLUSHBUFFERED(self):
        SCR_LOG.info(f'{self.command}: {self.path}')
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

        if self.headers["Content-Type"] == HTTP_CT_BPLIST:
            content_len = int(self.headers["Content-Length"])
            if content_len > 0:
                body = self.rfile.read(content_len)

                plist = readPlistFromString(body)
                fr = 0
                if "flushFromSeq" in plist:
                    fr = plist["flushFromSeq"]
                if "flushUntilSeq" in plist:
                    to = plist["flushUntilSeq"]
                    self.server.streams[0].audio_connection.send(f"flush_from_until_seq-{fr}-{to}")
                SCR_LOG.debug(self.pp.pformat(plist))

    def do_POST(self):
        self.dispatch()

    def do_SETUP(self):
        dacp_id = self.headers.get("DACP-ID")
        active_remote = self.headers.get("Active-Remote")
        ua = self.headers.get("User-Agent")
        SCR_LOG.info(f'{self.command}: {self.path}')
        SCR_LOG.debug(self.headers)
        # Found in SETUP after ANNOUNCE:
        if self.headers["Transport"]:
            # SCR_LOG.debug(self.headers["Transport"])

            # Set up a stream to receive.
            stream = {
                'audioFormat': self.sdp.AirplayAudFmt,
                'latencyMin': int(self.sdp.minlatency),
                'latencyMax': int(self.sdp.maxlatency),
                'ct': 0,  # Compression Type(?)
                'shk': self.aeskeyobj.aeskey,
                'shiv': self.aeskeyobj.aesiv,
                'spf': int(self.sdp.spf),  # sample frames per pkt
                'type': int(self.sdp.payload_type),
                'controlPort': 0,
            }

            streamobj = Stream(stream, AIRPLAY_BUFFER, DEBUG, self.aud_params)

            self.server.streams.append(streamobj)

            event_port, self.event_proc = EventGeneric.spawn(
                self.server.server_address, name='events', isDebug=DEBUG)
            timing_port, self.timing_proc = EventGeneric.spawn(
                self.server.server_address, name='ntp', isDebug=DEBUG)
            transport = self.headers["Transport"].split(';')
            res = []
            res.append("RTP/AVP/UDP")
            res.append("unicast")
            res.append("mode=record")
            ctl_msg = f"control_port={streamobj.control_port}"
            res.append(ctl_msg)
            SCR_LOG.debug(ctl_msg)
            data_msg = f"server_port={streamobj.data_port}"
            res.append(data_msg)
            SCR_LOG.debug(data_msg)
            ntp_msg = f"timing_port={timing_port}"
            res.append(ntp_msg)
            SCR_LOG.debug(ntp_msg)
            string = ';'

            self.send_response(200)
            self.send_header("Transport", string.join(res))
            self.send_header("Session", "1")
            self.send_header("Audio-Jack-Status", 'connected; type=analog')
            self.send_header("Server", self.version_string())
            self.send_header("CSeq", self.headers["CSeq"])
            self.end_headers()
            SCR_LOG.info('')

            return

        if self.headers["Content-Type"] == HTTP_CT_BPLIST:
            content_len = int(self.headers["Content-Length"])
            if content_len > 0:
                body = self.rfile.read(content_len)

                plist = readPlistFromString(body)
                SCR_LOG.debug(self.pp.pformat(plist))
                if 'eiv' in plist and 'ekey' in plist:
                    self.aesiv = plist['eiv']
                    self.aeskey = plist['ekey']
                    self.aeskeyobj = FairPlayAES(fpaeskey=self.aeskey, aesiv=self.aesiv, keymsg=self.fairplay_keymsg)

                if "streams" not in plist:
                    SCR_LOG.debug("Sending EVENT:")
                    event_port, self.event_proc = EventGeneric.spawn(
                        self.server.server_address, name='events', isDebug=DEBUG)
                    device_setup["eventPort"] = event_port
                    SCR_LOG.debug(f"[+] eventPort={event_port}")

                    SCR_LOG.debug(self.pp.pformat(device_setup))
                    res = writePlistToString(device_setup)
                    self.send_response(200)
                    self.send_header("Content-Length", len(res))
                    self.send_header("Content-Type", HTTP_CT_BPLIST)
                    self.send_header("Server", self.version_string())
                    self.send_header("CSeq", self.headers["CSeq"])
                    self.end_headers()
                    self.wfile.write(res)
                    SCR_LOG.info('')
                else:
                    SCR_LOG.debug("Sending CONTROL/DATA:")
                    stream = Stream(plist["streams"][0], AIRPLAY_BUFFER, DEBUG)
                    set_volume_pid(stream.data_proc.pid)
                    self.server.streams.append(stream)
                    device_setup_data["streams"][0]["controlPort"] = stream.control_port
                    device_setup_data["streams"][0]["dataPort"] = stream.data_port

                    SCR_LOG.debug(f"[+] controlPort={stream.control_port} dataPort={stream.data_port}")
                    if stream.type == Stream.BUFFERED:
                        device_setup_data["streams"][0]["type"] = stream.type
                        device_setup_data["streams"][0]["audioBufferSize"] = AIRPLAY_BUFFER

                    SCR_LOG.debug(self.pp.pformat(device_setup_data))
                    res = writePlistToString(device_setup_data)

                    self.send_response(200)
                    self.send_header("Content-Length", len(res))
                    self.send_header("Content-Type", HTTP_CT_BPLIST)
                    self.send_header("Server", self.version_string())
                    self.send_header("CSeq", self.headers["CSeq"])
                    self.end_headers()
                    self.wfile.write(res)
                    SCR_LOG.info('')
                return
        self.send_error(404)
        SCR_LOG.info('')

    def do_GET_PARAMETER(self):
        SCR_LOG.info(f'{self.command}: {self.path}')
        SCR_LOG.debug(self.headers)
        params_res = {}
        content_len = int(self.headers["Content-Length"])
        if content_len > 0:
            body = self.rfile.read(content_len)

            params = body.splitlines()
            for p in params:
                if p == b"volume":
                    SCR_LOG.info(f"GET_PARAMETER: {p}")
                    if not DISABLE_VM:
                        params_res[p] = str(get_volume()).encode()
                    else:
                        SCR_LOG.warning("Volume Management is disabled")
                else:
                    SCR_LOG.info(f"Ops GET_PARAMETER: {p}")
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
        self.wfile.write(res)
        hexdump(res) if DEBUG else ''

    def do_SET_PARAMETER(self):
        SCR_LOG.info(f'{self.command}: {self.path}')
        SCR_LOG.debug(self.headers)
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
                        SCR_LOG.info(f"SET_PARAMETER: {pp[0]} => {pp[1]}")
                        if not DISABLE_VM:
                            set_volume(float(pp[1]))
                        else:
                            SCR_LOG.warning("Volume Management is disabled")
                    # elif pp[0] == b"progress":
                        # startTimeStamp, currentTimeStamp, stopTimeStamp
                        # SCR_LOG.info(pp[1].decode('utf8').lstrip(' ').split('/'))
                    #     SCR_LOG.info(f"SET_PARAMETER: {pp[0]} => {pp[1]}")
                    # else:
                    #     SCR_LOG.info(f"Ops SET_PARAMETER: {p}")
        elif content_type == HTTP_CT_IMAGE:
            if content_len > 0:
                fname = None
                with tempfile.NamedTemporaryFile(prefix="artwork", dir=".", delete=False, suffix=".jpg") as f:
                    f.write(self.rfile.read(content_len))
                    fname = f.name
                SCR_LOG.info(f"Artwork saved to {fname}")
        elif content_type == HTTP_CT_DMAP:
            if content_len > 0:
                SCR_LOG.info(parse_dxxp(self.rfile.read(content_len)))
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def do_RECORD(self):
        SCR_LOG.info(f'{self.command}: {self.path}')
        SCR_LOG.debug(self.headers)
        if self.headers["Content-Type"] == HTTP_CT_BPLIST:
            content_len = int(self.headers["Content-Length"])
            if content_len > 0:
                body = self.rfile.read(content_len)

                plist = readPlistFromString(body)
                SCR_LOG.info(self.pp.pformat(plist))
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def do_SETRATEANCHORTIME(self):
        SCR_LOG.info(f'{self.command}: {self.path}')
        SCR_LOG.debug(self.headers)
        if self.headers["Content-Type"] == HTTP_CT_BPLIST:
            content_len = int(self.headers["Content-Length"])
            try:
                if content_len > 0:
                    body = self.rfile.read(content_len)

                    plist = readPlistFromString(body)
                    if plist["rate"] == 1:
                        self.server.streams[0].audio_connection.send(f"play-{plist['rtpTime']}")
                    if plist["rate"] == 0:
                        self.server.streams[0].audio_connection.send("pause")
                    SCR_LOG.info(self.pp.pformat(plist))
            except IndexError:
                # Fixes some disconnects
                SCR_LOG.error('Cannot process request; streams torn down already.')
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def do_TEARDOWN(self):
        SCR_LOG.info(f'{self.command}: {self.path}')
        SCR_LOG.debug(self.headers)
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
                SCR_LOG.info(self.pp.pformat(plist))
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

        # Erase the hap() instance, otherwise reconnects fail
        self.server.hap = None

        # terminate the forked event_proc, otherwise a zombie process consumes 100% cpu
        self.event_proc.terminate()
        if(self.ntp_proc):
            self.ntp_proc.terminate()
        # When changing from RTP_BUFFERED to REALTIME, must clean up:
        for stream in self.server.streams:
            stream.teardown()
        self.server.streams.clear()

    def do_SETPEERS(self):
        """
        A shorter format to set timing (PTP clock) peers.

        Content-Type: /peer-list-changed
        Contains [] array of IP{4|6}addrs:
        ['...::...',
         '...::...',
         '...']
        """
        SCR_LOG.info(f'{self.command}: {self.path}')
        SCR_LOG.debug(self.headers)
        content_len = int(self.headers["Content-Length"])
        if content_len > 0:
            body = self.rfile.read(content_len)

            plist = readPlistFromString(body)
            SCR_LOG.info(self.pp.pformat(plist))
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def do_SETPEERSX(self):
        # Extended format for setting timing (PTP clock) peers
        # Requires Ft52PeersExtMsg (bit 52)
        # Note: this method does not require defining in do_OPTIONS

        # Content-Type: /peer-list-changed-x
        # Contains [] array of:
        # {'Addresses': ['fe80::...',
        #         '...'],
        #   'ClockID': 000000000000000000,
        #   'ClockPorts': {GUID1: port,
        #                  GUID2: port,
        #                  GUIDN: port},
        #   'DeviceType': 0,
        #   'ID': GUID,
        #   'SupportsClockPortMatchingOverride': T/F}

        # SETPEERSX may require more logic when PTP is finished.
        SCR_LOG.info(f'{self.command}: {self.path}')
        SCR_LOG.debug(self.headers)
        content_len = int(self.headers["Content-Length"])
        if content_len > 0:
            body = self.rfile.read(content_len)

            plist = readPlistFromString(body)
            SCR_LOG.info(self.pp.pformat(plist))
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def do_FLUSH(self):
        SCR_LOG.info(f'{self.command}: {self.path}')
        SCR_LOG.debug(self.headers)
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
                # don't print this massive blob - one day we may use it though.
                # SCR_LOG.debug(plist)  # SCR_LOG.info(self.pp.pformat(plist))
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
                SCR_LOG.info(self.pp.pformat(plist))

        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def handle_auth_setup(self):
        self.handle_X_setup('auth')

    def handle_fp_setup(self):
        self.handle_X_setup('fp')

    def handle_X_setup(self, op: str = ''):
        response = b''
        content_len = int(self.headers["Content-Length"])
        if content_len > 0:
            # This is the session fairplay_keymsg (168 bytes long)
            self.fairplay_keymsg = body = self.rfile.read(content_len)

            if op == 'fp':
                pf = PlayFair()
                pf_info = PlayFair.fairplay_s()
                response = pf.fairplay_setup(pf_info, body)
            if op == 'auth':
                plist = readPlistFromString(body)
                SCR_LOG.info(self.pp.pformat(plist))
                if 'X-Apple-AT' in self.headers and self.headers["X-Apple-AT"] == '16':
                    # Use flags: 144037111597568 / 0x830040DF0A00
                    SCR_LOG.error('Unhandled edge-case for unencrypted auth setup')
            hexdump(body) if DEBUG else ''

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
            self.server.hap = Hap(PI, DEBUG)
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

        if self.server.hap.encrypted and self.server.hap.mfi_setup:
            SCR_LOG.warning('MFi setup not yet possible. Disable feature bit 51.')
        elif self.server.hap.encrypted:
            hexdump(self.server.hap.accessory_shared_key) if DEBUG else ''
            self.upgrade_to_encrypted(self.server.hap.accessory_shared_key)

    def handle_pair_add(self):
        self.handle_pair_ARL('add')

    def handle_pair_remove(self):
        self.handle_pair_ARL('remove')

    def handle_pair_list(self):
        self.handle_pair_ARL('list')

    def handle_pair_ARL(self, op):
        SCR_LOG.info(f"pair-{op} {self.path}")
        SCR_LOG.debug(self.headers)
        content_len = int(self.headers["Content-Length"])
        if content_len > 0:
            body = self.rfile.read(content_len)
            if op == 'add':
                res = self.server.hap.pair_add(body)
            elif op == 'remove':
                res = self.server.hap.pair_remove(body)
            elif op == 'list':
                res = self.server.hap.pair_list(body)
            hexdump(res) if DEBUG else ''
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
        SCR_LOG.info(f"configure {self.path}")
        SCR_LOG.debug(self.headers)
        content_len = int(self.headers["Content-Length"])
        if content_len > 0:
            body = self.rfile.read(content_len)
            plist = readPlistFromString(body)
            SCR_LOG.info(self.pp.pformat(plist))
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
        SCR_LOG.info(self.pp.pformat(configure_info))

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
                    SCR_LOG.info(self.pp.pformat(plist))
                    if "qualifier" in plist and "txtAirPlay" in plist["qualifier"]:
                        SCR_LOG.info('Sending our device info')
                        SCR_LOG.debug(self.pp.pformat(device_info))
                        res = writePlistToString(device_info)

                        self.send_response(200)
                        self.send_header("Content-Length", len(res))
                        self.send_header("Content-Type", HTTP_CT_BPLIST)
                        self.send_header("Server", self.version_string())
                        self.send_header("CSeq", self.headers["CSeq"])
                        self.end_headers()
                        self.wfile.write(res)
                    else:
                        SCR_LOG.error("No txtAirPlay")
                        self.send_error(404)
                        return
                else:
                    SCR_LOG.error("No content")
                    self.send_error(404)
                    return
            else:
                SCR_LOG.error(f"Content-Type: {self.headers['Content-Type']} | Not implemented")
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
        SCR_LOG.debug("----- ENCRYPTED CHANNEL -----")


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
        f"{receiver_name}._airplay._tcp.local.",
        # addresses=[socket.inet_aton("127.0.0.1")],
        addresses=addresses,
        port=7000,
        properties=mdns_props,
        server=f"{receiver_name}.local.",
    )

    zeroconf = Zeroconf(ip_version=IPVersion.V4Only)
    zeroconf.register_service(info)
    SCR_LOG.info("mDNS service registered")
    return (zeroconf, info)


def unregister_mdns(zeroconf, info):
    SCR_LOG.info("Unregistering...")
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
    timeout = 60  # seconds

    def __init__(self, addr_port, handler):
        super().__init__(addr_port, handler)
        self.connections = {}
        self.hap = None
        self.enc_layer = False
        self.streams = []

    # Override
    def get_request(self):
        # Quick clean-up in case anything from before is still around.
        self.hap = None
        client_socket, client_addr = super().get_request()
        SCR_LOG.info(f"Opened connection from {client_addr[0]}:{client_addr[1]}")
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
    parser.add_argument("--debug", help="Prints extra debug message e.g. HTTP headers.", action='store_true')

    args = parser.parse_args()

    DEBUG = args.debug
    if DEBUG:
        SCR_LOG = get_screen_logger('Receiver', level='DEBUG')
    else:
        SCR_LOG = get_screen_logger('Receiver', level='INFO')

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
            SCR_LOG.info(f"Features:")
            SCR_LOG.info(Feat(FEATURES))
        except Exception:
            SCR_LOG.error("[!] Error with feature arg - hex format required")
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
                SCR_LOG.info(f'Chosen features: {flags:016x}')
                SCR_LOG.info(Feat(flags))
            except Exception:
                SCR_LOG.info("[!] Incorrect flags/mask.")
                SCR_LOG.info(f"[!] Proceeding with defaults.")
    SCR_LOG.info(f'Enabled features: {FEATURES:016x}')
    SCR_LOG.info(FEATURES)

    DEVICE_ID = None
    IPV4 = None
    IPV6 = None
    if ifen.get(ni.AF_LINK):
        DEVICE_ID = ifen[ni.AF_LINK][0]["addr"]
    if ifen.get(ni.AF_INET):
        IPV4 = ifen[ni.AF_INET][0]["addr"]
    if ifen.get(ni.AF_INET6):
        IPV6 = ifen[ni.AF_INET6][0]["addr"].split("%")[0]

    setup_global_structs(args, isDebug=DEBUG)

    # Rudimentary check for whether v4/6 are still None (no IP found)
    if IPV4 is None and IPV6 is None:
        SCR_LOG.fatal("[!] No IP found on chosen interface.")
        list_network_interfaces()
        exit(-1)

    SCR_LOG.info(f"Interface: {IFEN}")
    SCR_LOG.info(f"Mac: {DEVICE_ID}")
    SCR_LOG.info(f"IPv4: {IPV4}")
    SCR_LOG.info(f"IPv6: {IPV6}")
    SCR_LOG.info("")

    mdns = register_mdns(args.mdns)
    SCR_LOG.info("Starting RTSP server, press Ctrl-C to exit...")
    try:
        PORT = 7000
        if IPV6 and not IPV4:
            with AP2Server((IPV6, PORT), AP2Handler) as httpd:
                SCR_LOG.info(f"serving at port {PORT}")
                httpd.serve_forever()
        else:  # i.e. (IPV4 and not IPV6) or (IPV6 and IPV4)
            with AP2Server((IPV4, PORT), AP2Handler) as httpd:
                SCR_LOG.info(F"serving at port {PORT}")
                httpd.serve_forever()

    except KeyboardInterrupt:
        pass
    except ConnectionResetError:
        # Weird client termination at the other end.
        pass
    finally:
        SCR_LOG.info("Shutting down mDNS...")
        unregister_mdns(*mdns)
