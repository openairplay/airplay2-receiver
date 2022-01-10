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

# # FEATURES = 0x1c340405fca00 equals the below mask
FEATURES = (
    FeatureFlags.Ft48TransientPairing
    | FeatureFlags.Ft47PeerMgmt
    | FeatureFlags.Ft46HKPairing
    | FeatureFlags.Ft41_PTPClock
    | FeatureFlags.Ft40BufferedAudio
    | FeatureFlags.Ft38CtrlChanEncrypt
    | FeatureFlags.Ft30UnifiedAdvertInf
    | FeatureFlags.Ft22AudioUnencrypted
    | FeatureFlags.Ft20RcvAudAAC_LC
    | FeatureFlags.Ft19RcvAudALAC
    | FeatureFlags.Ft18RcvAudPCM
    | FeatureFlags.Ft17AudioMetaTxtDAAP
    | FeatureFlags.Ft16AudioMetaProgress
    | FeatureFlags.Ft15AudioMetaCovers
    | FeatureFlags.Ft14MFiSoft_FairPlay
    | FeatureFlags.Ft11AudioRedundant
    | FeatureFlags.Ft09AirPlayAudio
)
"""


class FeatureFlags(IntFlag):
    # https://emanuelecozzi.net/docs/airplay2/features/
    # https://openairplay.github.io/airplay-spec/features.html
    # https://nto.github.io/AirPlay.html
    Ft00Video            = 0x0000000000000001  # 1<<0
    Ft01Photo            = 0x0000000000000002  # 1<<1
    Ft02VideoFairPlay    = 0x0000000000000004  # 1<<2
    Ft03VideoVolumeCtrl  = 0x0000000000000008  # 1<<3
    Ft04VideoHTTPLiveStr = 0x0000000000000010  # 1<<4
    Ft05Slideshow        = 0x0000000000000020  # 1<<5
    Ft06_Unknown         = 0x0000000000000040  # 1<<6
    # 07: seems to need NTP
    Ft07ScreenMirroring  = 0x0000000000000080  # 1<<7
    Ft08ScreenRotate     = 0x0000000000000100  # 1<<8
    # Ft09 is necessary for iPhones/Music: audio
    Ft09AirPlayAudio     = 0x0000000000000200  # 1<<9
    Ft10Unknown          = 0x0000000000000400  # 1<<10
    Ft11AudioRedundant   = 0x0000000000000800  # 1<<11
    # Feat12: iTunes4Win ends ANNOUNCE with rsaaeskey, does not attempt FPLY auth.
    # also coerces frequent OPTIONS packets (keepalive) from iPhones.
    Ft12FPSAPv2p5_AES_GCM = 0x0000000000001000  # 1<<12
    # 13-14 MFi stuff.
    Ft13MFiHardware      = 0x0000000000002000  # 1<<13
    # Music on iPhones needs this to stream audio
    Ft14MFiSoft_FairPlay = 0x0000000000004000  # 1<<14
    # 15-17 not mandatory - faster pairing without
    Ft15AudioMetaCovers  = 0x0000000000008000  # 1<<15
    Ft16AudioMetaProgress = 0x0000000000010000  # 1<<16
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
    def GetDefaultAirplayTwoFlags(self):
        return (
            self.Ft48TransientPairing | self.Ft47PeerMgmt | self.Ft46HKPairing
            | self.Ft41_PTPClock
            | self.Ft40BufferedAudio
            | self.Ft30UnifiedAdvertInf
            | self.Ft22AudioUnencrypted
            | self.Ft20RcvAudAAC_LC | self.Ft19RcvAudALAC | self.Ft18RcvAudPCM
            | self.Ft17AudioMetaTxtDAAP
            | self.Ft16AudioMetaProgress
            # | self.Ft15AudioMetaCovers
            | self.Ft14MFiSoft_FairPlay | self.Ft09AirPlayAudio
        )

    # Generic names to simplify usage (don't need to track changes in receiver)
    def getFeature12(self):
        return self.Ft12FPSAPv2p5_AES_GCM

    def getFeature19ALAC(self):
        return self.Ft19RcvAudALAC

    def getFeature20AAC(self):
        return self.Ft20RcvAudAAC_LC


class StatusFlags(IntFlag):
    StatusNone                     = 0x000000  # 0
    ProblemsExist                  = 0x000001  # 1<< 0
    # Probably a WAC (wireless accessory ctrl) thing:
    Not_yet_configured             = 0x000002  # 1<< 1
    # Audio cable attached (legacy): all is well.
    AudioLink                      = 0x000004  # 1<< 2
    PINmode                        = 0x000008  # 1<< 3
    PINentry                       = 0x000010  # 1<< 4
    PINmatch                       = 0x000020  # 1<< 5
    SupportsAirPlayFromCloud       = 0x000040  # 1<< 6
    # Need password to use
    PasswordNeeded                 = 0x000080  # 1<< 7
    StatusUnknown_08               = 0x000100  # 1<< 8
    # need PIN to pair
    PairingPIN_aka_OTP             = 0x000200  # 1<< 9
    # Note: prevents adding to HomeKit when set.
    Enable_HK_Access_Control       = 0x000400  # 1<<10
    # Shows in logs as relayable. iOS connects to get currently playing track
    RemoteControlRelay             = 0x000800  # 1<<11
    SilentPrimary                  = 0x001000  # 1<<12
    TightSyncIsGroupLeader         = 0x002000  # 1<<13
    TightSyncBuddyNotReachable     = 0x004000  # 1<<14
    IsAppleMusicSubscriber         = 0x008000  # 1<<15
    iCloudLibraryIsOn              = 0x010000  # 1<<16
    ReceiverSessionIsActive        = 0x020000  # 1<<17
    StatusUnknown_18               = 0x040000  # 1<<18
    StatusUnknown_19               = 0x080000  # 1<<19
    """
    possibly others
    """
    def GetDefaultStatusFlags(self):
        return (
            self.AudioLink
            # we must handle stream type 130 for RCR
            # | self.RemoteControlRelay
        )

    def getHKACFlag(self):
        return (
            self.Enable_HK_Access_Control
        )

    def getPWSetFlag(self):
        return (
            self.PasswordNeeded
            | self.PairingPIN_aka_OTP
        )
