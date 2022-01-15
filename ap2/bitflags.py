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
    | FeatureFlags.Ft47PeerManagement
    | FeatureFlags.Ft46HomeKitPairing
    | FeatureFlags.Ft41_PTPClock
    | FeatureFlags.Ft40BufferedAudio
    | FeatureFlags.Ft38ControlChannelEncrypt
    | FeatureFlags.Ft30UnifiedAdvertisingInfo
    | FeatureFlags.Ft22AudioUnencrypted
    | FeatureFlags.Ft20ReceiveAudioAAC_LC
    | FeatureFlags.Ft19ReceiveAudioALAC
    | FeatureFlags.Ft18ReceiveAudioPCM
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
    Ft00Video = 1 << 0
    Ft01Photo = 1 << 1
    Ft02VideoFairPlay = 1 << 2
    Ft03VideoVolumeCtrl = 1 << 3
    Ft04VideoHTTPLiveStreaming = 1 << 4
    Ft05Slideshow = 1 << 5
    Ft06_Unknown = 1 << 6
    # 07: seems to need NTP
    Ft07ScreenMirroring = 1 << 7
    Ft08ScreenRotate = 1 << 8
    # Ft09 is necessary for iPhones/Music: audio
    Ft09AirPlayAudio = 1 << 9
    Ft10Unknown = 1 << 10
    Ft11AudioRedundant = 1 << 11
    # Feat12: iTunes4Win ends ANNOUNCE with rsaaeskey, does not attempt FPLY auth.
    # also coerces frequent OPTIONS packets (keepalive) from iPhones.
    Ft12FPSAPv2p5_AES_GCM = 1 << 12
    # 13-14 MFi stuff.
    Ft13MFiHardware = 1 << 13
    # Music on iPhones needs this to stream audio
    Ft14MFiSoft_FairPlay = 1 << 14
    # 15-17 not mandatory - faster pairing without
    Ft15AudioMetaCovers = 1 << 15
    Ft16AudioMetaProgress = 1 << 16
    Ft17AudioMetaTxtDAAP = 1 << 17
    # macOS needs 18 to pair
    Ft18ReceiveAudioPCM = 1 << 18
    # macOS needs 19
    Ft19ReceiveAudioALAC = 1 << 19
    # iOS needs 20
    Ft20ReceiveAudioAAC_LC = 1 << 20
    Ft21Unknown = 1 << 21
    # Try Ft22 without Ft40 - ANNOUNCE + SDP
    Ft22AudioUnencrypted = 1 << 22
    Ft23RSA_Auth = 1 << 23
    Ft24Unknown = 1 << 24
    # Pairing stalls with longer /auth-setup string w/26
    # Ft25 seems to require ANNOUNCE
    Ft25iTunes4WEncryption = 1 << 25
    # try Ft26 without Ft40. Ft26 = crypt audio? mutex w/Ft22?
    Ft26Audio_AES_Mfi = 1 << 26
    # 27: connects and works OK
    Ft27LegacyPairing = 1 << 27
    Ft28_Unknown = 1 << 28
    Ft29plistMetaData = 1 << 29
    Ft30UnifiedAdvertisingInfo = 1 << 30
    # Bit 31 Reserved     =  # 1 << 31
    Ft32CarPlay = 1 << 32
    Ft33AirPlayVideoPlayQueue = 1 << 33
    Ft34AirPlayFromCloud = 1 << 34
    Ft35TLS_PSK = 1 << 35
    Ft36_Unknown = 1 << 36
    Ft37CarPlayControl = 1 << 37
    # 38 seems to be implicit with other flags; works with or without 38.
    Ft38ControlChannelEncrypt = 1 << 38
    Ft39_Unknown = 1 << 39
    # 40 absence: requires ANNOUNCE method
    Ft40BufferedAudio = 1 << 40
    Ft41_PTPClock = 1 << 41
    Ft42ScreenMultiCodec = 1 << 42
    # 43
    Ft43SystemPairing = 1 << 43
    Ft44APValeriaScreenSend = 1 << 44
    # 45: macOS wont connect, iOS will, but dies on play.
    # 45 || 41; seem mutually exclusive.
    # 45 triggers stream type:96 (without ft41, PTP)
    Ft45_NTPClock = 1 << 45
    Ft46HomeKitPairing = 1 << 46
    # 47: For PTP
    Ft47PeerManagement = 1 << 47
    Ft48TransientPairing = 1 << 48
    Ft49AirPlayVideoV2 = 1 << 49
    Ft50NowPlayingInfo = 1 << 50
    Ft51MfiPairSetup = 1 << 51
    Ft52PeersExtendedMessage = 1 << 52
    Ft53_Unknown = 1 << 53
    Ft54SupportsAPSync = 1 << 54
    Ft55SupportsWoL = 1 << 55
    Ft56SupportsWoL = 1 << 56
    Ft57_Unknown = 1 << 57
    Ft58HangdogRemote = 1 << 58
    Ft59AudioStreamConnectionSetup = 1 << 59
    Ft60AudioMediaDataControl = 1 << 60
    Ft61RFC2198Redundant = 1 << 61
    Ft62_Unknown = 1 << 62
    """
    Ft51 - macOS sits for a while. Perhaps trying a closed connection port or medium?;
     iOS just fails at Pair-Setup [2/5]
    """
    def GetDefaultAirplayTwoFlags(self):
        return (
            self.Ft48TransientPairing | self.Ft47PeerManagement | self.Ft46HomeKitPairing
            | self.Ft41_PTPClock
            | self.Ft40BufferedAudio
            | self.Ft30UnifiedAdvertisingInfo
            | self.Ft22AudioUnencrypted
            | self.Ft20ReceiveAudioAAC_LC | self.Ft19ReceiveAudioALAC | self.Ft18ReceiveAudioPCM
            | self.Ft17AudioMetaTxtDAAP
            | self.Ft16AudioMetaProgress
            # | self.Ft15AudioMetaCovers
            | self.Ft14MFiSoft_FairPlay | self.Ft09AirPlayAudio
        )

    # Generic names to simplify usage (don't need to track changes in receiver)
    def getFeature12(self):
        return self.Ft12FPSAPv2p5_AES_GCM

    def getFeature19ALAC(self):
        return self.Ft19ReceiveAudioALAC

    def getFeature20AAC(self):
        return self.Ft20ReceiveAudioAAC_LC


class StatusFlags(IntFlag):
    StatusNone = 0
    ProblemsExist = 1 << 0
    # Probably a WAC (wireless accessory ctrl) thing:
    Not_yet_configured = 1 << 1
    # Audio cable attached (legacy): all is well.
    AudioLink = 1 << 2
    PINmode = 1 << 3
    PINentry = 1 << 4
    PINmatch = 1 << 5
    SupportsAirPlayFromCloud = 1 << 6
    # Need password to use
    PasswordNeeded = 1 << 7
    StatusUnknown_08 = 1 << 8
    # need PIN to pair - client will request PIN based auth
    PairingPIN_aka_OTP = 1 << 9
    # Note: prevents adding to HomeKit when set.
    Enable_HK_Access_Control = 1 << 10
    # Shows in logs as relayable. iOS connects to get currently playing track
    RemoteControlRelay = 1 << 11
    SilentPrimary = 1 << 12
    TightSyncIsGroupLeader = 1 << 13
    TightSyncBuddyNotReachable = 1 << 14
    IsAppleMusicSubscriber = 1 << 15
    iCloudLibraryIsOn = 1 << 16
    ReceiverSessionIsActive = 1 << 17
    StatusUnknown_18 = 1 << 18
    StatusUnknown_19 = 1 << 19
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

    def getRecvSessActive(self):
        return (
            self.ReceiverSessionIsActive
        )
