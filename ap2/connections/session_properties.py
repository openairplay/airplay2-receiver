from ap2.playfair import PlayFair, FairPlayAES


class Session():
    """ place to hold session information """

    def __init__(self, info=None, keymsg=None):

        self.isMultiSelectAirPlay = info['isMultiSelectAirPlay'] if 'isMultiSelectAirPlay' in info else False
        self.groupContainsGroupLeader = info['groupContainsGroupLeader'] if 'groupContainsGroupLeader' in info else False
        self.groupUUID = info['groupUUID'] if 'groupUUID' in info else None
        # HijackID
        self.HTGroupUUID = info['HTGroupUUID'] if 'HTGroupUUID' in info else None
        self.isTightSyncGroupLeader = info['isTightSyncGroupLeader'] if 'IsTightSyncGroupLeader' in info else False
        # isGroupPlayback
        # persistentGroupSize
        self.sessionUUID = info['sessionUUID'] if 'sessionUUID' in info else None
        self.tightSyncUUID = info['tightSyncUUID'] if 'tightSyncUUID' in info else None

        if 'eiv' in info and 'ekey' in info:
            self.aesiv = info['eiv']
            self.aeskey = info['ekey']
            self.aeskeyobj = FairPlayAES(fpaeskey=self.aeskey, aesiv=self.aesiv, keymsg=keymsg)

        if 'timingPeerInfo' in info:
            """ consists of:
            Addresses: [{IPv4, IPv6, ...}],
            ClockID: uint64,
            ClockPorts: {'guid': port},
            DeviceType: int,
            ID: 'guid',
            SupportsClockPortMatchingOverride: bool,
            """
            timingPeerInfo = info['timingPeerInfo']
        if 'timingPeerList' in info:
            """ Array of:
            [timingPeerInfo, timingPeerInfo, ...]
            """
            self.timingPeerList = []
            for tp in info['timingPeerList']:
                self.timingPeerList.append(TimingPeer(tp))

    # Timing stuff
    def getTimingPeerList(self):
        if len(self.timingPeerList) > 0:
            return self.timingPeerList

    def getSessionUUID(self):
        return self.sessionUUID

    def getGroupUUID(self):
        return self.groupUUID

    def groupContainsGroupLeader(self):
        return self.groupContainsGroupLeader

    def isMultiSelectAirPlay(self):
        return self.isMultiSelectAirPlay

    # Key stuff
    def getAESKey(self):
        return self.aeskeyobj.getAESKey()

    def getAESIV(self):
        return self.aeskeyobj.getAESIV()


class TimingPeer():
    """
    SETPEERSX sends these.
    Sender also includes these at connect time.
    """
    def __init__(self, timingPeer):
        if 'Addresses' in timingPeer:
            self.Addresses = timingPeer['Addresses']
        if 'ClockID' in timingPeer:
            self.ClockID = timingPeer['ClockID']
        if 'ClockPorts' in timingPeer:
            self.ClockPorts = timingPeer['ClockPorts']
        if 'DeviceType' in timingPeer:
            self.DeviceType = timingPeer['DeviceType']
        if 'ID' in timingPeer:
            self.ID = timingPeer['ID']
        if 'SupportsClockPortMatchingOverride' in timingPeer:
            self.SupportsClockPortMatchingOverride = timingPeer['SupportsClockPortMatchingOverride']

    def getAddresses(self):
        return self.Addresses

    def getClockID(self):
        return self.ClockID

    def getClockPorts(self):
        return self.ClockPorts

    def getDeviceType(self):
        return self.DeviceType

    def getID(self):
        return self.ID

    def SupportsClockPortMatchingOverride(self):
        return self.SupportsClockPortMatchingOverride
