

class StreamConnection:
    """ Enable bit 59, and reply with a 'streamConnectionKeyPort': int to send
    a listen port for a particular type. Not yet sure what the advantages of
    streamConnections are, tho once a streamConnection is up, everything is sent
    over it when e.g. macOS has a connection. iOS still makes a new one for each
    new track in buffered mode. Who knows, this might be the future.
    AFAICT, I'm the first to publicly figure streamConnections out, so not sure
    what the problem is that it intends to solve.
    Devices send these in the initial plist:
    ...
    'streamConnectionID': uint64,
    'streamConnections': {'streamConnectionTypeRTCP': {'streamConnectionKeyPort': int},
                          'streamConnectionTypeRTP': {'streamConnectionKeyUseStreamEncryptionKey': bool}},
    'supportsDynamicStreamID': bool,
    ...
    These also arrive for audio only. Assume also for v+a, and v+a+rc.
    """

    def __init__(
        self,
        streamCs,
        selfaddr=None,
        selfmac=None,
        rtpP=None,
        rtcpP=None,
        mdcP=None,
        isDebug=False,
    ):
        self.isDebug = isDebug
        # self.streamConnections = []
        scs = 'streamConnections'
        # self.streamConnectionTypeRTP = []
        sctRTP = 'streamConnectionTypeRTP'
        # self.streamConnectionTypeRTCP = []
        sctRTCP = 'streamConnectionTypeRTCP'
        # self.streamConnectionTypeMediaDataControl = []
        sctMDC = 'streamConnectionTypeMediaDataControl'
        # self.streamConnectionKeyUseStreamEncryptionKey = True
        scKUSEC = 'streamConnectionKeyUseStreamEncryptionKey'
        # self.streamConnectionKeyEncryptionSeed = None
        scKES = 'streamConnectionKeyEncryptionSeed'
        # self.streamConnectionKeyPort = 0
        scKP = 'streamConnectionKeyPort'
        # self.streamConnectionKeyIPAddress = 0
        scKIPA = 'streamConnectionKeyIPAddress'
        # self.streamConnectionKeyMACAddress = 0x0
        scKMACA = 'streamConnectionKeyMACAddress'

        if scs in streamCs:
            for sc in streamCs[scs]:
                if sctRTCP in sc:
                    if rtcpP:
                        streamCs[scs][sctRTCP][scKP] = rtcpP
                    if selfaddr:
                        streamCs[scs][sctRTCP][scKIPA] = selfaddr
                    """
                    if selfmac:
                        streamCs[scs][sctRTCP][scKMACA] = selfmac
                    """
                if sctRTP in sc:
                    if rtpP:
                        streamCs[scs][sctRTP][scKP] = rtpP
                    if selfaddr:
                        streamCs[scs][sctRTP][scKIPA] = selfaddr
                    """
                    if selfmac:
                        streamCs[scs][sctRTP][scKMACA] = selfmac
                    """
                    if scKUSEC in streamCs[scs][sctRTP]:
                        # Does not matter what you set this key to when a Receiver
                        del streamCs[scs][sctRTP][scKUSEC]
                if sctMDC in sc:
                    if mdcP:
                        streamCs[scs][sctMDC][scKP] = mdcP
                    if selfaddr:
                        streamCs[scs][sctMDC][scKIPA] = selfaddr
                    """
                    if selfmac:
                        streamCs[scs][sctMDC][scKMACA] = selfmac
                    """
            self.sCs = streamCs[scs]

    def getSCs(self):
        return self.sCs
