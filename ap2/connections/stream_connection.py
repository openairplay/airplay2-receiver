

class StreamConnection:
    """ don't know much about what these are but enable bit 59,
    devices start to send these in the initial plist:
    ...
    'streamConnections': {'streamConnectionTypeRTP': {'streamConnectionKeyUseStreamEncryptionKey': True}},
    ...
    Needs active behaviour on the receiver to set up RTP beyond simply listening.
    pcaps show that no RTP is sent if we do nothing. These also arrive for audio only.
    """

    def __init__(
        self,
        streamConnections,
        isDebug=False,
    ):
        self.isDebug = isDebug
        self.streamConnections = []
        self.streamConnectionTypeRTP = []
        for sct in streamConnections:
            if 'streamConnectionTypeRTP' in sct:
                for sc in streamConnections['streamConnectionTypeRTP']:
                    self.streamConnectionTypeRTP.append(sc)
