import random


from .control import Control
from .audio import AudioRealtime, AudioBuffered
from .stream_connection import StreamConnection
from ap2.utils import get_free_socket


class Stream:

    REALTIME = 96
    BUFFERED = 103

    def __init__(self, stream, addr, port=0, buff_size=0, stream_id=None, shared_key=None, isDebug=False, aud_params=None):
        # self.audioMode = stream["audioMode"] # default|moviePlayback
        self.isDebug = isDebug
        self.addr = addr
        self.port = port
        self.audio_connection = None
        self.control_conns = None
        self.initialized = False

        self.data_socket = None
        self.data_proc = None

        self.control_socket = get_free_socket(self.addr)
        self.control_proc = None

        self.shared_key = shared_key
        self.culled = False
        """stat fields at teardown
        ccCountAPSender
        ccCountNonAPSender
        ccCountSender
        """

        """ Senders handle a stream with an ID up to 32 bits long.
        You get overflowed values back if you try with 64 bits. The sender
        gives us streamID for teardown. Receiver provides the sender with a
        list of active streams at every POST /feedback. Possibly also POST /info.
        A monotonically increasing counter precludes collisions/repeats,
        although having a random # as plan B is OK.
        """
        if stream_id:
            self.streamID = stream_id
        else:
            self.streamID = random.getrandbits(32)

        # type should always be present
        self.streamtype = stream["type"]
        # A uint64:
        self.streamConnectionID = stream["streamConnectionID"] if "streamConnectionID" in stream else None
        # A boolean:
        self.supportsDynamicStreamID = stream["supportsDynamicStreamID"] if "supportsDynamicStreamID" in stream else None

        if self.streamtype == Stream.REALTIME:
            self.data_socket = get_free_socket(self.addr)
        elif self.streamtype == Stream.BUFFERED:
            self.data_socket = get_free_socket(self.addr, tcp=True)

        self.has_scs = False
        if 'streamConnections' in stream:
            self.has_scs = True
            self.streamConnections = StreamConnection(
                stream,
                # selfaddr=self.addr,
                # selfmac=self.mac,
                rtcpP=self.getControlPort(),
                rtpP=self.getDataPort(),
                # mdcP=self.getMRCPort(),
                isDebug=self.isDebug,
            )

        if self.streamtype == Stream.REALTIME or self.streamtype == Stream.BUFFERED:
            self.control_proc, self.control_conns = Control.spawn(
                controladdr_ours=self.control_socket,
                dataaddr_ours=self.data_socket,
                isDebug=self.isDebug,
            )
            self.audio_format = stream["audioFormat"]
            """ ct: 0x1 = PCM, 0x2 = ALAC, 0x4 = AAC_LC, 0x8 = AAC_ELD. largely implied by audioFormat """
            self.compression = stream["ct"]
            self.session_key = stream["shk"] if "shk" in stream else b"\x00" * 32
            self.spf = stream["spf"]
            self.buff_size = buff_size

        if self.streamtype == Stream.REALTIME:
            self.session_iv = stream["shiv"] if "shiv" in stream else None
            self.server_control = stream["controlPort"] if "controlPort" in stream else None
            """ Run receiver with bit 13/14 and no bit 25, it's RSA in ANNOUNCE. Sender assumes you are an
            airport with only 250msec buffer, so min/max are absent from SDP. Support FP2? """
            self.latency_min = stream["latencyMin"]
            self.latency_max = stream["latencyMax"]
            """ Define a small buffer size - enough to keep playback stable
            (11025//352) ≈ 0.25 seconds. Not 'realtime', but prevents jitter well.
            """
            buffer = ((self.latency_min * 7) // self.spf) + 1
            self.data_proc, self.audio_connection = AudioRealtime.spawn(
                self.data_socket,
                self.session_key, self.session_iv,
                self.audio_format, buffer,
                self.spf,
                self.streamtype,
                control_conns=self.control_conns,
                isDebug=self.isDebug,
                aud_params=None,
            )
            self.descriptor = {
                'type': self.streamtype,
                'controlPort': self.getControlPort(),
                'dataPort': self.getDataPort(),
                'audioBufferSize': self.buff_size,
                'streamID': self.streamID,
            }
            if self.has_scs:
                self.descriptor['streamConnections'] = self.streamConnections.getSCs()

        elif self.streamtype == Stream.BUFFERED:
            buffer = (buff_size // self.spf) + 1
            iv = None
            self.data_proc, self.audio_connection = AudioBuffered.spawn(
                self.data_socket,
                self.session_key, iv,
                self.audio_format, buffer,
                self.spf,
                self.streamtype,
                control_conns=self.control_conns,
                isDebug=self.isDebug,
                aud_params=None,
            )
            self.descriptor = {
                'type': self.streamtype,
                'controlPort': self.getControlPort(),
                'dataPort': self.getDataPort(),
                # Reply with the passed buff size, not the calculated array size
                'audioBufferSize': self.buff_size,
                'streamID': self.streamID,
            }
            if self.has_scs:
                self.descriptor['streamConnections'] = self.streamConnections.getSCs()

        self.initialized = True

    def isAudio(self):
        return self.streamtype == Stream.BUFFERED or self.streamtype == Stream.REALTIME

    def isInitialized(self):
        return self.initialized

    def getStreamType(self):
        return self.streamtype

    def getStreamID(self):
        return self.streamID

    def getControlPort(self):
        return self.control_socket.getsockname()[1] if self.control_socket else 0

    def getControlProc(self):
        return self.control_proc

    def getDataPort(self):
        return self.data_socket.getsockname()[1] if self.data_socket else 0

    def getDataProc(self):
        return self.data_proc

    def getAudioConnection(self):
        return self.audio_connection

    def getSummaryMessage(self):
        msg = f'[+] type {self.getStreamType()}: '
        if self.getControlPort() != 0:
            msg += f'controlPort={self.getControlPort()} '
        if self.getDataPort() != 0:
            msg += f'dataPort={self.getDataPort()} '
        return msg

    def getDescriptor(self):
        return self.descriptor

    def isCulled(self):
        return self.culled

    def teardown(self):
        self.culled = True

        if self.streamtype == Stream.REALTIME or self.streamtype == Stream.BUFFERED:
            if self.control_proc:
                for conn in self.control_conns:
                    conn.close()
                self.control_proc.terminate()
                self.control_proc.join()
            self.data_proc.terminate()
            self.data_proc.join()
            self.audio_connection.close()
