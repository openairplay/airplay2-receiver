import multiprocessing

from .control import Control
from .audio import AudioRealtime, AudioBuffered


class Stream:

    # TIMING_REQUEST = 82
    # TIMING_REPLY = 83
    # TIME_SYNC = 84
    # RETRANSMIT_REQUEST = 85
    # RETRANSMIT_REPLY = 86
    REALTIME = 96
    BUFFERED = 103

    def __init__(self, stream, buff, isDebug=False):
        # self.audioMode = stream["audioMode"] # default|moviePlayback
        self.isDebug = isDebug
        self.audio_format = stream["audioFormat"]
        self.compression = stream["ct"]
        self.session_key = stream["shk"] if "shk" in stream else b"\x00" * 32
        self.frames_packet = stream["spf"]
        self.type = stream["type"]

        buff = buff // self.frames_packet
        self.control_port, self.control_proc = Control.spawn(self.isDebug)
        if self.type == Stream.REALTIME:
            self.session_iv = stream["shiv"] if "shiv" in stream else None
            self.server_control = stream["controlPort"]
            self.latency_min = stream["latencyMin"]
            self.latency_max = stream["latencyMax"]
            self.data_port, self.data_proc, self.audio_connection = AudioRealtime.spawn(
                self.session_key, self.audio_format, buff, self.session_iv, isDebug=self.isDebug)
        elif self.type == Stream.BUFFERED:
            self.data_port, self.data_proc, self.audio_connection = AudioBuffered.spawn(
                self.session_key, self.audio_format, buff, iv=None, isDebug=self.isDebug)

    def teardown(self):
        self.data_proc.terminate()
        self.data_proc.join()
        self.control_proc.terminate()
        self.control_proc.join()
        self.audio_connection.close()
