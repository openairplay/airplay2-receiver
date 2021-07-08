import multiprocessing

from .control import Control
from .audio import AudioRealtime, AudioBuffered

class Stream:

    REALTIME = 96
    BUFFERED = 103

    def __init__(self, stream, audio_device, use_portaudio):
        self.audio_format = stream["audioFormat"]
        self.compression = stream["ct"]
        self.session_key = stream["shk"]
        self.frames_packet = stream["spf"]
        self.type = stream["type"]

        self.control_port, self.control_proc = Control.spawn()
        if self.type == Stream.REALTIME:
            self.server_control = stream["controlPort"]
            self.latency_min = stream["latencyMin"]
            self.latency_max = stream["latencyMax"]
            self.data_port, self.data_proc, audio_connection = AudioRealtime.spawn(self.session_key, self.audio_format, audio_device, use_portaudio)
        elif self.type == Stream.BUFFERED:
            self.data_port, self.data_proc, self.audio_connection = AudioBuffered.spawn(self.session_key, self.audio_format, audio_device, use_portaudio)

    def teardown(self):
        self.data_proc.terminate()
        self.data_proc.join()
        self.control_proc.terminate()
        self.control_proc.join()
