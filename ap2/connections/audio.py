import socket
import struct
import multiprocessing

import pyaudio
from Crypto.Cipher import ChaCha20_Poly1305

from ..alac.alac import AlacDecoder
from ..utils import get_logger, get_free_port

class RTP:

    def __init__(self, data):
        self.version = (data[0] & 0b11000000) >> 6
        self.padding = (data[0] & 0b00100000) >> 5
        self.extension = (data[0] & 0b00010000) >> 4
        self.csrc_count = data[0] & 0b00001111
        self.marker = (data[1] & 0b10000000) >> 7
        self.payload_type = data[1] & 0b01111111
        self.sequence_no = struct.unpack(">H", data[2:4])[0]
        self.timestamp = struct.unpack(">I", data[4:8])[0]
        self.ssrc = struct.unpack(">I", data[8:12])[0]

        self.nonce = data[-8:]
        self.tag = data[-24:-8]
        self.aad = data[4:12]
        self.payload = data[12:-24]

class Audio:

    def __init__(self, session_key):
        self.port = get_free_port()
        self.session_key = session_key

    def decrypt(self, rtp):
        c = ChaCha20_Poly1305.new(key=self.session_key, nonce=rtp.nonce)
        c.update(rtp.aad)
        data = c.decrypt_and_verify(rtp.payload, rtp.tag)
        return data

    def handle(self, rtp):
        self.logger.debug("v=%d p=%d x=%d cc=%d m=%d pt=%d seq=%d ts=%d ssrc=%d" % (rtp.version, rtp.padding,
             rtp.extension, rtp.csrc_count,
             rtp.marker, rtp.payload_type,
             rtp.sequence_no, rtp.timestamp,
             rtp.ssrc))

    @classmethod
    def spawn(cls, session_key):
        audio = cls(session_key)
        p = multiprocessing.Process(target=audio.serve)
        p.start()
        return audio.port, p

class AudioRealtime(Audio):

    def init_audio_sink(self):
        self.decoder = AlacDecoder()
        self.decoder.init()
        self.pa = pyaudio.PyAudio()
        self.sink = self.pa.open(format=self.pa.get_format_from_width(2),
                         channels=2,
                         rate=44100,
                         output=True)

    def fini_audio_sink(self):
        self.sink.close()
        self.pa.terminate()
        self.decoder.terminate()

    def process(self, rtp):
        data = self.decrypt(rtp)
        err, decoded = self.decoder.decode_frame(data)
        return decoded

    def serve(self):
        self.logger = get_logger("audio", level="DEBUG")
        self.init_audio_sink()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        addr = ("0.0.0.0", self.port)
        sock.bind(addr)

        try:
            while True:
                data, address = sock.recvfrom(4096)
                if data:
                    rtp = RTP(data)
                    self.handle(rtp)
                    audio = self.process(rtp)
                    self.sink.write(audio)
        except KeyboardInterrupt:
            pass
        finally:
            sock.close()
            self.fini_audio_sink()

class AudioBuffered(Audio):

    def serve(self):
        self.logger = get_logger("audio", level="DEBUG")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        addr = ("0.0.0.0", self.port)
        sock.bind(addr)
        sock.listen(1)

        conn, addr = sock.accept()
        try:
            while True:
                data_len = struct.unpack(">H", conn.recv(2, socket.MSG_WAITALL))[0]
                data = conn.recv(data_len-2, socket.MSG_WAITALL)
                rtp = RTP(data)
                self.handle(rtp)
        except KeyboardInterrupt:
            pass
        finally:
            conn.close()
            sock.close()

