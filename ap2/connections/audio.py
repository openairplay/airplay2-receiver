import socket
import struct
import multiprocessing
import enum

import av
import pyaudio
from Crypto.Cipher import ChaCha20_Poly1305
from av.audio.format import AudioFormat

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
    class AudioFormat(enum.Enum):
        PCM_8000_16_1 = 1 << 2
        PCM_8000_16_2 = 1 << 3
        PCM_16000_16_1 = 1 << 4
        PCM_16000_16_2 = 1 << 5
        PCM_24000_16_1 = 1 << 6
        PCM_24000_16_2 = 1 << 7
        PCM_32000_16_1 = 1 << 8
        PCM_32000_16_2 = 1 << 9
        PCM_44100_16_1 = 1 << 10
        PCM_44100_16_2 = 1 << 11
        PCM_44100_24_1 = 1 << 12
        PCM_44100_24_2 = 1 << 13
        PCM_48000_16_1 = 1 << 14
        PCM_48000_16_2 = 1 << 15
        PCM_48000_24_1 = 1 << 16
        PCM_48000_24_2 = 1 << 17
        ALAC_44100_16_2 = 1 << 18
        ALAC_44100_24_2 = 1 << 19
        ALAC_48000_16_2 = 1 << 20
        ALAC_48000_24_2 = 1 << 21
        AAC_LC_44100_2 = 1 << 22
        AAC_LC_48000_2 = 1 << 23
        AAC_ELD_44100_2 = 1 << 24
        AAC_ELD_48000_2 = 1 << 25
        AAC_ELD_16000_1 = 1 << 26
        AAC_ELD_24000_1 = 1 << 27
        OPUS_16000_1 = 1 << 28
        OPUS_24000_1 = 1 << 29
        OPUS_48000_1 = 1 << 30
        AAC_ELD_44100_1 = 1 << 31
        AAC_ELD_48000_1 = 1 << 32

    def __init__(self, session_key, audio_format):
        if audio_format != Audio.AudioFormat.ALAC_44100_16_2.value \
                and audio_format != Audio.AudioFormat.AAC_LC_44100_2.value:
            raise Exception("Unsupported format: %s", Audio.AudioFormat(audio_format)).name
        self.audio_format = audio_format
        self.port = get_free_port()
        self.session_key = session_key

    def init_audio_sink(self):
        self.pa = pyaudio.PyAudio()
        self.sink = self.pa.open(format=self.pa.get_format_from_width(2),
                                 channels=2,
                                 rate=44100,
                                 output=True)
        codec = None
        extradata = None
        if self.audio_format == Audio.AudioFormat.ALAC_44100_16_2.value:
            extradata = bytes([
                # Offset 0x00000000 to 0x00000035
                0x00, 0x00, 0x00, 0x24, 0x61, 0x6c, 0x61, 0x63, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x01, 0x60, 0x00, 0x10, 0x28, 0x0a, 0x0e, 0x02, 0x00, 0xff,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xac, 0x44
            ])
            codec = av.codec.Codec('alac', 'r')
        elif self.audio_format == Audio.AudioFormat.AAC_LC_44100_2.value:
            codec = av.codec.Codec('aac', 'r')

        if codec is not None:
            self.codecContext = av.codec.CodecContext.create(codec)
            self.codecContext.sample_rate = 44100
            self.codecContext.channels = 2
            self.codecContext.format = AudioFormat('s16p')
        if extradata is not None:
            self.codecContext.extradata = extradata

        self.resampler = av.AudioResampler(
            format=av.AudioFormat('s16').packed,
            layout='stereo',
            rate=44100,
        )

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

    def process(self, rtp):
        data = self.decrypt(rtp)
        packet = av.packet.Packet(data)
        for frame in self.codecContext.decode(packet):
            frame = self.resampler.resample(frame)
            return frame.planes[0].to_bytes()

    @classmethod
    def spawn(cls, session_key, audio_format):
        audio = cls(session_key, audio_format)
        p = multiprocessing.Process(target=audio.serve)
        p.start()
        return audio.port, p

class AudioRealtime(Audio):

    def fini_audio_sink(self):
        self.sink.close()
        self.pa.terminate()

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
        self.init_audio_sink()
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
                audio = self.process(rtp)
                self.sink.write(audio)
        except KeyboardInterrupt:
            pass
        finally:
            conn.close()
            sock.close()
