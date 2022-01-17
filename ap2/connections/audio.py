import socket
import string
import multiprocessing
import enum
import threading
import time
import logging

import av
import numpy
import pyaudio
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Cipher import AES
from av.audio.format import AudioFormat
from collections import deque
from operator import attrgetter


from ..utils import get_file_logger, get_screen_logger, get_free_socket


class RTP:
    def __init__(self, data):
        self.version = (data[0] & 0b11000000) >> 6
        self.padding = (data[0] & 0b00100000) >> 5
        self.extension = (data[0] & 0b00010000) >> 4
        self.csrc_count = data[0] & 0b00001111

        self.timestamp = int.from_bytes(data[4:8], byteorder='big')
        self.ssrc = int.from_bytes(data[8:12], byteorder='big')

        self.nonce = data[-8:]
        self.tag = data[-24:-8]
        self.aad = data[4:12]
        self.payload = data[12:-24]


class RTP_REALTIME(RTP):
    def __init__(self, data):
        super(RTP_REALTIME, self).__init__(data)
        self.payload_type = data[1] & 0b01111111
        self.marker = (data[1] & 0b10000000) >> 7
        self.sequence_no = int.from_bytes(data[2:4], byteorder='big')


class RTP_BUFFERED(RTP):
    def __init__(self, data):
        super(RTP_BUFFERED, self).__init__(data)
        self.payload_type = 0
        self.marker = 0
        self.sequence_no = int.from_bytes(b'\0' + data[1:4], byteorder='big')


class RTPRealtimeBuffer:
    """
    It's small, simple, resilient.
    """
    BUFFER_SIZE = 1

    def __init__(self, size, isDebug=False):
        self.BUFFER_SIZE = size
        self.isDebug = isDebug
        self.queue = deque(maxlen=self.BUFFER_SIZE + 1)
        """
        if self.isDebug:
            self.rtp_logger = get_screen_logger('RTPRealtimeBuffer', level='DEBUG')
        else:
            self.rtp_logger = get_screen_logger('RTPRealtimeBuffer', level='INFO')
        """

    def append(self, rtp):
        """ puts rtp into the bottom or left of the queue """
        self.queue.appendleft(rtp)

    def pop(self, seq=None, get_ts=False):
        if seq is None or seq == 0:  # Start-up
            return self.queue.pop()
        else:
            pos = self.find(seq, get_ts)
            if pos == len(self.queue) - 1:  # at end
                return self.queue.pop()
            elif pos == 0:  # at start
                return self.queue.popleft()
            elif pos:  # in midst of queue (jitter)
                r = self.queue[pos]
                self.queue.remove(r)
                return r

    def get_filler(self):
        """ just get top of buffer """
        return self.queue[len(self.queue) - 1]

    def amount(self):
        """ fullness, content """
        return len(self.queue) / self.queue.maxlen

    def is_full(self):
        return len(self.queue) == self.queue.maxlen

    def is_empty(self):
        return len(self.queue) == 0

    def find(self, seq, get_ts=False):
        """ returns queue index of the sought rtp seqNo/timestamp """
        found = False
        lowestFound = 0
        length = len(self.queue)
        attr = 'timestamp' if get_ts else 'sequence_no'
        if length == 0:
            return 0
        for i in range(0, length, 1):
            value = attrgetter(attr)(self.queue[i])
            if value == seq:
                found = True
                return i
        if found is False:
            try:  # seek the next best
                self.find(seq + 1)
            except RecursionError:
                # Find lowest in the buffer
                for i in range(0, length, 1):
                    thisseq = attrgetter(attr)(self.queue[i])
                    if i == 0:
                        lowestFound = thisseq
                    if thisseq < lowestFound:
                        lowestFound = thisseq
                return lowestFound


# Very simple circular buffer implementation
class RTPBuffer:
    # TODO : Centralized for both this buffer size and audioBufferSize returned by SETUP
    BUFFER_SIZE = 1

    def __init__(self, size, isDebug=False):
        self.BUFFER_SIZE = size
        self.isDebug = isDebug
        self.buffer_array = numpy.empty(self.BUFFER_SIZE, dtype=RTP_BUFFERED)
        # Stores indexes only for quick bisect search
        self.buffer_array_seqs = numpy.empty(self.BUFFER_SIZE, dtype=int)

        # read index - where data is ready to be read
        self.read_index = -1
        # write index - where data is ready to be written
        self.write_index = 0
        self.flush_from_sequence = None
        self.flush_to_sequence = None
        if self.isDebug:
            self.rtp_logger = get_screen_logger('RTPBuffer', level='DEBUG')
        else:
            self.rtp_logger = get_screen_logger('RTPBuffer', level='INFO')

    def increment_buffer_index(self, index):
        # increments the index position in the buffer by one
        return (index + 1) % self.BUFFER_SIZE

    def decrement_buffer_index(self, index):
        # decrements the index position in the buffer by one
        return (index + self.BUFFER_SIZE - 1) % self.BUFFER_SIZE

    def add(self, rtp_data):
        if self.write_index % 1e3 == 0:
            msg = f"buffer: writing - full at {self.get_fullness():.1%}"
            msg += f" - ri={self.read_index} - wi={self.write_index}"
            msg += f" - seq={rtp_data.sequence_no}"
            self.rtp_logger.info(msg)

        used_index = self.write_index
        self.buffer_array[self.write_index] = rtp_data
        self.buffer_array_seqs[self.write_index] = rtp_data.sequence_no
        if self.read_index == -1:
            # First write - init read index
            self.read_index = self.write_index
        else:
            if self.increment_buffer_index(self.write_index) == self.read_index:
                # buffer overflow, we "push" the read index
                self.rtp_logger.warning("buffer full: won't overwrite unparsed data")
                self.read_index = self.increment_buffer_index(self.read_index)
        self.write_index = self.increment_buffer_index(self.write_index)

        return used_index

    def get(self):
        return self.buffer_array[self.read_index]

    def can_read(self):
        return self.read_index != -1

    def next(self):
        if self.read_index == -1:
            self.rtp_logger.warning("buffer empty: read impossible")
            return None
        else:
            buffered_object = self.buffer_array[self.read_index]
            if self.read_index % 1e3 == 0:
                msg = f"buffer: reading - full at {self.get_fullness():.1%} - ri={self.read_index}"
                msg += f" - wi={self.write_index} - seq={buffered_object.sequence_no}"
                self.rtp_logger.info(msg)

            if self.increment_buffer_index(self.read_index) == self.write_index:
                # buffer underrun, nothing we can do
                self.rtp_logger.warning("buffer low: demand >= supply")
                self.read_index = -1
            else:
                self.read_index = self.increment_buffer_index(self.read_index)

        return buffered_object

    def get_fullness(self):
        # get distance between read and write in relation to buff size
        return ((self.BUFFER_SIZE + self.write_index - self.read_index)
                % self.BUFFER_SIZE) / self.BUFFER_SIZE

    def get_bounds(self):
        if self.read_index <= self.write_index:
            return self.read_index, self.write_index
        else:
            return self.write_index, self.read_index

    def find_seq(self, seq):
        # do binary search. Bin = O(log n) vs linear O(n)
        # here we iterate max several times
        left = self.read_index
        right = self.write_index

        if left == -1:
            return
        if left == right:
            return

        while left <= right:
            m = (left + right // 2) % self.BUFFER_SIZE
            msg = f'searching left={left}, right={right},'
            msg += f' m={m}, srch={seq}, now_at={self.buffer_array_seqs[m]}'
            self.rtp_logger.debug(msg)
            if self.buffer_array_seqs[m] == seq:
                return m
            if self.buffer_array_seqs[m] < seq:
                left = self.increment_buffer_index(m)
            elif self.buffer_array_seqs[m] > seq:
                left = self.decrement_buffer_index(m)

    # initialize buffer for reading
    def init(self):
        self.read_index = self.write_index

    # Flush - Must be called from writer (server)
    def flush_write(self, index_from):
        if self.write_index > index_from:
            self.write_index = index_from
            return True
        else:
            return False


class AirplayAudFmt(enum.Enum):
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


class AudioSetup:
    def __init__(self, sr, ss, cc, codec_tag, ver=0, spf=352, compat_ver=0,
                 hist_mult=40, init_hist=10, rice_lmt=14, max_run=255, mcfs=0, abr=0):
        x = bytes()  # a 36-byte QuickTime atom passed through as extradata
        x += (36).to_bytes(4, byteorder='big')             # 32 bits  atom size
        x += (codec_tag).encode()                          # 32 bits  tag ('alac')
        x += int(ver).to_bytes(4, byteorder='big')         # 32 bits  tag version (0)
        x += int(spf).to_bytes(4, byteorder='big')         # 32 bits  samples per frame
        x += int(compat_ver).to_bytes(1, byteorder='big')  # 8 bits  compatible version   (0)
        x += int(ss).to_bytes(1, byteorder='big')          # 8 bits  sample size
        x += int(hist_mult).to_bytes(1, byteorder='big')   # 8 bits  history mult         (40)
        x += int(init_hist).to_bytes(1, byteorder='big')   # 8 bits  initial history      (10)
        x += int(rice_lmt).to_bytes(1, byteorder='big')    # 8 bits  rice param limit     (14)
        x += int(cc).to_bytes(1, byteorder='big')          # 8 bits  channels
        x += int(max_run).to_bytes(2, byteorder='big')     # 16 bits  maxRun               (255)
        x += int(mcfs).to_bytes(4, byteorder='big')        # 32 bits  max coded frame size (0 means unknown)
        x += int(abr).to_bytes(4, byteorder='big')         # 32 bits  average bitrate      (0 means unknown)
        x += int(sr).to_bytes(4, byteorder='big')          # 32 bits  samplerate
        self.extradata = x
        self.sr = sr
        self.ss = ss
        self.cc = cc
        self.spf = spf

    def get_extra_data(self):
        return self.extradata


class Audio:
    @staticmethod
    def set_audio_params(self, audio_format):
        # defaults
        self.sample_rate = 44100
        self.sample_size = 16
        self.channel_count = 2
        self.af = af = str(AirplayAudFmt(audio_format))

        if '8000' in af:
            self.sample_rate = 8000
        elif'16000' in af:
            self.sample_rate = 16000
        elif'24000' in af:
            self.sample_rate = 24000
        elif'32000' in af:
            self.sample_rate = 32000
        elif'44100' in af:
            self.sample_rate = 44100
        elif'48000' in af:
            self.sample_rate = 48000
        else:  # default
            self.sample_rate = 44100

        if '_16' in af:
            self.sample_size = 16
        elif'_24' in af:
            self.sample_size = 24
        else:  # default
            self.sample_size = 16

        if af.endswith('_1'):
            self.channel_count = 1
        else:
            self.channel_count = 2

        self.audio_screen_logger.debug(f"Negotiated audio format: {AirplayAudFmt(audio_format)}")

    def __init__(
            self,
            addr,
            session_key, session_iv=None,
            audio_format=None, buff_size=None,
            streamtype=0,
            isDebug=False,
            aud_params: AudioSetup = None,
    ):
        self.isDebug = isDebug
        self.addr = addr
        if self.isDebug:
            self.audio_file_logger = get_file_logger("Audio.debug", level="DEBUG")
            self.audio_screen_logger = get_screen_logger("Audio.Main", level="DEBUG")
        else:
            self.audio_screen_logger = get_screen_logger("Audio.Main", level="INFO")
        self.audio_format = audio_format
        self.audio_params = aud_params
        self.session_key = session_key
        self.session_iv = session_iv
        sk_len = len(session_key)
        self.key_and_iv = True if (sk_len == 16 or sk_len == 24 or sk_len == 32 and session_iv is not None) else False
        self.set_audio_params(self, audio_format)

    def init_audio_sink(self):
        codecLatencySec = 0
        self.pa = pyaudio.PyAudio()
        self.sink = self.pa.open(format=self.pa.get_format_from_width(2),
                                 channels=self.channel_count,
                                 rate=self.sample_rate,
                                 output=True,
                                 # frames_per_buffer=int(self.sample_rate * 1e-3)
                                 )
        # nice Python3 crash if we don't check self.sink is null. Not harmful, but should check.
        if not self.sink:
            exit()
        # codec = None
        ed = None
        if self.audio_format == AirplayAudFmt.ALAC_44100_16_2.value:
            ed = AudioSetup(codec_tag='alac', sr=44100, ss=16, cc=2).get_extra_data()
        elif self.audio_format == AirplayAudFmt.ALAC_44100_24_2.value:
            ed = AudioSetup(codec_tag='alac', sr=44100, ss=24, cc=2).get_extra_data()
        elif self.audio_format == AirplayAudFmt.ALAC_48000_16_2.value:
            ed = AudioSetup(codec_tag='alac', sr=48000, ss=16, cc=2).get_extra_data()
        elif self.audio_format == AirplayAudFmt.ALAC_48000_24_2.value:
            ed = AudioSetup(codec_tag='alac', sr=48000, ss=24, cc=2).get_extra_data()

        if self.audio_params:
            ed = self.audio_params.get_extra_data()

        if 'ALAC' in self.af:
            self.codec = av.codec.Codec('alac', 'r')
        elif'AAC' in self.af:
            self.codec = av.codec.Codec('aac', 'r')
        elif'OPUS' in self.af:
            self.codec = av.codec.Codec('opus', 'r')
        # PCM
        elif'PCM' and '_16_' in self.af:
            self.codec = av.codec.Codec('pcm_s16le_planar', 'r')
        elif'PCM' and '_24_' in self.af:
            self.codec = av.codec.Codec('pcm_s24le', 'r')

        """
        #It seems that these are not required.
        if  'ELD'   in self.af:
            codecLatencySec = (2017 / self.sample_rate)
        elif'AAC_LC'in self.af:
            codecLatencySec = (2624 / self.sample_rate)
        codecLatencySec = 0
        screen_logger.debug(f'codecLatencySec: {codecLatencySec}')
        """

        if self.codec is not None:
            self.codecContext = av.codec.CodecContext.create(self.codec)
            self.codecContext.sample_rate = self.sample_rate
            self.codecContext.channels = self.channel_count
            self.codecContext.format = av.AudioFormat('s' + str(self.sample_size) + 'p')
        if ed is not None:
            self.codecContext.extradata = ed

        self.resampler = av.AudioResampler(
            format=av.AudioFormat('s' + str(self.sample_size)).packed,
            layout='stereo',
            rate=self.sample_rate,
        )

        audioDevicelatency = \
            self.pa.get_default_output_device_info()['defaultLowOutputLatency']
        # defaultLowOutputLatency or defaultHighOutputLatency
        self.audio_screen_logger.debug(f"audioDevicelatency (sec): {audioDevicelatency:0.5f}")
        pyAudioDelay = self.sink.get_output_latency()
        self.audio_screen_logger.debug(f"pyAudioDelay (sec): {pyAudioDelay:0.5f}")
        ptpDelay = 0.002
        self.sample_delay = pyAudioDelay + audioDevicelatency + codecLatencySec + ptpDelay
        self.audio_screen_logger.info(f"Total sample_delay (sec): {self.sample_delay:0.5f}")

    def decrypt(self, rtp):
        data = b''
        if self.key_and_iv:
            try:
                pl_len = len(rtp.payload) + len(rtp.tag) + len(rtp.nonce)
                # Older streaming model has different payload boundary: pkt end.
                payload = memoryview(rtp.payload + rtp.tag + rtp.nonce)
                pl_len_crypted = pl_len & ~0xf
                pl_len_clear = pl_len & 0xf
                if(pl_len_crypted % 16 == 0):
                    # Decrypt using RSA key
                    c  = AES.new(key=self.session_key, mode=AES.MODE_CBC, iv=self.session_iv)
                    # decrypt the encrypted portion:
                    data = c.decrypt(payload[0:pl_len_crypted])
                    # append the unencrypted trailing bytes (fewer than 16)
                    data += payload[pl_len_crypted:pl_len]
                # else:
                #     data = payload[0:pl_len]
            except (KeyError, ValueError) as e:
                self.audio_screen_logger.error(f'RTP AES MODE_CBC decrypt: {repr(e)}')
        else:
            c = ChaCha20_Poly1305.new(key=self.session_key, nonce=rtp.nonce)
            c.update(rtp.aad)  # necessary at least for RTP type 103.
            try:
                data = c.decrypt_and_verify(rtp.payload, rtp.tag)
            except ValueError as e:
                self.audio_screen_logger.error(f'RTP ChaCha20_Poly1305 decrypt: {repr(e)}')
                pass
        return data

    def log(self, rtp):
        if self.isDebug:
            msg = f"v={rtp.version} p={rtp.padding} x={rtp.extension}"
            msg += f" cc={rtp.csrc_count} m={rtp.marker} pt={rtp.payload_type}"
            msg += f" seq={rtp.sequence_no} ts={rtp.timestamp} ssrc={rtp.ssrc}"
            self.audio_file_logger.debug(msg)

    def process(self, rtp):
        data = self.decrypt(rtp)
        packet = av.packet.Packet(data)
        if(len(data) > 0):
            try:
                for frame in self.codecContext.decode(packet):
                    frame = self.resampler.resample(frame)
                    return frame.planes[0].to_bytes()
            except ValueError as e:
                self.audio_screen_logger.error(repr(e))
                pass

    def run(self, rcvr_cmd_pipe):
        # This pipe is between player (read data) and server (write data)
        here, there = multiprocessing.Pipe()
        server_thread = threading.Thread(target=self.serve, args=(there,))
        player_thread = threading.Thread(target=self.play, args=(rcvr_cmd_pipe, here))

        server_thread.start()
        player_thread.start()

    @classmethod
    def spawn(
            cls,
            addr,
            session_key, iv=None,
            audio_format=0, buff_size=None,
            streamtype=0,
            isDebug=False,
            aud_params: AudioSetup = None,
    ):
        audio = cls(
            addr,
            session_key, iv,
            audio_format, buff_size,
            streamtype,
            isDebug,
            aud_params,
        )
        # This pipe is reachable from receiver
        rcvr_cmd_pipe, audio.command_chan = multiprocessing.Pipe()
        audio_proc = multiprocessing.Process(target=audio.run, args=(rcvr_cmd_pipe,))
        audio_proc.start()

        return audio.port, audio_proc, audio.command_chan


class AudioRealtime(Audio):
    """
    This method for handling Realtime packets is a bit hand to mouth, and needs
    at least a few packet's worth of buffer to handle jitter.
    """
    def __init__(
            self,
            addr,
            session_key, iv,
            audio_format, buff_size,
            streamtype,
            isDebug=False,
            aud_params: AudioSetup = None
    ):
        super(AudioRealtime, self).__init__(
            addr,
            session_key, iv,
            audio_format, buff_size,
            streamtype,
            isDebug,
            aud_params
        )
        self.isDebug = isDebug
        self.socket = get_free_socket(addr)
        self.port = self.socket.getsockname()[1]
        self.rtp_buffer = RTPRealtimeBuffer(buff_size, self.isDebug)

    def fini_audio_sink(self):
        self.sink.close()
        self.pa.terminate()

    def play(self, rtspconn, serverconn):
        # we don't use this method yet
        pass

    def serve(self, playerconn):
        self.init_audio_sink()
        RTP_SEQ_SIZE = 2**16
        RTP_ROLLOVER = RTP_SEQ_SIZE - 1  # 65535
        lastRecvdSeqNo = 0
        lastPlayedSeqNo = 0
        playing = False

        try:
            while True:
                data, address = self.socket.recvfrom(4096)
                if data:
                    pkt = RTP_REALTIME(data)
                    lastRecvdSeqNo = pkt.sequence_no
                    self.log(pkt)
                    self.rtp_buffer.append(pkt)
                    if (
                        self.rtp_buffer.is_full()
                    ):
                        try:
                            if playing:
                                rtp = self.rtp_buffer.pop((lastPlayedSeqNo + 1) % RTP_SEQ_SIZE)
                            else:
                                rtp = self.rtp_buffer.pop(0)
                            if not rtp:  # There was a sequence jump (pkt loss)
                                nextseq = self.rtp_buffer.find((lastPlayedSeqNo + 1) % RTP_SEQ_SIZE)
                                rtp = self.rtp_buffer.pop(nextseq)
                            if rtp:
                                lastPlayedSeqNo = rtp.sequence_no
                            audio = self.process(rtp)
                            if(audio):
                                self.sink.write(audio)
                                playing = True
                        except (RecursionError, TypeError) as e:
                            self.audio_screen_logger.error(repr(e))
                            playing = False
                            pass
        except KeyboardInterrupt:
            pass
        finally:
            self.socket.close()
            self.fini_audio_sink()


class AudioBuffered(Audio):
    def __init__(
            self,
            addr,
            session_key, iv=None,
            audio_format=None, buff_size=None,
            streamtype=0,
            isDebug=False,
            aud_params: AudioSetup = None
    ):
        super(AudioBuffered, self).__init__(
            addr,
            session_key, iv,
            audio_format, buff_size,
            streamtype,
            isDebug,
            aud_params,
        )
        self.isDebug = isDebug
        if self.isDebug:
            self.ab_file_logger = get_file_logger("AudioBuffered", level="DEBUG")
            self.ab_screen_logger = get_screen_logger("AudioBuffered", level='DEBUG')
        else:
            self.ab_screen_logger = get_screen_logger("AudioBuffered", level="INFO")
        self.socket = get_free_socket(addr, tcp=True)
        self.port = self.socket.getsockname()[1]
        self.anchorMonotonicTime = None  # local play start time in nanos
        self.rtp_buffer = RTPBuffer(buff_size, self.isDebug)
        self.anchorRtpTime = None  # remote playback start in RTP Hz

    def get_time_offset(self, rtp_ts):
        # gets the offset in millis from incoming RTP timestamp vs playout millis
        # Usually fills to about ~120 seconds ahead for buffered streams.
        if not self.anchorRtpTime:
            return 0
        rtptime_offset = rtp_ts - self.anchorRtpTime
        realtime_offset_ms = (time.monotonic_ns() - self.anchorMonotonicTime) * 1e-6
        time_offset_ms = (1000 * rtptime_offset / self.sample_rate) - int(realtime_offset_ms)
        return int(time_offset_ms)

    def get_min_timestamp(self):
        realtime_offset_sec = (time.monotonic_ns() - self.anchorMonotonicTime) * 1e-9
        self.ab_screen_logger.debug(f"playback: get_min_timestamp - realtime_offset_sec={realtime_offset_sec:06.4f}")
        res = self.anchorRtpTime + realtime_offset_sec * self.sample_rate
        self.ab_screen_logger.debug(f"playback: get_min_timestamp return={res}")

        return res

    def forward(self, requested_timestamp):
        finished = False
        while not finished:
            rtp = self.rtp_buffer.next()
            if rtp:
                if rtp.timestamp >= requested_timestamp:
                    finished = True
                else:
                    pass
                    # self.ab_screen_logger.info(f"playback: still forwarding... ts={rtp.timestamp}")
            else:
                self.ab_screen_logger.error("playback: !!! error while forwarding !!!")
                finished = True

    # player moves readindex in buffer
    def play(self, rtspconn, serverconn):
        playing = False
        data_ready = False
        data_ontime = True
        i = 0
        while True:
            if not playing:
                rtsp_timeout = None
            else:
                rtsp_timeout = 0
            if not data_ontime:
                server_timeout = None
            else:
                server_timeout = 0

            if self.rtp_buffer.can_read() and self.rtp_buffer.get_fullness() > 0.2:
                data_ready = True

            if serverconn.poll(server_timeout):
                message = serverconn.recv()
                if message == "data_ready":
                    data_ready = True
                elif message == "data_ontime_response":
                    self.ab_screen_logger.info("playback: ontime data response received")
                    ts = self.get_min_timestamp()
                    self.ab_screen_logger.info(f"playback: forwarding to timestamp {ts}")
                    self.forward(ts)

                    data_ontime = True

            if rtspconn.poll(rtsp_timeout):
                message = rtspconn.recv()
                if str.startswith(message, "play"):
                    self.anchorMonotonicTime = time.monotonic_ns()
                    self.anchorRtpTime = int(str.split(message, "-")[1])

                    playing = True

                elif message == "pause":
                    playing = False
                    data_ready = False

                elif str.startswith(message, "flush_from_until_seq"):
                    from_int, until_int = map(int, str.split(message, "-")[-2:])
                    msg = f"playback: received flush request from-until"
                    seqplus = f" sequence {from_int}-{until_int}. Relaying to server."
                    msg += seqplus
                    self.ab_screen_logger.info(msg)
                    serverconn.send(message)

            if playing and data_ready:
                rtp = self.rtp_buffer.next()
                if rtp:
                    time_offset_ms = self.get_time_offset(rtp.timestamp)
                    if i % 1000 == 0:
                        # pass
                        self.ab_screen_logger.info(f"playback: offset is {time_offset_ms} ms")
                    if time_offset_ms >= (self.sample_delay * 10**3):
                        msg = f"playback: offset {time_offset_ms} ms too big"
                        msg += f" - seq = {rtp.sequence_no} - sleeping {time_offset_ms * 1e-3:5.2f} sec"
                        self.ab_screen_logger.debug(msg)
                        # This method is more smooth, but more delay vs other devices.
                        time.sleep(time_offset_ms * 10**-3)
                        # This method gets sync almost exact, by itself, but stutters a bit at start.
                        # time.sleep((self.sample_delay * 0.5) - 0.001)
                        pass
                    elif time_offset_ms < -1e2:
                        msg = f"playback: offset of {time_offset_ms} ms too late "
                        msg += f"seq={rtp.sequence_no}, ts={rtp.timestamp} - sent ontime data request to server"
                        self.ab_screen_logger.info(msg)
                        # request on_time data message
                        serverconn.send("on_time_data_request")
                        data_ontime = False

                    audio = self.process(rtp)
                    self.sink.write(audio)
                    i += 1

    # server moves write index in buffer
    # the exception to this rule is the buffer initialization (init call)
    def serve(self, playerconn):
        self.init_audio_sink()

        conn, addr = self.socket.accept()
        seq_to_overtake = None
        pending_ontime_data_request = False
        try:
            while True:
                while playerconn.poll():
                    message = playerconn.recv()
                    if str.startswith(message, "flush_from_until_seq"):
                        self.ab_screen_logger.info(f"server: received flush request: {message}")
                        from_int, seq_to_overtake = map(int, str.split(message, "-")[-2:])
                        from_index = self.rtp_buffer.find_seq(from_int)
                        if from_index:
                            if self.rtp_buffer.flush_write(from_index):
                                self.ab_screen_logger.info(f"server: successfully flushed - write index moved to {from_index}")
                            else:
                                self.ab_screen_logger.info("server: flush did not move write index")
                    elif message == "on_time_data_request":
                        self.ab_screen_logger.debug("server: ontime data request received")
                        pending_ontime_data_request = True

                # Receive RTP packets from the TCP stream:
                message = conn.recv(2, socket.MSG_WAITALL)
                if message:
                    # Each RTP packet is preceeded by a uint16 of its size
                    data_len = int.from_bytes(message, byteorder='big')
                    # Then the RTP packet:
                    data = conn.recv(data_len - 2, socket.MSG_WAITALL)

                    rtp = RTP_BUFFERED(data)
                    self.log(rtp)
                    time_offset_ms = self.get_time_offset(rtp.timestamp)
                    # self.ab_screen_logger.debug(f"server: writing seq={rtp.sequence_no} offset={time_offset_ms} msec")
                    if seq_to_overtake is None:
                        self.rtp_buffer.add(rtp)
                    else:
                        msg = f"server: searching sequence {seq_to_overtake} -"
                        msg += f" current is {rtp.sequence_no}"
                        self.ab_screen_logger.debug(msg)
                        # do not write data if it is expired
                        if rtp.sequence_no >= seq_to_overtake:
                            if from_int == 0:
                                self.ab_screen_logger.debug("server: buffer initialisation")
                                self.rtp_buffer.init()
                            self.rtp_buffer.add(rtp)
                            msg = f"server: requested sequence to overtake "
                            msg += f"{seq_to_overtake} - received sequence {rtp.sequence_no}"
                            self.ab_screen_logger.info(msg)
                            # as soon as we overtake seq_to_overtake sequence, let's inform the player
                            playerconn.send("data_ready")
                            seq_to_overtake = None
                    if pending_ontime_data_request:
                        if abs(time_offset_ms) >= 1e2:
                            pending_ontime_data_request = False
                            playerconn.send("data_ontime_response")
                            self.ab_screen_logger.debug("server: ontime data response sent")

        except KeyboardInterrupt:
            pass
        finally:
            conn.close()
            self.socket.close()
