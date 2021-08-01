import socket
import string
import multiprocessing
import enum
import threading
import time

import av
import numpy
import pyaudio
from Crypto.Cipher import ChaCha20_Poly1305
from av.audio.format import AudioFormat

from ..utils import get_logger, get_free_tcp_socket, get_free_udp_socket

from ap2.connections.ptp_time import PTP

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


# Very simple circular buffer implementation
class RTPBuffer:
    # TODO : Centralized for both this buffer size and audioBufferSize returned by SETUP
    BUFFER_SIZE = 1

    def __init__(self, size):
        self.BUFFER_SIZE = size
        self.buffer_array = numpy.empty(self.BUFFER_SIZE, dtype=RTP_BUFFERED)
        # Stores indexes only for quick bisect search
        self.buffer_array_seqs = numpy.empty(self.BUFFER_SIZE, dtype=int)

        # read index - where data is ready to be read
        self.read_index = -1
        # write index - where data is ready to be written
        self.write_index = 0
        self.flush_from_sequence = None
        self.flush_to_sequence = None

    def increment_index(self, index):
        return (index + 1) % self.BUFFER_SIZE

    def decrement_index(self, index):
        return (index + self.BUFFER_SIZE - 1) % self.BUFFER_SIZE

    def add(self, rtp_data):
        # print("write  - %i %i" % (self.read_index, self.write_index))
        if self.write_index % 1000 == 0:
            print("buffer: writing - full at %s - ri=%i - wi=%i - seq=%i" % ("{:.1%}".format(self.get_fullness()), self.read_index, self.write_index, rtp_data.sequence_no))

        used_index = self.write_index
        self.buffer_array[self.write_index] = rtp_data
        self.buffer_array_seqs[self.write_index] = rtp_data.sequence_no
        if self.read_index == -1:
            # First write - init read index
            self.read_index = self.write_index
        else:
            if self.increment_index(self.write_index) == self.read_index:
                # buffer overflow, we "push" the read index
                print("buffer: over-run")
                self.read_index = self.increment_index(self.read_index)
        self.write_index = self.increment_index(self.write_index)

        return used_index

    def get(self):
        return self.buffer_array[self.read_index]

    def can_read(self):
        return self.read_index != -1

    def next(self):
        # print("read   - %i %i" % (self.read_index, self.write_index))
        if self.read_index == -1:
            print("buffer: read is not possible - empty buffer")
            return None
        else:
            buffered_object = self.buffer_array[self.read_index]
            if self.read_index % 1000 == 0:
                print("buffer: reading - full at %s - ri=%i - wi=%i - seq=%i"
                      % ("{:.1%}".format(self.get_fullness()),
                          self.read_index,
                          self.write_index,
                          buffered_object.sequence_no))

            if self.increment_index(self.read_index) == self.write_index:
                # buffer underrun, nothing we can do
                print("buffer: underrun")
                self.read_index = -1
            else:
                self.read_index = self.increment_index(self.read_index)

        return buffered_object

    def previous(self):
        self.read_index = self.decrement_index(self.read_index)
        buffered_object = self.buffer_array[self.read_index]
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
            # print('searching left=%d, right=%d, m=%d, srch=%d, now_at=%d' % \
            # (left, right, m, seq, self.buffer_array_seqs[m] ))
            if self.buffer_array_seqs[m] == seq:
                return m
            if self.buffer_array_seqs[m] < seq:
                left = self.increment_index(m)
            elif self.buffer_array_seqs[m] > seq:
                left = self.decrement_index(m)

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

        print("Negotiated audio format: ", AirplayAudFmt(audio_format))

    def __init__(self, session_key, audio_format, buff_size):
        self.audio_format = audio_format
        self.session_key = session_key
        self.rtp_buffer = RTPBuffer(buff_size)
        self.set_audio_params(self, audio_format)

    @staticmethod
    def set_alac_extradata(self, sample_rate, sample_size, channel_count):
        extradata = bytes()  # a 36-byte QuickTime atom passed through as extradata
        extradata += (36).to_bytes(4, byteorder='big')   # 32 bits  atom size
        extradata += ('alac').encode()                   # 32 bits  tag ('alac')
        extradata += (0).to_bytes(4, byteorder='big')    # 32 bits  tag version (0)
        extradata += (352).to_bytes(4, byteorder='big')  # 32 bits  samples per frame
        extradata += (0).to_bytes(1, byteorder='big')    # 8 bits  compatible version   (0)
        extradata += (sample_size).to_bytes(1, byteorder='big')  # 8 bits  sample size
        extradata += (40).to_bytes(1, byteorder='big')   # 8 bits  history mult         (40)
        extradata += (10).to_bytes(1, byteorder='big')   # 8 bits  initial history      (10)
        extradata += (14).to_bytes(1, byteorder='big')   # 8 bits  rice param limit     (14)
        extradata += (channel_count).to_bytes(1, byteorder='big')  # 8 bits  channels
        extradata += (255).to_bytes(2, byteorder='big')  # 16 bits  maxRun               (255)
        extradata += (0).to_bytes(4, byteorder='big')    # 32 bits  max coded frame size (0 means unknown)
        extradata += (0).to_bytes(4, byteorder='big')    # 32 bits  average bitrate      (0 means unknown)
        extradata += (sample_rate).to_bytes(4, byteorder='big')  # 32 bits  samplerate
        return extradata

    def init_audio_sink(self):
        codecLatencySec = 0
        self.pa = pyaudio.PyAudio()
        self.sink = self.pa.open(format=self.pa.get_format_from_width(2),
                                 channels=self.channel_count,
                                 rate=self.sample_rate,
                                 output=True,
                                 stream_callback=self.callback,
                                 start=False,)
        # nice Python3 crash if we don't check self.sink is null. Not harmful, but should check.
        if not self.sink:
            exit()
        # codec = None
        extradata = None
        if self.audio_format == AirplayAudFmt.ALAC_44100_16_2.value:
            extradata = self.set_alac_extradata(self, 44100, 16, 2)
        elif self.audio_format == AirplayAudFmt.ALAC_44100_24_2.value:
            extradata = self.set_alac_extradata(self, 44100, 24, 2)
        elif self.audio_format == AirplayAudFmt.ALAC_48000_16_2.value:
            extradata = self.set_alac_extradata(self, 48000, 16, 2)
        elif self.audio_format == AirplayAudFmt.ALAC_48000_24_2.value:
            extradata = self.set_alac_extradata(self, 48000, 24, 2)

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
        print('codecLatencySec:',codecLatencySec)
        """

        if self.codec is not None:
            self.codecContext = av.codec.CodecContext.create(self.codec)
            self.codecContext.sample_rate = self.sample_rate
            self.codecContext.channels = self.channel_count
            self.codecContext.format = av.AudioFormat('s' + str(self.sample_size) + 'p')
        if extradata is not None:
            self.codecContext.extradata = extradata

        self.resampler = av.AudioResampler(
            format=av.AudioFormat('s' + str(self.sample_size)).packed,
            layout='stereo',
            rate=self.sample_rate,
        )

        audioDevicelatency = \
            self.pa.get_default_output_device_info()['defaultHighOutputLatency']
        # defaultLowOutputLatency is also available
        print(f"audioDevicelatency (sec): {audioDevicelatency:0.5f}")
        pyAudioDelay = self.sink.get_output_latency()
        print(f"pyAudioDelay (sec): {pyAudioDelay:0.5f}")
        ptpDelay = 0.002
        self.sample_delay = pyAudioDelay + audioDevicelatency + codecLatencySec + ptpDelay
        print(f"Total sample_delay (sec): {self.sample_delay:0.5f}")

    def decrypt(self, rtp):
        c = ChaCha20_Poly1305.new(key=self.session_key, nonce=rtp.nonce)
        c.update(rtp.aad)
        data = c.decrypt_and_verify(rtp.payload, rtp.tag)
        return data

    def handle(self, rtp):
        self.logger.debug(
            "v=%d p=%d x=%d cc=%d m=%d pt=%d seq=%d ts=%d ssrc=%d"
            % (rtp.version, rtp.padding,
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

    def run(self, parent_reader_connection, ptp_link):
        # This pipe is between player (read data) and server (write data)
        parent_writer_connection, writer_connection = multiprocessing.Pipe()
        server_thread = threading.Thread(target=self.serve, args=(writer_connection,))
        player_thread = threading.Thread(target=self.play, args=(parent_reader_connection, parent_writer_connection, ptp_link))

        server_thread.start()
        player_thread.start()

    @classmethod
    def spawn(cls, session_key, audio_format, buff, ptp_link=None):
        audio = cls(session_key, audio_format, buff)
        # This pipe is reachable from receiver
        parent_reader_connection, audio.audio_connection = multiprocessing.Pipe()
        mainprocess = multiprocessing.Process(target=audio.run, args=(parent_reader_connection, ptp_link))
        mainprocess.start()

        return audio.port, mainprocess, audio.audio_connection


class AudioRealtime(Audio):

    def __init__(self, session_key, audio_format, buff):
        super(AudioRealtime, self).__init__(session_key, audio_format, buff)
        self.socket = get_free_udp_socket()
        self.port = self.socket.getsockname()[1]

    def fini_audio_sink(self):
        self.sink.close()
        self.pa.terminate()

    def play(self, rtspconn, serverconn):
        # for now RealTime does not use RTPBuffer at all, we don't use this method
        pass

    def serve(self, playerconn):
        self.logger = get_logger("audio", level="DEBUG")
        self.init_audio_sink()

        try:
            while True:
                data, address = self.socket.recvfrom(4096)
                if data:
                    rtp = RTP_REALTIME(data)
                    self.handle(rtp)
                    audio = self.process(rtp)
                    self.sink.write(audio)
        except KeyboardInterrupt:
            pass
        finally:
            self.socket.close()
            self.fini_audio_sink()


class AudioBuffered(Audio):
    def __init__(self, session_key, audio_format, buff):
        super(AudioBuffered, self).__init__(session_key, audio_format, buff)
        self.socket = get_free_tcp_socket()
        self.port = self.socket.getsockname()[1]
        self.anchorMonotonicTime = None
        self.anchorRtpTime = None

    def get_time_offset(self, rtp_ts):
        if not self.anchorRtpTime:
            return 0
        rtptime_offset = rtp_ts - self.anchorRtpTime
        realtime_offset_ms = (time.monotonic_ns() - self.anchorMonotonicTime) / 10 ** 6
        time_offset_ms = (1000 * rtptime_offset / self.sample_rate) - realtime_offset_ms
        return time_offset_ms

    def get_min_timestamp(self):
        realtime_offset_sec = (time.monotonic_ns() - self.anchorMonotonicTime) / 10 ** 9
        print("player: get_min_timestamp - realtime_offset_sec={:06.4f}".format(realtime_offset_sec))
        res = self.anchorRtpTime + realtime_offset_sec * self.sample_rate
        print("player: get_min_timestamp return=%i" % res)

        return res


    def callback(self, in_data, frame_count, time_info, status):
        self.ptp_link.send("get_ptp_master_nanos_timestamped")
        if self.ptp_link.poll(1):
            network_time_ns, network_time_monotonic_ts = self.ptp_link.recv()
            time_monotonic_ns = time.monotonic_ns()
            network_time_ns += time_monotonic_ns - network_time_monotonic_ts
        else:
            return

        rtp = self.rtp_buffer.next()
        if not rtp:
            print(f"callback {frame_count} no more data")
            return (None, pyaudio.paAbort)

        dac_offset = time_info["output_buffer_dac_time"] - time_info["current_time"]

        rtp_timestamp = (
            (network_time_ns - self.anchorNetworkTime) / (10 ** 9) + dac_offset
        ) * self.sample_rate + self.anchorRtpTime

        # print(
        #     f"callback {frame_count} {rtp.timestamp} {time_info['output_buffer_dac_time']} {time_info['current_time']} ts: {rtp_timestamp} dac offset {dac_offset}"
        # )
        skip = 0
        while rtp_timestamp - rtp.timestamp > 1024:
            rtp = self.rtp_buffer.next()
            if rtp is None:
                return
            skip += 1
        if skip != 0:
            print(f"skipped {skip}")

        back = 0
        while skip == 0 and rtp.timestamp - rtp_timestamp > 1024:
            rtp = self.rtp_buffer.previous()
            back += 1
        if back > 0:
            print(f"went back {back}")

        audio = self.process(rtp)
        return (audio, pyaudio.paContinue)

    def forward(self, requested_timestamp):
        finished = False
        while not finished:
            rtp = self.rtp_buffer.next()
            if rtp:
                if rtp.timestamp >= requested_timestamp:
                    finished = True
                else:
                    pass
                    # print("player: still forwarding.. ts=%i" % rtp.timestamp)
            else:
                print("player: !!! error while forwarding !!!")
                finished = True

    # player moves readindex in buffer
    def play(self, rtspconn, serverconn, ptp_link):
        playing = False
        data_ready = False
        data_ontime = True
        self.ptp_link = ptp_link
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

            if not data_ready and self.rtp_buffer.get_fullness() > 0.2:
                print(
                    f"setting data ready at buffer fullness {self.rtp_buffer.get_fullness()}"
                )
                data_ready = True

            if serverconn.poll(server_timeout):
                message = serverconn.recv()
                if message == "data_ready":
                    data_ready = True
                    print(f"setting data ready at from server")
                elif message == "data_ontime_response":
                    print("player: ontime data response received")
                    ts = self.get_min_timestamp()
                    print("player: forwarding to timestamp %i" % ts)
                    self.forward(ts)

                    data_ontime = True

            if rtspconn.poll(rtsp_timeout):
                message = rtspconn.recv()
                if str.startswith(message, "play"):
                    self.anchorMonotonicTime = time.monotonic_ns()
                    msg_data = str.split(message, "-")
                    self.anchorRtpTime = int(msg_data[1])
                    self.anchorNetworkTime = int(msg_data[2])

                    playing = True

                elif message == "pause":
                    playing = False
                    data_ready = False
                    print("pause event")
                    if self.use_callback:
                        print("  stopping stream")
                        self.sink.stop_stream()

                elif str.startswith(message, "flush_from_until_seq"):
                    pending_flush_from_seq, pending_flush_until_seq = str.split(
                        message, "-"
                    )[-2:]
                    pending_flush_from_seq = int(pending_flush_from_seq)
                    pending_flush_until_seq = int(pending_flush_until_seq)

                    print(
                        "player: request flush received from-until %i-%i"
                        % (pending_flush_from_seq, pending_flush_until_seq)
                    )
                    print(
                        "player: relay message to server to flush from-until sequence %i-%i"
                        % (pending_flush_from_seq, pending_flush_until_seq)
                    )
                    serverconn.send(message)

            if playing and data_ready:
                if not self.sink.is_active():
                    print("starting stream")
                    self.sink.start_stream()
                continue  # use callback

    # server moves write index in buffer
    # the exception to this rule is the buffer initialization (init call)
    def serve(self, playerconn):
        self.logger = get_logger("audio", level="DEBUG")
        self.init_audio_sink()

        conn, addr = self.socket.accept()
        seq_to_overtake = None
        pending_ontime_data_request = False
        try:
            while True:
                while playerconn.poll():
                    message = playerconn.recv()
                    if str.startswith(message, "flush_from_until_seq"):
                        print("server: flush request received: %s" % message)
                        pending_flush_from_seq, pending_flush_until_seq = str.split(message, "-")[-2:]
                        pending_flush_from_seq = int(pending_flush_from_seq)
                        seq_to_overtake = int(pending_flush_until_seq)
                        from_index = self.rtp_buffer.find_seq(pending_flush_from_seq)
                        if from_index:
                            if self.rtp_buffer.flush_write(from_index):
                                print("server: successfully flushed - write index moved to %i" % from_index)
                            else:
                                print("server: flush did not move write index")
                    elif message == "on_time_data_request":
                        print("server: ontime data request received")
                        pending_ontime_data_request = True

                message = conn.recv(2, socket.MSG_WAITALL)
                if message:
                    data_len = int.from_bytes(message, byteorder='big')
                    data = conn.recv(data_len - 2, socket.MSG_WAITALL)

                    rtp = RTP_BUFFERED(data)
                    self.handle(rtp)
                    time_offset_ms = self.get_time_offset(rtp.timestamp)
                    # print("server: writing seq %i timeoffset %i" % (rtp.sequence_no, time_offset_ms))
                    if seq_to_overtake is None:
                        self.rtp_buffer.add(rtp)
                    else:
                        print("server: searching sequence %i - current is %i" % (seq_to_overtake, rtp.sequence_no))
                        # do not write data if it is expired
                        if rtp.sequence_no >= seq_to_overtake:
                            if pending_flush_from_seq == 0:
                                print("server: buffer initialisation")
                                self.rtp_buffer.init()
                            self.rtp_buffer.add(rtp)
                            print("server: requested sequence to overtake %i - receiving sequence %i" % (seq_to_overtake, rtp.sequence_no))
                            # as soon as we overtake seq_to_overtake sequence, let's inform the player
                            playerconn.send("data_ready")
                            seq_to_overtake = None
                    if pending_ontime_data_request:
                        if time_offset_ms >= 100:
                            pending_ontime_data_request = False
                            playerconn.send("data_ontime_response")
                            print("server: ontime data response sent")

        except KeyboardInterrupt:
            pass
        finally:
            conn.close()
            self.socket.close()
