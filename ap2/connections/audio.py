import socket
import string
import struct
import multiprocessing
import enum
import threading
from array import array
import time
from bisect import bisect_left

import av
import numpy
import pyaudio
from Crypto.Cipher import ChaCha20_Poly1305
from av.audio.format import AudioFormat

from ..utils import get_logger, get_free_tcp_socket, get_free_udp_socket


class RTP:
    def __init__(self, data):
        self.version = (data[0] & 0b11000000) >> 6
        self.padding = (data[0] & 0b00100000) >> 5
        self.extension = (data[0] & 0b00010000) >> 4
        self.csrc_count = data[0] & 0b00001111

        self.timestamp = struct.unpack(">I", data[4:8])[0]
        self.ssrc = struct.unpack(">I", data[8:12])[0]

        self.nonce = data[-8:]
        self.tag = data[-24:-8]
        self.aad = data[4:12]
        self.payload = data[12:-24]


class RTP_REALTIME(RTP):
    def __init__(self, data):
        super(RTP_REALTIME, self).__init__(data)
        self.payload_type = data[1] & 0b01111111
        self.marker = (data[1] & 0b10000000) >> 7
        self.sequence_no = struct.unpack(">H", data[2:4])[0]


class RTP_BUFFERED(RTP):
    def __init__(self, data):
        super(RTP_BUFFERED, self).__init__(data)
        self.payload_type = 0
        self.marker = 0
        self.sequence_no = struct.unpack('>I', b'\0' + data[1:4])[0]


# Very simple circular buffer implementation
class RTPBuffer:
    # TODO : Centralized for both this buffer size and audioBufferSize returned by SETUP
    BUFFER_SIZE = 8192

    def __init__(self):
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
        if index < self.BUFFER_SIZE - 1:
            return index + 1
        else:
            return 0

    def decrement_index(self, index):
        if index == 0:
            return self.BUFFER_SIZE - 1
        else:
            return index - 1

    def add(self, rtp_data):
        #print("write  - %i %i" % (self.read_index, self.write_index))
        if self.write_index % 1000 == 0:
            print("write - buffer full at %s - ri=%i - wi=%i - seq=%i" % ("{:.1%}".format(self.get_fullness()), self.read_index, self.write_index, rtp_data.sequence_no))

        used_index = self.write_index
        self.buffer_array[self.write_index] = rtp_data
        self.buffer_array_seqs[self.write_index] = rtp_data.sequence_no
        if self.read_index == -1:
            # First write - init read index
            self.read_index = self.write_index
        else:
            if self.increment_index(self.write_index) == self.read_index:
                # buffer overflow, we "push" the read index
                print("Buffer overrrun")
                self.read_index = self.increment_index(self.read_index)
        self.write_index = self.increment_index(self.write_index)

        return used_index

    def get(self):
        return self.buffer_array[self.read_index]

    def next(self):
        # print("read   - %i %i" % (self.read_index, self.write_index))
        if self.read_index == -1:
            return None
        else:
            buffered_object = self.buffer_array[self.read_index]
            if self.read_index % 1000 == 0:
                print("read  - buffer full at %s - ri=%i - wi=%i - seq=%i" % ("{:.1%}".format(self.get_fullness()), self.read_index, self.write_index,buffered_object.sequence_no))

            if self.increment_index(self.read_index) == self.write_index:
                # buffer underrun, nothing we can do
                print("Buffer underrun")
                self.read_index = -1
            else:
                self.read_index = self.increment_index(self.read_index)

        return buffered_object

    def get_fullness(self):
        write_index = self.write_index
        read_index = self.read_index
        if read_index < write_index:
            fill = write_index - read_index
        else:
            fill = self.BUFFER_SIZE - read_index + write_index
        return fill / self.BUFFER_SIZE

    def get_bounds(self):
        if self.read_index<= self.write_index:
            return self.read_index, self.write_index
        else:
            return self.write_index, self.read_index

    def find_seq(self, seq):
        # buffer_bounds = self.get_bounds()
        # active_seq_array = self.buffer_array_seqs[buffer_bounds[0]:buffer_bounds[1]]
        # index = bisect_left(active_seq_array, seq)
        # if index != len(active_seq_array) and active_seq_array[index] == seq:
        #     return index
        # return None
        for i in range(self.BUFFER_SIZE - 1):
            if self.buffer_array[i] and self.buffer_array[i].sequence_no == seq:
                return i

    # Flush - Must be called from reader (player)
    def flush_read(self, new_index, seq_from, seq_until):
        if seq_from < self.buffer_array[self.read_index].sequence_no < seq_until:
            self.read_index = new_index
            return True
        else:
            return False

    # Flush - Must be called from writer (server)
    def flush_write(self, index_from):
        if self.write_index > index_from:
            self.write_index = index_from
            return True
        else:
            return False

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
        self.session_key = session_key
        self.rtp_buffer = RTPBuffer()

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
        #p = multiprocessing.Process(target=audio.serve)
        # This pipe is reachable from receiver
        parent_reader_connection, audio.audio_connection = multiprocessing.Pipe()
        # This one is between player (read data) and server (write data)
        parent_writer_connection, writer_connection = multiprocessing.Pipe()
        p = threading.Thread(target=audio.serve, args=(writer_connection,))
        m = multiprocessing.Manager()
        play = threading.Thread(target=audio.play, args=(parent_reader_connection,parent_writer_connection))
        p.start()
        play.start()
        return audio.port, p, audio.audio_connection

class AudioRealtime(Audio):

    def __init__(self, session_key, audio_format):
        super(AudioRealtime, self).__init__(session_key, audio_format)
        self.socket = get_free_udp_socket()
        self.port = self.socket.getsockname()[1]

    def fini_audio_sink(self):
        self.sink.close()
        self.pa.terminate()

    def play(self, rtspconn, serverconn):
        # for now RT do no use RTPBuffer at all, we don't use this method
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
    def __init__(self, session_key, audio_format):
        super(AudioBuffered, self).__init__(session_key, audio_format)
        self.socket = get_free_tcp_socket()
        self.port = self.socket.getsockname()[1]

    # player moves readindex in buffer 
    def play(self, rtspconn, serverconn):
        playing = False
        pending_flush_until_seq = None
        pending_flush_from_index = None
        while True:
            if not playing:
                timeout = None
            else:
                timeout = 0.01

            if pending_flush_until_seq is not None:
                # Unfortunately, we cannot poll both serverconn and rtspconn at once
                if serverconn.poll(2):
                    message = serverconn.recv()
                    if str.startswith(message, "data_ready_response"):
                        print("player: received message %s" % message)
                        message, flush_until_seq, flush_until_index = str.split(message, "-")
                        flush_until_index = int(flush_until_index)
                        flush_until_seq = int(flush_until_seq)
                        # Check the message is matching our last flush request
                        if flush_until_seq == pending_flush_until_seq:
                            if self.rtp_buffer.flush_read(flush_until_index, pending_flush_from_seq, flush_until_seq):
                                print("player: successfully flushed from index % i until index %i" % (pending_flush_from_index, flush_until_index))
                            else:
                                print("player: flush did not move read index")

                            pending_flush_until_seq = None

                        else:
                            print("player: ignore sequence search response - sequence mismatch")
                else:
                    print("player: pending sequence search did not respond in time")
                    pending_flush_until_seq = None

            if rtspconn.poll(timeout):
                message = rtspconn.recv()
                if message == "stop":
                    playing = False
                if message == "play":
                    playing = True

                if str.startswith(message, "flush_start"):
                    pending_flush_from_seq, pending_flush_until_seq = str.split(message, "-")[-2:]
                    pending_flush_from_seq = int(pending_flush_from_seq)
                    pending_flush_until_seq = int(pending_flush_until_seq)
                    print("player: request flush received from-until %i-%i" % (pending_flush_from_seq, pending_flush_until_seq))
                    # packet may not have been written yet, so only server is/will be aware
                    # we request the server to inform, move of read index will be done by player thread itself
                    serverconn.send("data_ready_request-%i" % pending_flush_until_seq)
                    if pending_flush_from_seq != 0:
                        # flush-from may move write index, and is managed by server thread -> request it to flush
                        current_time = time.time()
                        pending_flush_from_index = self.rtp_buffer.find_seq(pending_flush_from_seq)
                        if pending_flush_from_index:
                            print("player: requested from sequence %i in %04.2f seconds" % (pending_flush_from_seq, time.time() - current_time))
                            serverconn.send("flush_from_index-%i" % pending_flush_from_index)
                        else:
                            raise Exception("player: flush failed - sequence %i not found" % pending_flush_from_seq)
                    else:
                        pending_flush_from_index = 0
            if playing and pending_flush_until_seq is None:
                rtp = self.rtp_buffer.next()
                if rtp:
                    audio = self.process(rtp)
                    self.sink.write(audio)

    # server moves write index in buffer
    def serve(self, playerconn):
        self.logger = get_logger("audio", level="DEBUG")
        self.init_audio_sink()

        conn, addr = self.socket.accept()
        searched_sequence = None
        try:
            while True:
                while playerconn.poll():
                    message = playerconn.recv()
                    if str.startswith(message, "data_ready_request"):
                        searched_sequence = int(str.split(message, "-")[1])
                        current_time = time.time()
                        searched_index = self.rtp_buffer.find_seq(searched_sequence)
                        if searched_index:
                            print("server: requested sequence %i - found sequence %i in %04.2f seconds" % (searched_sequence, searched_sequence, time.time() - current_time))
                            playerconn.send("data_ready_response-%i-%i" % (searched_sequence, searched_index))
                            searched_sequence = None
                        else:
                            print("server: requested sequence %i - nothing found - took %04.2f seconds" % (searched_sequence, time.time() - current_time))

                    if str.startswith(message, "flush_from_index"):
                        print("server: flush-from request received: %s" % message)
                        from_index = int(str.split(message, "-")[1])
                        if from_index:
                            if self.rtp_buffer.flush_write(from_index):
                                print("server: successfully flushed - write index moved to %i" % from_index)
                            else:
                                print("server: flush did not move write index")

                message = conn.recv(2, socket.MSG_WAITALL)
                if message:
                    data_len = struct.unpack(">H", message)[0]
                    data = conn.recv(data_len - 2, socket.MSG_WAITALL)

                    rtp = RTP_BUFFERED(data)
                    self.handle(rtp)
                    # do not write data if it is expired
                    if searched_sequence is None or rtp.sequence_no >= searched_sequence:
                        used_index = self.rtp_buffer.add(rtp)
                    if searched_sequence is not None:
                        print("server: Searching sequence %i - Current is %i" % (searched_sequence, rtp.sequence_no))
                        if rtp.sequence_no >= searched_sequence:
                            print("server: Requested sequence %i - Receiving sequence %i" % (searched_sequence, rtp.sequence_no))
                            # as soon as we detect sequence, inform player
                            playerconn.send("data_ready_response-%i-%i" % (searched_sequence, used_index))
                            searched_sequence = None

        except KeyboardInterrupt:
            pass
        finally:
            conn.close()
            self.socket.close()