import socket
import multiprocessing
import enum
import threading
import time

import av
import pyaudio
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Cipher import AES
from collections import deque
from operator import attrgetter
from operator import add
from functools import reduce


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
        self.hasredundancy = False
        """ Welcome to airplay redundancy. 0 to 7 blocks/frames opportunistically
        prepend the current audio frame, together forming the (encrypted) payload,
        when space comprising the difference between packet MTU and current audio
        frame is available. Redundancy is extra copies of earlier audio frames.

        Passages with low dynamic range i.e. quieter passages which losslessly
        compress better get more redundancy, up to an observed max of 8 blocks
        (7 redundant previous frames, plus 1 current, in this order).
        Passages with high dynamic range, get less to none. This assumes ALAC.
        Activate feature bit 61 for the sender to use redundancy.
        This works with or without buffered audio (bit 40+41).
        """
        """ header block from RFC2198 with ordinal bits:
                           1                   2                   3
         1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |F|block PT 7bit|  timestamp offset 14bits  |block length 10bits|
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        F (1 bit): First bit. 1 indicates whether another header block
           follows. 0 if this is the last header block.

        block PT (7 bits): RTP payload type for this corresponding block.

        if F is 1:
        timestamp (TS) offset (14 bits): Unsigned offset of this block TS
           relative to pkt header TS. Unsigned means redundant data must
           be sent after the primary data, ∴ subtracted from current TS
           to determine the data TS for which this block is the redundancy.

        block length (10 bits): byte length of the corresponding data
           block excluding header.

        if F is 0: payload commences after block PT.
        Ex RTP:
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |V=2|P|X| CC=0  |M|      PT     |   sequence number of primary  |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |              timestamp  of primary encoding                   |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |           synchronization source (SSRC) identifier            |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Then for example:
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |0|    0x60 / 96| payload (current, not to scale)               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        or:
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |1|    0x60 / 96|   352  (1 pkt ago, r-1)   |           size    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |0|    0x60 / 96| payload (r-1 + current, not to scale)         |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        or:
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |1|    0x60 / 96|   352  (1 pkt ago, r-1)   |           size    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |1|    0x60 / 96|   704  (2 pkts ago r-2)   |           size    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |1|    0x60 / 96|  1056  (3 pkts ago, r-3)  |           size    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |1|    0x60 / 96|  ....  (X pkts ago, r-X)  |           size    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |1|    0x60 / 96|  2464  (7 pkts ago, r-7)  |           size    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |0|    0x60 / 96| payload (r-1 + r-2 + r-3 + r-X + .. + current)|
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
        if self.payload_type == 97:
            self.block_list = []
            fbit = 1
            i = 0
            try:
                while fbit:
                    extra_hdr = data[12 + (i * 4):16 + (i * 4)]
                    fbit = extra_hdr[0] & 0b10000000
                    block_pt = extra_hdr[0] & 0x7F
                    if fbit:
                        self.hasredundancy = True
                        ts_offset = (int.from_bytes(extra_hdr[1:3], byteorder='big') & 0x3FFC) >> 2
                        block_length = int.from_bytes(extra_hdr[2:4], byteorder='big') & 0x3FF
                        self.block_list.append((block_pt, ts_offset, block_length))
                        # ts_offset increment is spf, e.g. 352
                    else:
                        # Can be zero headers, but 1 F+PT byte
                        self.payload = data[12 + (i * 4) + 1:-24]
                        break
                    i += 1
            except IndexError as e:
                # pkt was probably not one with redundancy. Corrupt?
                pass


class RTP_BUFFERED(RTP):
    def __init__(self, data):
        super(RTP_BUFFERED, self).__init__(data)
        self.payload_type = 0
        self.marker = 0
        self.sequence_no = int.from_bytes(b'\0' + data[1:4], byteorder='big')


class RTPRealtimeBuffer:
    """
    Small, simple, resilient.
    Appends all packets at the bottom. Flags any missing pkts.
    Pop from top returns next in order.
    """
    BUFFER_SIZE = 1
    RTP_SEQ_SIZE = 2**16
    RTP_ROLLOVER = RTP_SEQ_SIZE - 1  # 65535
    HALF_RTP = RTP_SEQ_SIZE // 2
    TS_SIZE = 2**32
    TS_ROLLOVER = TS_SIZE - 1
    HALF_TS = TS_SIZE // 2

    def __init__(self, size, isDebug=False):
        self.BUFFER_SIZE = size
        self.isDebug = isDebug
        self.queue = deque(maxlen=self.BUFFER_SIZE)
        self.sn_queue = deque(maxlen=self.BUFFER_SIZE)
        self.ts_queue = deque(maxlen=self.BUFFER_SIZE)
        self.window_divisor = 5
        self.missing_check_length = self.BUFFER_SIZE // self.window_divisor
        self.missing_seq_no_list = list()
        self.gapsExist = False
        self.ts_diff = None
        """
        level = 'DEBUG' if self.isDebug else 'INFO':
        self.rtp_logger = get_screen_logger(self.__class__.__name__, level=level)
        """

    def inter_pkt_diff(self):
        """ Should be constant 1024/352. """
        return self.ts_diff

    def has(self, pkt, seq=False):
        """ True if our q(s) already has this pkt """
        return True if pkt.sequence_no in self.sn_queue or pkt.timestamp in self.ts_queue else False

    def append(self, rtp):
        """ puts rtp into the bottom or left of the queue, if not already """
        if not self.has(rtp):
            self.queue.appendleft(rtp)
            self.sn_queue.appendleft(rtp.sequence_no)
            self.ts_queue.appendleft(rtp.timestamp)
        if rtp.sequence_no % self.missing_check_length == 0:
            """ Only run missing pkt check on a fraction of the q
            Otherwise we encourage repeat pkts in the buffer. """
            self.missing_sequence_nos_chk()
        if not self.ts_diff:
            """ Timestamp increases by a constant. Find it at startup. """
            self.find_ts_diff(rtp)

    def rollover_sort(self, sn=True):
        """ First get all seq # above 32768, then below 32768, so pairwise_check works at rollover """
        q = self.sn_queue if sn else self.ts_queue
        ro = self.HALF_RTP if sn else self.HALF_TS
        """ is there a cleaner way than this? Splits the q when rolling over, and midway thru so it sorts correctly """
        if self.RTP_ROLLOVER in q:
            sort = sorted([x for x in q if x & ro > 0]) + sorted([x for x in q if x & ro == 0])
        else:
            sort = sorted([x for x in q if x & ro == 0]) + sorted([x for x in q if x & ro > 0])
        return sort

    def missing_sequence_nos_chk(self):
        """ Determine which sequence numbers are missing from q """
        length = len(self.sn_queue)
        window = length // self.window_divisor
        if length > 0 and self.amount() > 0.6:
            """ Examine only an approaching portion of ordered buffer content.
            This gives jittered pkts time to arrive. Sort with rollover. """
            seq_sorted = self.rollover_sort(sn=True)
            self.pairwise_check(seq_sorted[window:window * 2])
            """ 2nd 5th and 4th 5th allow for missing pkts to arrive, but checks those parts twice
            i.e. risks requesting missing pkts twice. We check whether the q has a pkt before accepting it. """
            self.pairwise_check(seq_sorted[window * 3:window * 4])

    def pairwise_check(self, iterable):
        """ iterate, check for monotonic increase of seq #, flag any sequence breaks/jumps  """
        it = iter(iterable)
        a = next(it, None)
        for b in it:
            jump = self.calc_seq_rod(b, a) - 1
            if jump >= 1:
                jump = 7 if jump > 7 else jump
                self.missing_seq_no_list.append((a + 1, jump))
                self.gapsExist = True
            a = b

    def gaps_exist(self):
        return self.gapsExist

    def missing_sequence_nos(self):
        """ return the list of missing sequence numbers. Empty it also. """
        _list = self.missing_seq_no_list
        self.missing_seq_no_list = list()
        self.gapsExist = False
        return _list

    def calc_seq_rod(self, a, b):
        """ calc RollOverDiff: seq no. diff between a & b, where a > b, accounting for 16 bit rollover """
        return (a - b) & self.RTP_ROLLOVER

    def calc_ts_rod(self, a, b):
        """ calc RollOverDiff: timestamp diff between a & b, where a > b, accounting for 32 bit rollover """
        return (a - b) & self.TS_ROLLOVER

    def find_ts_diff(self, rtp):
        """ calculates the inter-pkt timestamp diff on stream startup """
        if self.size() > 1 and self.calc_seq_rod(rtp.sequence_no, 1) == self.queue[1].sequence_no:
            self.ts_diff = rtp.timestamp - self.queue[1].timestamp

    def get_ts_diff(self):
        return self.ts_diff

    def clear(self):
        """ Clears the 3 parallel qs of contents. Like a reinit, but we don't specify all params again """
        self.queue.clear()
        self.ts_queue.clear()
        self.sn_queue.clear()
        self.ts_diff = None

    def pop(self, seq=None, get_ts=False):
        """ Seq numbers increase monotonically. TS increase by a constant. """
        length = self.size()
        if length == 0:
            return None
        else:
            if seq is None or seq == 0:  # Start-up
                self.sn_queue.pop()
                self.ts_queue.pop()
                return self.queue.pop()
            return self.peek(seq, get_ts)

    def peek(self, seq=None, get_ts=False):
        """Look in the queue for a seq#/ts and return pkt if q has it
        Slightly risky to use other q index, e.g. if qs desync """
        try:
            if get_ts:
                index = self.ts_queue.index(seq)
                self.ts_queue.remove(seq)
            else:
                index = self.sn_queue.index(seq)
                self.sn_queue.remove(seq)
            pkt = self.queue[index]
            self.queue.remove(pkt)
            return pkt
        except (ValueError, IndexError):
            return None

    def size(self):
        """ just get current size of buffer """
        return len(self.queue)

    def amount(self):
        """ How full buffer is """
        return len(self.queue) / self.queue.maxlen

    def is_full(self):
        return len(self.queue) == self.queue.maxlen

    def is_empty(self):
        return len(self.queue) == 0

    def flush(self, until, ts=False):
        q = list(self.queue)
        s = list(self.sn_queue)
        t = list(self.ts_queue)
        attr = 'sequence_no' if not ts else 'timestamp'
        self.queue = deque([rtp for rtp in reversed(q) if attrgetter(attr)(rtp) >= until], maxlen=self.BUFFER_SIZE)
        """ using q (and not the new self.q) takes slightly longer, but we wont get index out of range errors """
        self.ts_queue = deque([ts for ts in reversed(t) if ts >= q[len(q) - 1].timestamp], maxlen=self.BUFFER_SIZE)
        self.sn_queue = deque([sn for sn in reversed(s) if sn >= q[len(q) - 1].sequence_no], maxlen=self.BUFFER_SIZE)


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
            spf=1024,
            streamtype=0,
            control_conns=None,
            isDebug=False,
            aud_params: AudioSetup = None,
    ):
        self.isDebug = isDebug
        self.addr = addr
        loglevel = 'DEBUG' if self.isDebug else 'INFO'
        self.audio_file_logger = get_file_logger("Audio.debug", level="DEBUG")
        self.audio_screen_logger = get_screen_logger(self.__class__.__name__, level=loglevel)

        self.audio_format = audio_format
        self.audio_params = aud_params
        self.spf = spf
        self.streamtype = streamtype
        self.session_key = session_key
        self.session_iv = session_iv
        self.control_conns = control_conns
        sk_len = len(session_key)
        self.key_and_iv = True if (sk_len == 16 or sk_len == 24 or sk_len == 32 and session_iv is not None) else False
        self.set_audio_params(self, audio_format)

        """ variables we get via RTCP from Control class """
        self.senderRtpTimestamp, self.playAtRtpTimestamp = None, None
        self.remoteClockMonotonic_ts, self.remoteClockId = None, None

    def init_audio_sink(self):
        codecLatencySec = 0
        self.pa = pyaudio.PyAudio()
        self.sink = self.pa.open(format=self.pa.get_format_from_width(2),
                                 channels=self.channel_count,
                                 rate=self.sample_rate,
                                 output=True,
                                 frames_per_buffer=4,
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
        elif'AAC_LC' in self.af:
            codecLatencySec = (2624 / self.sample_rate)
        codecLatencySec = 0
        self.audio_screen_logger.debug(f'codecLatencySec: {codecLatencySec}')
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
            try:
                c = ChaCha20_Poly1305.new(key=self.session_key, nonce=rtp.nonce)
                c.update(rtp.aad)  # necessary at least for RTP type 103.
                data = c.decrypt_and_verify(rtp.payload, rtp.tag)
            except ValueError as e:
                self.audio_screen_logger.error(f'RTP ChaCha20_Poly1305 decrypt: {repr(e)}')
                pass  # noqa
        return data

    def log(self, rtp):
        if self.isDebug:
            msg = f"v={rtp.version} p={rtp.padding} x={rtp.extension}"
            msg += f" cc={rtp.csrc_count} m={rtp.marker} pt={rtp.payload_type}"
            msg += f" seq={rtp.sequence_no} ts={rtp.timestamp} ssrc={rtp.ssrc}"
            self.audio_file_logger.debug(msg)

    def process(self, rtp):
        data = self.decrypt(rtp)
        if isinstance(rtp, RTP_REALTIME) and rtp.hasredundancy:
            # rtp.payloads tuple: type, ts_offset (samples ago), length
            # Set data to start at last block (add all lengths), skip redundancy for now.
            data = data[reduce(add, [row[-1] for row in rtp.block_list]):]
        packet = av.packet.Packet(data)
        if(len(data) > 0):
            try:
                for frame in self.codecContext.decode(packet):
                    frame = self.resampler.resample(frame)
                    return frame.planes[0].to_bytes()
            except ValueError as e:
                self.audio_screen_logger.error(repr(e))
                pass  # noqa

    def run(self, rcvr_cmd_pipe, control_conns):
        # This pipe is between player (read data) and server (write data)
        here, there = multiprocessing.Pipe()
        if control_conns:
            control_recv, control_send = control_conns
        else:
            control_recv, control_send = None, None

        server_thread = threading.Thread(target=self.serve, args=(there, control_recv, control_send))
        player_thread = threading.Thread(target=self.play, args=(rcvr_cmd_pipe, here))

        server_thread.start()
        player_thread.start()

    def msec_to_playout(self, rtp_ts):
        """
        msec until intended playout of RTP packet with timestamp rtp_ts
        """
        if not self.anchorRTPTimestamp:
            return 0
        rtp_ts_diff = rtp_ts - self.anchorRTPTimestamp
        millis_to_anchor = int((time.monotonic_ns() - self.anchorMonotonicNanosLocal) * 1e-6)
        return int(1000 * rtp_ts_diff / self.sample_rate) - millis_to_anchor

    def msec_to_playout_with_outdev_delay(self, rtp_ts):
        return int(self.msec_to_playout(rtp_ts) - ((self.sample_delay * 1e3)))

    def samples_elapsed_since_anchor(self):
        realtime_offset_sec = (time.monotonic_ns() - self.anchorMonotonicNanosLocal) * 1e-9
        samples_to_playhead = self.anchorRTPTimestamp + realtime_offset_sec * self.sample_rate
        return samples_to_playhead

    @classmethod
    def spawn(
            cls,
            addr,
            session_key, iv=None,
            audio_format=0, buff_size=None,
            spf=1024,
            streamtype=0,
            control_conns=None,
            isDebug=False,
            aud_params: AudioSetup = None,
    ):
        audio = cls(
            addr,
            session_key, iv,
            audio_format, buff_size,
            spf,
            streamtype,
            control_conns,
            isDebug,
            aud_params,
        )
        # This pipe is reachable from receiver
        rcvr_cmd_pipe, audio.command_chan = multiprocessing.Pipe()
        audio_proc = multiprocessing.Process(target=audio.run, args=(rcvr_cmd_pipe, control_conns))
        audio_proc.start()

        return audio_proc, audio.command_chan


class AudioRealtime(Audio):
    """
    Realtime needs at least a few packets in the buffer to handle jitter.
    """
    def __init__(
            self,
            addr,
            session_key, iv,
            audio_format, buff_size,
            spf,
            streamtype,
            control_conns=None,
            isDebug=False,
            aud_params: AudioSetup = None
    ):
        super(AudioRealtime, self).__init__(
            addr,
            session_key, iv,
            audio_format, buff_size,
            spf,
            streamtype,
            control_conns,
            isDebug,
            aud_params
        )
        self.isDebug = isDebug
        self.socket = get_free_socket() if not addr else addr
        self.port = self.socket.getsockname()[1]
        self.rtp_buffer = RTPRealtimeBuffer(buff_size, self.isDebug)
        self.anchorRTPTimestamp = None

    def fini_audio_sink(self):
        self.sink.close()
        self.pa.terminate()

    def serve(self, serverconn, control_recv, control_send):
        while True:
            if control_recv:
                rtsp = control_recv.get()
                if rtsp:
                    # update local variables
                    self.senderRtpTimestamp, self.playAtRtpTimestamp = rtsp.getRtpTimesAtSender()
                    """
                    self.audio_screen_logger.debug((
                        f'audio got senderRtpTimestamp:{self.senderRtpTimestamp}'
                        f'; playAtRtpTimestamp:{self.playAtRtpTimestamp}'
                    ))
                    """
                    # If remoteClockId is None, we're in NTP mode
                    self.remoteClockMonotonic_ts, self.remoteClockId = rtsp.getClockAtSender()
                    """
                    self.audio_screen_logger.debug((
                        f'audio got remoteMonotonic:{self.remoteClockMonotonic_ts}'
                        f'; remoteClockId:{self.remoteClockId}'
                    ))
                    """

            if self.rtp_buffer.gaps_exist():
                for missing_seq in self.rtp_buffer.missing_sequence_nos():
                    # Each missing_seq is a tuple: (Seq#, amount_following)
                    self.audio_screen_logger.debug(
                        f'requesting resend of sequence_no {missing_seq[0]}; amt {missing_seq[1]}'
                    )
                    # request resend via control channel here
                    """ syntax:
                    resend_{missing_seq_no_start}/{amount_following}/{optional_timestamp}
                    """
                    control_send.put(f'resend_{missing_seq[0]}/{missing_seq[1]}/{0}')

            # Wake every ~fifth packet
            time.sleep((self.spf / self.sample_rate) * 5)

    def play(self, rtspconn, serverconn):
        self.init_audio_sink()
        RTP_SEQ_SIZE = 2**16
        RTP_ROLLOVER = RTP_SEQ_SIZE - 1  # 65535
        lastRecvdSeqNo = 0
        lastPlayedSeqNo = 0
        playing = False
        starting = True
        one_pkt = (self.spf / self.sample_rate) * 1e3
        p_write_avg = deque(maxlen=20)
        p_write = p_write_a = None

        try:
            while True:

                if rtspconn.poll(0):
                    message = rtspconn.recv()
                    if str.startswith(message, "flush_seq_rtptime"):
                        flush_seq, self.anchorRTPTimestamp = map(int, str.split(message, "-")[-2:])
                        self.rtp_buffer.flush(flush_seq)
                        starting = True
                        playing = False
                    elif str.startswith(message, "progress"):
                        startTS, currentTS, stopTS = map(int, str.split(message, "-")[-1:][0].split('/'))

                data, address = self.socket.recvfrom(2048)
                if data:
                    pkt = RTP_REALTIME(data)
                    lastRecvdSeqNo = pkt.sequence_no
                    self.log(pkt)
                    self.rtp_buffer.append(pkt)
                """ realtime can get crunchy. Let it fill. """
                if (
                    self.rtp_buffer.is_full()  # or amount() > 0.x
                ):
                    try:
                        if playing:
                            rtp = self.rtp_buffer.pop((lastPlayedSeqNo + 1) % RTP_SEQ_SIZE)
                        else:
                            rtp = self.rtp_buffer.pop(0)
                            if starting:
                                self.anchorMonotonicNanosLocal = time.monotonic_ns()
                                starting = False

                        if rtp:
                            if p_write_a:
                                delay = self.msec_to_playout(rtp.timestamp) - p_write_a
                                """
                                if p_write > one_pkt:
                                    print(f'excessive audio write times:{p_write:3.3} msec')
                                print(f'd{self.msec_to_playout(rtp.timestamp):4}; pw:{p_write:3.3} ; combo;{delay:3.3}', end='\r', flush=False)
                                """
                                ''' # comment this out to enable relative sync
                                if delay < ((2 * -one_pkt)):
                                    """ What to do here depends on the receiver performance. 'continue' too often can sound crunchy.
                                    dont skip frames and the playout lags behind. This is an unbuffered approach. WiFi also affects. """
                                    continue
                                '''  # comment this out to enable relative sync
                                if delay - 2 > 3:
                                    time.sleep((delay - 2) * 1e-3)

                                if rtp.sequence_no % 20 == 0:
                                    print(f'playout offset: {delay:+3.2} msec (relative to self)     ', end='\r', flush=False)

                            audio = self.process(rtp)

                            if(audio):
                                pre_write = time.monotonic_ns()
                                self.sink.write(audio)
                                lastPlayedSeqNo = rtp.sequence_no
                                post_write = time.monotonic_ns()
                                p_write = (post_write - pre_write) * 1e-6
                                p_write_avg.append(p_write)
                                p_write_a = sum(p_write_avg) / len(p_write_avg)

                                playing = True
                        else:
                            playing = False

                    except (RecursionError, TypeError) as e:
                        self.audio_screen_logger.error(repr(e))
                        playing = False

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
            spf=1024,
            streamtype=0,
            control_conns=None,
            isDebug=False,
            aud_params: AudioSetup = None
    ):
        super(AudioBuffered, self).__init__(
            addr,
            session_key, iv,
            audio_format, buff_size,
            spf,
            streamtype,
            control_conns,
            isDebug,
            aud_params,
        )
        self.isDebug = isDebug

        self.socket = get_free_socket(addr, tcp=True) if not addr else addr
        self.port = self.socket.getsockname()[1]
        self.control_conns = control_conns

        self.anchorMonotonicNanosLocal = None  # local play start time in nanos
        self.rtp_buffer = RTPRealtimeBuffer(buff_size, self.isDebug)
        # RTP timestamp of where the play start anchor is
        self.anchorRTPTimestamp = None

    # player plays
    def play(self, rtspconn, serverconn):
        playing = False
        buffer_ready = False
        p_write_avg = deque(maxlen=20)
        p_write = p_write_a = None
        pkt_time_one = ((self.spf / self.sample_rate) * 1e3)
        synced = True

        i = 0
        while True:
            if not playing:
                rtsp_cmd_receiver_timeout = None
            else:
                rtsp_cmd_receiver_timeout = 0
            if not synced:
                rtp_server_wait_timeout = None
            else:
                rtp_server_wait_timeout = 0

            if not self.rtp_buffer.is_empty():
                buffer_ready = True

            if serverconn.poll(rtp_server_wait_timeout):
                message = serverconn.recv()

                if message == "buffer_ready":
                    buffer_ready = True
                elif message == "synced_response":
                    self.audio_screen_logger.info("playback: align playhead response received")
                    ts = self.samples_elapsed_since_anchor()
                    self.audio_screen_logger.info(f"playback: forwarding to timestamp {ts}")
                    self.rtp_buffer.flush(ts)
                    synced = True

            if rtspconn.poll(rtsp_cmd_receiver_timeout):
                try:
                    message = rtspconn.recv()
                    if isinstance(message, str):
                        if str.startswith(message, "play"):
                            self.anchorMonotonicNanosLocal = time.monotonic_ns()
                            self.anchorRTPTimestamp = int(str.split(message, "-")[1])
                            playing = True

                        elif message == "pause":
                            playing = False
                            buffer_ready = False

                        elif str.startswith(message, "flush_from_until_seq"):
                            flush_from, flush_to = map(int, str.split(message, "-")[-2:])
                            serverconn.send(message)
                            playing = False

                except (OSError, EOFError, BrokenPipeError) as e:
                    pass
                except (IndexError, ValueError):
                    pass  # unrecognized message passed

            if playing and buffer_ready:
                rtp = self.rtp_buffer.pop()
                if rtp:
                    if p_write_a:
                        msec_to_playout = self.msec_to_playout(rtp.timestamp) - p_write_a
                        if i % 1000 == 0:
                            self.audio_screen_logger.info(f"playback: offset is {msec_to_playout:+3.2} msec")

                        if i % 20 == 0:
                            print(f'playout offset: {msec_to_playout:+3.2} msec (relative to self)     ', end='\r', flush=False)

                        if msec_to_playout > 0:
                            time.sleep((msec_to_playout) * 10**-3)
                            msec_to_playout = self.msec_to_playout(rtp.timestamp) - p_write_a

                        if msec_to_playout < -pkt_time_one:
                            self.rtp_buffer.pop()
                            msec_to_playout = self.msec_to_playout(rtp.timestamp) - p_write_a

                    pre_proc = time.monotonic_ns()
                    audio = self.process(rtp)

                    if audio:
                        self.sink.write(audio)
                        post_proc = time.monotonic_ns()
                        p_write = post_proc - pre_proc
                        p_write_avg.append(p_write * 1e-6)
                        p_write_a = sum(p_write_avg) / len(p_write_avg)

                        i += 1

    # server fills the buffer, and admits packets within desired timestamp ranges.
    def serve(self, playerconn, control_recv, control_send):
        self.init_audio_sink()

        conn, addr = self.socket.accept()
        flush_until = None
        need_newer_data = False
        try:
            while True:
                try:
                    while playerconn.poll():
                        message = playerconn.recv()
                        if str.startswith(message, "flush_from_until_seq"):
                            self.audio_screen_logger.info(f"server: player requested flush: {message}")
                            flush_from, flush_until = map(int, str.split(message, "-")[-2:])
                            self.rtp_buffer.flush(flush_until)
                        elif message == "on_time_data_request":
                            self.audio_screen_logger.debug("server: ontime data request received")
                            need_newer_data = True
                except EOFError as e:
                    self.audio_screen_logger.error(repr(e))

                # Receive RTP packets from the TCP stream:
                message = conn.recv(2, socket.MSG_WAITALL)
                if message:
                    # Each RTP packet is preceeded by a uint16 of its size
                    data_len = int.from_bytes(message, byteorder='big')
                    # Then the RTP packet:
                    data = conn.recv(data_len - 2, socket.MSG_WAITALL)

                    rtp = RTP_BUFFERED(data)
                    self.log(rtp)
                    msec_to_playout = self.msec_to_playout_with_outdev_delay(rtp.timestamp)
                    if not flush_until:
                        self.rtp_buffer.append(rtp)
                    else:

                        msg = f"server: searching sequence {flush_until} -"
                        msg += f" current is {rtp.sequence_no}"
                        self.audio_screen_logger.debug(msg)
                        # only admit data newer than our jump target
                        if rtp.sequence_no > flush_until:
                            if flush_from == 0:
                                self.audio_screen_logger.debug("server: buffer init")
                                self.rtp_buffer.clear()
                            self.rtp_buffer.append(rtp)
                            flush_until = None
                            playerconn.send("buffer_ready")
                    if need_newer_data:
                        if abs(msec_to_playout) >= 1e2:
                            need_newer_data = False
                            playerconn.send("synced_response")

        except KeyboardInterrupt:
            pass
        finally:
            conn.close()
            self.socket.close()
