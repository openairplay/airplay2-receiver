import select
import socket
import struct
import multiprocessing
from queue import Empty
import threading
import time
import enum

from ..utils import get_file_logger, get_free_port, get_free_socket, get_screen_logger


class RTCP:
    """ The packets and logic here let us associate the Receiver and Sender RTP
    timelines so the receiver knows when to present the RTP packets so that
    playback locks to the sender, and multiroom systems play simultaneously.
    It also enables things like accurate jitter and clock-skew calculation.
    """
    class PktType(enum.Enum):
        def __str__(self):
            # so when we enumerate, we only print the msg name w/o class:
            return self.name
        TIME_ANNOUNCE_NTP = 212  # 0xd4
        """ example
        0000   80 d4 00 04 57 20 4d 19 83 ac 0b 7b d0 b1 d4 f9
        0010   57 21 7a 90
        """
        """ example 2 that thinks it is 32 bytes/(7+1) dwords, but isn't (Apple Music app)
        0000   80 d4 00 07 9b 80 b1 ce 83 ae bc 55 25 81 8c 79
        0010   9b 82 0b b7
        """

        REXMIT_REQUEST = 213  # 0xd5
        """ example
        0000   80 d5 00 02 f9 0c 00 03
        """

        REXMIT_RESPONSE = 214  # 0xd6
        """ example
        0000   80 d6 00 91 80 60 f9 0c 0a 8e 05 53 00 00 00 00
        0010   3d 87 87 26 97 35 fe 89 36 30 7b de 0e 3e a7 02
        ...
        """

        TIME_ANNOUNCE_PTP = 215  # 0xd7
        """
        example at start
        0000   90 d7 00 06 21 36 78 19 00 01 a4 03 e3 be 94 b5
        0010   21 37 a5 90 01 02 03 04 05 06 07 08
        example continue
        0000   80 d7 00 06 f3 3b 9d 17 00 01 a2 42 0e 0d 79 fc
        0010   f3 3c ca 8e 01 02 03 04 05 06 07 08
        """

    def __init__(self, data: bytes):
        # RTCP header part common to all types
        self.version = (data[0] & 0b11000000) >> 6
        self.padding = (data[0] & 0b00100000) >> 5
        self.count = data[0] & 0b00011111
        self.ptype = self.PktType(data[1])
        """plen is in dwords, i.e. 32bits. +1 for the dword of header [0:4]"""
        self.plen = (int.from_bytes(data[2:4], byteorder='big') + 1) * 4
        self.syncs = 0

        """ Seen when we set up RT streams using AP2, with PTP"""
        if ((self.ptype == RTCP.PktType.TIME_ANNOUNCE_PTP and self.plen == 28)
           or (self.ptype == RTCP.PktType.TIME_ANNOUNCE_NTP and self.plen == 20)
           or (self.ptype == RTCP.PktType.TIME_ANNOUNCE_NTP and self.plen == 32)):
            # pkt with senderRtpTimestamp is the RTP 'clock' time with the NTP timestamp...
            self.senderRtpTimestamp = int.from_bytes(data[4:8], byteorder='big')
            # ...that should be played when playAtRtpTimestamp occurs
            self.playAtRtpTimestamp = int.from_bytes(data[16:20], byteorder='big')

        """ Seen when we set up RT streams using (AP1 ANNOUNCE method, i.e.) NTP """
        if ((self.ptype == RTCP.PktType.TIME_ANNOUNCE_NTP and self.plen == 20)
           or (self.ptype == RTCP.PktType.TIME_ANNOUNCE_NTP and self.plen == 32)):
            self.ntp_time = self.getNTPTimestamp(data[8:16])

        """Consider the sender bool flag SupportsClockPortMatchingOverride"""
        if self.ptype == RTCP.PktType.TIME_ANNOUNCE_PTP and self.plen == 28:
            """monotonic_ns is the sender's PTP timestamp, i.e. uptime."""
            self.monotonic_ns = int.from_bytes(data[8:16], byteorder='big')
            """clockIdentity is the clockID + port of the currently
                elected PTP GM at the sender
            """
            self.clockIdentity = data[20:28]

        """ weird that we would receive it, but this is the logic """
        if self.ptype == RTCP.PktType.REXMIT_REQUEST:
            """ This is the sequence number of the first missing packet you want """
            self.startSequenceNo = int.from_bytes(data[4:6], byteorder='big')
            """ This is the amount of subsequent missing packets following the start seq"""
            self.subsequentAmount = int.from_bytes(data[6:8], byteorder='big')
            """ This is the optional NTP timestamp (corresponding to above start seq)"""
            self.optionalNTPsecs = int.from_bytes(data[8:12], byteorder='big')
            self.optionalNTPfrac = int.from_bytes(data[12:16], byteorder='big')

        """ In realtime, things don't always work out. So we request a re-send """
        if self.ptype == RTCP.PktType.REXMIT_RESPONSE:
            """ the original packet. forward it to our audio dataport """
            self.originalRTPpacket = data[4:]

    @staticmethod
    def getNTPTimestamp(data: bytes):
        ntp_sec = int.from_bytes(data[0:4], byteorder='big')
        ntp_frac = int.from_bytes(data[4:8], byteorder='big')
        return ntp_sec + ((ntp_frac & 0xffffffff) * 2**-32)

    @staticmethod
    def buildRetransmitRequest(start_seq: int, amount: int, timestamp: int):
        req_length = 16 if timestamp else 8

        data = bytearray(req_length)
        data[0] = 0x80
        data[1] = RTCP.PktType.REXMIT_REQUEST.value
        data[2:4] = int(req_length / 4).to_bytes(length=2, byteorder='big')
        data[4:6] = int(start_seq).to_bytes(length=2, byteorder='big')
        data[6:8] = int(amount).to_bytes(length=2, byteorder='big')
        if timestamp:
            # right shift or *2**-32 to isolate the upper bytes
            data[8:12] = int(timestamp >> 32).to_bytes(length=4, byteorder='big')
            # mask to get lower 32bits. left shift or * 2**32 and then /1000000 to get fraction.
            data[12:16] = (((int(timestamp & 0xffffffff) * 2**32) * 1e-6)).to_bytes(length=4, byteorder='big')
        # pkt built.
        return data

    def getType(self):
        return self.ptype

    def getRtpTimesAtSender(self):
        if ((self.ptype == RTCP.PktType.TIME_ANNOUNCE_PTP and self.plen == 28)
           or (self.ptype == RTCP.PktType.TIME_ANNOUNCE_NTP and self.plen == 20)
           or (self.ptype == RTCP.PktType.TIME_ANNOUNCE_NTP and self.plen == 32)):
            return [self.senderRtpTimestamp, self.playAtRtpTimestamp]

    def getClockAtSender(self):
        if self.ptype == RTCP.PktType.TIME_ANNOUNCE_NTP and self.plen == 20:
            return [self.ntp_time, None]
        elif self.ptype == RTCP.PktType.TIME_ANNOUNCE_NTP and self.plen == 32:
            return [self.ntp_time, None]
        elif self.ptype == RTCP.PktType.TIME_ANNOUNCE_PTP and self.plen == 28:
            return [self.monotonic_ns, self.clockIdentity]

    def getOriginalRtpPkt(self):
        return self.originalRTPpacket

    def isResendResponse(self):
        return self.ptype == RTCP.PktType.REXMIT_RESPONSE


class Control:
    def __init__(
        self,
        controladdr_ours=None,
        dataaddr_ours=None,
        isDebug=False,
    ):
        self.isDebug = isDebug
        assert(isinstance(controladdr_ours, socket.socket) or isinstance(controladdr_ours, None))
        self.controladdr_ours = get_free_socket() if not controladdr_ours else controladdr_ours
        self.controladdr_theirs = None
        assert(isinstance(dataaddr_ours, socket.socket) or isinstance(controladdr_ours, None))
        self.dataaddr_ours = dataaddr_ours

        self.level = 'DEBUG' if self.isDebug else 'INFO'
        self.logname = (
            self.__class__.__name__ + ': '
            + str(self.controladdr_ours.getsockname()[0])
            + ':' + str(self.controladdr_ours.getsockname()[1])
        )
        self.logger = get_screen_logger(self.logname, level=self.level)

    def log(self, rtcp: RTCP):
        if (rtcp.ptype == RTCP.PktType.TIME_ANNOUNCE_PTP or rtcp.ptype == RTCP.PktType.TIME_ANNOUNCE_NTP):
            msg = f"{rtcp.ptype}: senderRtpTimestamp={rtcp.senderRtpTimestamp}"
            if rtcp.ptype == RTCP.PktType.TIME_ANNOUNCE_PTP:
                msg += f" with monotonic_s={rtcp.monotonic_ns * 1e-9:1.7f} clockID={rtcp.clockIdentity.hex()}"
            elif rtcp.ptype == RTCP.PktType.TIME_ANNOUNCE_NTP:
                msg += f" with ntp_time={rtcp.ntp_time:1.7f}"
            msg += f" plays at timestamp={rtcp.playAtRtpTimestamp} "

            self.logger.debug((msg))

        elif rtcp.ptype == RTCP.PktType.REXMIT_RESPONSE:
            pass
        else:
            msg = (
                f"vs={rtcp.version} pad={rtcp.padding} cn={rtcp.count}"
                f" type={rtcp.ptype} len={rtcp.plen}"
            )
            self.logger.debug((msg))

    def commands(self, audio_cmd_recv_q):
        try:
            while self.controladdr_ours:
                try:
                    message = audio_cmd_recv_q.get()
                    if str.startswith(message, "resend_"):
                        startTS, amount, timestamp = map(int, str.split(message, "_")[-1:][0].split('/'))
                        request = RTCP.buildRetransmitRequest(startTS, amount, timestamp)
                        readable, writable, exceptional = select.select([], [self.controladdr_ours], [self.controladdr_ours])
                        for s in writable:
                            if self.controladdr_theirs:
                                try:
                                    # Send rexmit request to <sender control port>.
                                    s.sendto(request, self.controladdr_theirs)
                                except OSError as e:
                                    self.logger.error(f'{repr(e)}')

                except Empty:
                    self.logger.error('audio_cmd_recv_q empty')
                except ValueError as e:
                    self.logger.error(f'{repr(e)}')

        except KeyboardInterrupt:
            pass

    def packet_listen(self, audio_cmd_send_q):
        """ In a thread here, so self.logger is... thread local. But not logname or level. Go figure. """
        self.logger = get_screen_logger(self.logname, level=self.level)

        try:
            while self.controladdr_ours:
                readable, writable, exceptional = select.select([self.controladdr_ours], [], [])
                """ # Log reception time...?
                timenow = time.monotonic_ns()
                """
                for s in readable:
                    data, address = s.recvfrom(4096)
                    self.controladdr_theirs = address if not self.controladdr_theirs else address
                    if data:
                        rtcp = RTCP(data)
                        self.log(rtcp)
                        if rtcp.isResendResponse() and self.dataaddr_ours:
                            # self.logger.debug(f'Rcv retransmission')
                            """ Send rexmit response out from socket to audio listen port"""
                            try:
                                s.sendto(rtcp.getOriginalRtpPkt(), self.dataaddr_ours.getsockname())
                            except OSError as e:
                                self.logger.error(f'{repr(e)}')
                        if rtcp.ptype == RTCP.PktType.TIME_ANNOUNCE_PTP or rtcp.ptype == RTCP.PktType.TIME_ANNOUNCE_NTP:
                            """ Send the received RTCP pkt over to Audio classes """
                            audio_cmd_send_q.put(rtcp)
        except KeyboardInterrupt:
            pass
        except (OSError, ValueError) as e:
            self.logger.error(f'{repr(e)}')
        finally:
            self.controladdr_ours.close()

    def run(self, audio_cmd_send_q, audio_cmd_recv_q):
        # This pipe is between packet_listen_thread (rcv rtcp pkts) and command_thread
        packet_listen_thread = threading.Thread(target=self.packet_listen, args=(audio_cmd_send_q,))
        command_thread = threading.Thread(target=self.commands, args=(audio_cmd_recv_q,))

        packet_listen_thread.start()
        command_thread.start()

    @staticmethod
    def spawn(
        controladdr_ours=None,
        dataaddr_ours=None,
        isDebug=False,
    ):
        control = Control(
            controladdr_ours,
            dataaddr_ours,
            isDebug,
        )
        """ send and recv queues. Two needed to prevent listen and commands
        from eating each others messages to/from audio
        Send q forwards received rtcp objects to audio module.
        Recv q accepts commands back from audio module, e.g. to perform a resend
        """
        audio_cmd_send_q = multiprocessing.SimpleQueue()
        audio_cmd_recv_q = multiprocessing.SimpleQueue()

        p = multiprocessing.Process(target=control.run, args=(audio_cmd_send_q, audio_cmd_recv_q))

        p.start()
        return p, [audio_cmd_send_q, audio_cmd_recv_q]
