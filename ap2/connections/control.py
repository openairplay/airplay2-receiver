import socket
import struct
import multiprocessing

from ..utils import get_logger, get_free_port


class RTCP:
    TIME_ANNOUNCE = 215

    def __init__(self, data):
        self.version = (data[0] & 0b11000000) >> 6
        self.padding = (data[0] & 0b00100000) >> 5
        self.count = data[0] & 0b00011111
        self.ptype = data[1]
        self.plen = ((data[3] | data[2] << 8) + 1) * 4

        if self.ptype == RTCP.TIME_ANNOUNCE:
            self.rtpTimeRemote = struct.unpack(">I", data[4:8])[0]
            self.net = struct.unpack(">Q", data[8:16])[0] / 10 ** 9
            self.rtpTime = struct.unpack(">I", data[16:20])[0]
            self.net_base = struct.unpack(">Q", data[20:28])[0]


class Control:
    def __init__(self):
        self.port = get_free_port()

    def handle(self, rtcp):
        if rtcp.ptype == RTCP.TIME_ANNOUNCE:
            self.logger.debug("Time announce (215): rtpTimeRemote=%d rtpTime=%d net=%1.7f (%d)" % (
            rtcp.rtpTimeRemote, rtcp.rtpTime, rtcp.net, rtcp.net_base))
        else:
            self.logger.debug("vs=%d pad=%d cn=%d type=%d len=%d ssync=%d" % (
            rtcp.version, rtcp.padding, rtcp.count, rtcp.ptype, rtcp.plen, rtcp.syncs))

    def serve(self):
        self.logger = get_logger("control", level="DEBUG")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        addr = ("0.0.0.0", self.port)
        sock.bind(addr)

        try:
            while True:
                data, address = sock.recvfrom(4096)
                if data:
                    rtcp = RTCP(data)
                    self.handle(rtcp)
        except KeyboardInterrupt:
            pass
        finally:
            sock.close()

    @staticmethod
    def spawn():
        control = Control()
        p = multiprocessing.Process(target=control.serve)
        p.start()
        return control.port, p
