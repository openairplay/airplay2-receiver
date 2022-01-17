import socket
import struct
import multiprocessing

from ..utils import get_file_logger, get_free_port


class RTCP:

    TIME_ANNOUNCE = 215

    def __init__(self, data):
        self.version = (data[0] & 0b11000000) >> 6
        self.padding = (data[0] & 0b00100000) >> 5
        self.count = data[0] & 0b00011111
        self.ptype = data[1]
        self.plen = ((data[3] | data[2] << 8) + 1) * 4
        self.syncs = 0

        if self.ptype == RTCP.TIME_ANNOUNCE:
            self.rtpTimeRemote = struct.unpack(">I", data[4:8])[0]
            self.net = struct.unpack(">Q", data[8:16])[0] / 10**9
            self.rtpTime = struct.unpack(">I", data[16:20])[0]
            self.net_base = struct.unpack(">Q", data[20:28])[0]


class Control:
    def __init__(self, isDebug=False):
        self.isDebug = isDebug
        self.port = get_free_port()

    def handle(self, rtcp):
        if self.isDebug:
            if rtcp.ptype == RTCP.TIME_ANNOUNCE:
                msg = f"Time announce (215): rtpTimeRemote={rtcp.rtpTimeRemote}"
                msg += f" rtpTime={rtcp.rtpTime} net={rtcp.net:1.7f} ({rtcp.net_base})"
                self.logger.debug(msg)
            else:
                msg = f"vs={rtcp.version} pad={rtcp.padding} cn={rtcp.count}"
                msg += f" type={rtcp.ptype} len={rtcp.plen}"
                self.logger.debug(msg)

    def serve(self):
        try:
            if self.isDebug:
                self.logger = get_file_logger("control", level="DEBUG")
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            addr = ("0.0.0.0", self.port)
            sock.bind(addr)
            while True:
                data, address = sock.recvfrom(4096)
                if data:
                    rtcp = RTCP(data)
                    self.handle(rtcp)
        except KeyboardInterrupt:
            pass
        except OSError as e:
            self.logger.error(f'{repr(e)}')
        finally:
            sock.close()

    @staticmethod
    def spawn(isDebug):
        control = Control(isDebug=False)
        p = multiprocessing.Process(target=control.serve)
        p.start()
        return control.port, p
