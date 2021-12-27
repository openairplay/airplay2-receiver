import socket
import multiprocessing
import os

from ..utils import get_logger, get_free_port


class NTP:
    def __init__(self, addr=None, port=None):
        if port is None:
            self.port = get_free_port()
        else:
            self.port = port
        if addr is not None:
            self.addr, _ = addr
        else:
            self.addr  = "0.0.0.0"
        self.file = "./NTP.bin"

    def serve(self):
        self.logger = get_logger("ntp", level="DEBUG")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        addr = (self.addr, self.port)
        sock.bind(addr)
        sock.listen(1)

        try:
            conn, addr = sock.accept()
            self.logger.debug("Connection open from %s:%d" % addr)
            # ntp_file = open(self.file, "wb")
            try:
                while True:
                    data = conn.recv(1)
                    if data:
                        pass
                        # ntp_file.write(data)
            except KeyboardInterrupt:
                pass
            finally:
                conn.close()
                self.logger.debug("Connection close from %s:%d" % addr)
                try:
                    os.remove(self.file)
                except OSError:
                    pass

            sock.close()
        except KeyboardInterrupt:
            pass
            # there should be no conn object here...

    @staticmethod
    def spawn(addr=None, port=None):
        ntp = NTP(addr, port)
        p = multiprocessing.Process(target=ntp.serve)
        p.start()
        return ntp.port, p
