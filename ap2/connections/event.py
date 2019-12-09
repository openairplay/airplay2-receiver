import socket
import multiprocessing

from ..utils import get_logger, get_free_port

class Event:
    def __init__(self):
        self.port = get_free_port()

    def serve(self):
        self.logger = get_logger("event", level="DEBUG")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        addr = ("0.0.0.0", self.port)
        sock.bind(addr)
        sock.listen(1)

        conn, addr = sock.accept()
        self.logger.debug("Connection open from %s:%d" % addr)
        try:
            data = conn.recv(4096)
        except KeyboardInterrupt:
            pass
        finally:
            conn.close()
            self.logger.debug("Connection close from %s:%d" % addr)
        sock.close()

    @staticmethod
    def spawn():
        event = Event()
        p = multiprocessing.Process(target=event.serve)
        p.start()
        return event.port, p
    
