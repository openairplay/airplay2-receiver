import socket
import multiprocessing
import os

from ..utils import get_logger, get_free_port


class Event:
    def __init__(self, addr=None, port=None):
        if port is None:
            self.port = get_free_port()
        else:
            self.port = port
        if addr is not None:
            self.addr, _ = addr
        else:
            self.addr  = "0.0.0.0"
        self.file = "./events.bin"

    def serve(self):
        self.logger = get_logger("event", level="DEBUG")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        addr = (self.addr, self.port)
        sock.bind(addr)
        sock.listen(1)

        try:
            conn, addr = sock.accept()
            self.logger.debug("Connection open from %s:%d" % addr)
            event_file = open(self.file, "wb")
            try:
                while True:
                    data = conn.recv(1)
                    if data:
                        event_file.write(data)
                        pass
            except KeyboardInterrupt:
                pass
            finally:
                try:
                    os.remove(self.file)
                except OSError:
                    pass
                conn.close()
                self.logger.debug("Connection close from %s:%d" % addr)
            sock.close()
        except KeyboardInterrupt:
            pass
        except BrokenPipeError:
            pass
        finally:
            conn.close()
            self.socket.close()

    @staticmethod
    def spawn(addr=None, port=None):
        event = Event(addr, port)
        p = multiprocessing.Process(target=event.serve)
        p.start()
        return event.port, p
