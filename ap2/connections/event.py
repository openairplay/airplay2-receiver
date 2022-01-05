import socket
import multiprocessing
import os

from ..utils import get_file_logger, get_free_port


class EventGeneric:
    def __init__(self, addr=None, port=None, name='events', isDebug=False):
        self.name = name
        self.isDebug = isDebug
        if port is None:
            self.port = get_free_port()
        else:
            self.port = port
        if addr is not None:
            self.addr, _ = addr
        else:
            self.addr  = "0.0.0.0"
        self.file = f"./{self.name}.bin"

    def serve(self):
        if self.isDebug:
            self.logger = get_file_logger(self.name, level="DEBUG")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        local_addr_port = (self.addr, self.port)
        sock.bind(local_addr_port)
        sock.listen(1)

        try:
            conn, addr = sock.accept()
            if self.isDebug:
                self.logger.debug(f"Open connection from {addr[0]}:{addr[1]}")
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
                    if self.isDebug:
                        os.remove(self.file)
                except OSError:
                    pass
                conn.close()
                if self.isDebug:
                    self.logger.debug(f"Close connection from {addr[0]}:{addr[1]}")
            sock.close()
        except KeyboardInterrupt:
            pass
        except BrokenPipeError:
            pass
        finally:
            sock.close()
            if self.isDebug:
                self.logger.debug(f"Closed listen on {self.addr}:{self.port}")

    # Note that exit handlers and finally clauses, etc., will not be executed.
    # def terminate(self):
    #     self.logger.debug(f"Close connection to {addr[0]}:{addr[1]}")

    @staticmethod
    def spawn(addr=None, port=None, name='events', isDebug=False):
        event = EventGeneric(addr, port, name, isDebug)
        p = multiprocessing.Process(target=event.serve)
        p.start()
        return event.port, p
