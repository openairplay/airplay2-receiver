import os
import sys
import time
import struct
import socket
import argparse
import multiprocessing

import pprint

import http.server
import socketserver

import netifaces as ni
from zeroconf import IPVersion, ServiceInfo, Zeroconf

from biplist import readPlistFromString, writePlistToString

from Crypto.Cipher import AES

FEATURES = 2255099430193664

try: #en7 USB interface
    ifen = ni.ifaddresses("en7")
    IFEN = "en7"
except ValueError:
    ifen = ni.ifaddresses("en0")
    IFEN = "en0"

DEVICE_ID = ifen[ni.AF_LINK][0]["addr"]
IPV4 = ifen[ni.AF_INET][0]["addr"]
IPV6 = ifen[ni.AF_INET6][0]["addr"].split("%")[0]

SERVER_VERSION = "366.0"
HTTP_CT_BPLIST = "application/x-apple-binary-plist"
HTTP_CT_PARAM = "text/parameters"

def setup_global_structs(args):
    global EVENT_PORT
    global DATA_PORT
    global CONTROL_PORT
    global sonos_one_info
    global sonos_one_setup
    global sonos_one_setup_data
    global second_stage_info
    global mdns_props

    EVENT_PORT= args.event_port
    DATA_PORT = args.data_port
    CONTROL_PORT = args.control_port

    sonos_one_info = {
        # 'OSInfo': 'Linux 3.10.53',
        # 'PTPInfo': 'OpenAVNU ArtAndLogic-aPTP-changes a5d7f94-0.0.1',
        'audioLatencies': [   {   'inputLatencyMicros': 0,
                                  'outputLatencyMicros': 400000,
                                  'type': 100},
                              {   'audioType': 'default',
                                  'inputLatencyMicros': 0,
                                  'outputLatencyMicros': 400000,
                                  'type': 100},
                              {   'audioType': 'media',
                                  'inputLatencyMicros': 0,
                                  'outputLatencyMicros': 400000,
                                  'type': 100},
                              {   'audioType': 'media',
                                  'inputLatencyMicros': 0,
                                  'outputLatencyMicros': 400000,
                                  'type': 102}],
        # 'build': '16.0',
        'deviceID': DEVICE_ID,
        'features': FEATURES,
        # 'features': 496155769145856, # Sonos One
        # 'firmwareBuildDate': 'Nov  5 2019',
        # 'firmwareRevision': '53.3-71050',
        # 'hardwareRevision': '1.21.1.8-2',
        'keepAliveLowPower': True,
        'keepAliveSendStatsAsBody': True,
        'manufacturer': 'Sonos',
        'model': 'One',
        'name': 'Camera da letto',
        'nameIsFactoryDefault': False,
        'pi': 'ba5cb8df-7f14-4249-901a-5e748ce57a93', # UUID generated casually..
        'protocolVersion': '1.1',
        'sdk': 'AirPlay;2.0.2',
        'sourceVersion': '366.0',
        'statusFlags': 4
        # 'statusFlags': 0x404 # Sonos One
        }

    second_stage_info = {
        "initialVolume": -130,
        }

    sonos_one_setup = {
            'eventPort': EVENT_PORT,  # AP2 receiver event server
            'timingPort': 0,
            'timingPeerInfo': {
                'Addresses': [
                    IPV4, IPV6], 
                'ID': IPV4}
            }

    sonos_one_setup_data = {
            'streams': [
                {
                    'type': 96, 
                    'dataPort': DATA_PORT, # AP2 receiver data server 
                    'controlPort': CONTROL_PORT # AP2 receiver control server
                    }
                ]
            }

    mdns_props = {
            "srcvers": SERVER_VERSION,
            "deviceid": DEVICE_ID,
            "features": "%s,%s" % (hex(FEATURES & 0xffffffff), hex(FEATURES >> 32 & 0xffffffff)),
            "flags": "0x4",
            # "name": "GINO", # random
            # "model": "GIO", # random
            # "manufacturer": "Pino", # random
            # "serialNumber": "01234xX321", # random
            "protovers": "1.1",
            "acl": "0",
            "rsf": "0x0",
            "fv": "p20.78000.12",
            "pi": "5dccfd20-b166-49cc-a593-6abd5f724ddb", # UUID generated casually
            "gid": "5dccfd20-b166-49cc-a593-6abd5f724ddb", # UUID generated casually
            "gcgl": "0",
            # "vn": "65537",
            # "pk": "de352b0df39042e201d31564049023af58a106c6d904b74a68aa65012852997f",
            }

class AP2RTSP(http.server.BaseHTTPRequestHandler):

    pp = pprint.PrettyPrinter()

    def parse_request(self):
        self.raw_requestline = self.raw_requestline.replace(b"RTSP/1.0", b"HTTP/1.1")

        r = http.server.BaseHTTPRequestHandler.parse_request(self)
        self.protocol_version = "RTSP/1.0"
        self.close_connection = 0
        return r

    def send_response(self, code, message=None):
        if message is None:
            if code in self.responses:
                message = self.responses[code][0]
            else:
                message = b''

        response = "%s %d %s\r\n" % (self.protocol_version, code, message)
        self.wfile.write(response.encode())

    def version_string(self):
        return "AirTunes/%s" % SERVER_VERSION

    def do_GET(self):
        if self.path == "/info":
            print("GET /info")
            self.handle_info()
        else:
            print("GET %s Not implemented!" % self.path)
            self.send_error(404)

    def do_POST(self):
        print(self.path)
        if self.path == "/command":
            print("POST /command")
            self.handle_command()
        elif self.path == "/feedback":
            print("POST /feedback")
            self.handle_feedback()
        elif self.path == "/audioMode":
            print("POST /audioMode")
            self.handle_audiomode()
        else:
            print("POST %s Not implemented!" % self.path)
            self.send_error(404)

    def do_SETUP(self):
        dacp_id = self.headers.get("DACP-ID")
        active_remote = self.headers.get("Active-Remote")
        ua = self.headers.get("User-Agent")
        print("SETUP %s" % self.path)
        if self.headers["Content-Type"] == HTTP_CT_BPLIST:
            content_len = int(self.headers["Content-Length"])
            if content_len > 0:
                body = self.rfile.read(content_len)
                plist = readPlistFromString(body)
                self.pp.pprint(plist)
                if "streams" not in plist:
                    print("Sending EVENT:")
                    sonos_one_setup["eventPort"] = EVENT_PORT

                    self.server.queue_aes.put(plist["eiv"])
                    self.server.queue_aes.put(plist["ekey"])

                    self.pp.pprint(sonos_one_setup)
                    res = writePlistToString(sonos_one_setup)
                    self.send_response(200)
                    self.send_header("Content-Length", len(res))
                    self.send_header("Content-Type", HTTP_CT_BPLIST)
                    self.send_header("Server", self.version_string())
                    self.send_header("CSeq", self.headers["CSeq"])
                    self.end_headers()
                    self.wfile.write(res)
                else:
                    print("Sending CONTROL/DATA:")
                    sonos_one_setup_data["streams"][0]["controlPort"] = CONTROL_PORT
                    sonos_one_setup_data["streams"][0]["dataPort"] = DATA_PORT
                    
                    self.pp.pprint(sonos_one_setup_data)
                    res = writePlistToString(sonos_one_setup_data)

                    self.send_response(200)
                    self.send_header("Content-Length", len(res))
                    self.send_header("Content-Type", HTTP_CT_BPLIST)
                    self.send_header("Server", self.version_string())
                    self.send_header("CSeq", self.headers["CSeq"])
                    self.end_headers()
                    self.wfile.write(res)
                return
        self.send_error(404)

    def do_GET_PARAMETER(self):
        print("GET_PARAMETER %s" % self.path)
        print(self.headers)
        params_res = {}
        content_len = int(self.headers["Content-Length"])
        if content_len > 0:
            body = self.rfile.read(content_len)
            params = body.splitlines()
            for p in params:
                if p == b"volume":
                    print("GET_PARAMETER: %s" % p)
                    params_res[p] = b"-144"
                else:
                    print("Ops GET_PARAMETER: %s" % p)

        res = b"\r\n".join(b"%s: %s" % (k, v) for k, v in params_res.items()) + b"\r\n"
        self.send_response(200)
        self.send_header("Content-Length", len(res))
        self.send_header("Content-Type", HTTP_CT_PARAM)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()
        self.wfile.write(res)

    def do_SET_PARAMETER(self):
        print("SET_PARAMETER %s" % self.path)
        print(self.headers)
        params_res = {}
        content_len = int(self.headers["Content-Length"])
        if content_len > 0:
            body = self.rfile.read(content_len)
            params = body.splitlines()
            for p in params:
                pp = p.split(b":")
                if pp[0] == b"volume":
                    print("SET_PARAMETER: %s => %s" % (pp[0], pp[1]))
                else:
                    print("Ops SET_PARAMETER: %s" % p)

        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def do_RECORD(self):
        print("RECORD %s" % self.path)
        print(self.headers)
        if self.headers["Content-Type"] == HTTP_CT_BPLIST:
            content_len = int(self.headers["Content-Length"])
            if content_len > 0:
                body = self.rfile.read(content_len)
                plist = readPlistFromString(body)
                self.pp.pprint(plist)
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def do_TEARDOWN(self):
        print("TEARDOWN %s" % self.path)
        print(self.headers)
        if self.headers["Content-Type"] == HTTP_CT_BPLIST:
            content_len = int(self.headers["Content-Length"])
            if content_len > 0:
                body = self.rfile.read(content_len)
                plist = readPlistFromString(body)
                self.pp.pprint(plist)
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def do_SETPEERS(self):
        print("SETPEERS %s" % self.path)
        print(self.headers)
        content_len = int(self.headers["Content-Length"])
        if content_len > 0:
            body = self.rfile.read(content_len)
            plist = readPlistFromString(body)
            self.pp.pprint(plist)
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def do_FLUSH(self):
        print("FLUSH %s" % self.path)
        print(self.headers)
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def handle_command(self):
        print(self.headers)
        if self.headers["Content-Type"] == HTTP_CT_BPLIST:
            content_len = int(self.headers["Content-Length"])
            if content_len > 0:
                body = self.rfile.read(content_len)
                plist = readPlistFromString(body)
                newin = []
                for p in plist["params"]["mrSupportedCommandsFromSender"]:
                    iplist = readPlistFromString(p)
                    newin.append(iplist)
                plist["params"]["mrSupportedCommandsFromSender"] = newin
                self.pp.pprint(plist)
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def handle_feedback(self):
        print(self.headers)
        if self.headers["Content-Type"] == HTTP_CT_BPLIST:
            content_len = int(self.headers["Content-Length"])
            if content_len > 0:
                body = self.rfile.read(content_len)
                plist = readPlistFromString(body)
                self.pp.pprint(plist)
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def handle_audiomode(self):
        print(self.headers)
        if self.headers["Content-Type"] == HTTP_CT_BPLIST:
            content_len = int(self.headers["Content-Length"])
            if content_len > 0:
                body = self.rfile.read(content_len)
                plist = readPlistFromString(body)
                self.pp.pprint(plist)
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def handle_info(self):
        print(self.headers)
        if "Content-Type" in self.headers:
            if self.headers["Content-Type"] == HTTP_CT_BPLIST:
                content_len = int(self.headers["Content-Length"])
                if content_len > 0:
                    body = self.rfile.read(content_len)
                    plist = readPlistFromString(body)
                    self.pp.pprint(plist)
                    if "qualifier" in plist and "txtAirPlay" in plist["qualifier"]:
                        print("Sending:")
                        self.pp.pprint(sonos_one_info)
                        res = writePlistToString(sonos_one_info)

                        self.send_response(200)
                        self.send_header("Content-Length", len(res))
                        self.send_header("Content-Type", HTTP_CT_BPLIST)
                        self.send_header("Server", self.version_string())
                        self.send_header("CSeq", self.headers["CSeq"])
                        self.end_headers()
                        self.wfile.write(res)
                    else:
                        print("No txtAirPlay")
                        self.send_error(404)
                        return
                else:
                    print("No content")
                    self.send_error(404)
                    return
            else:
                print("Content-Type: %s | Not implemented" % self.headers["Content-Type"])
                self.send_error(404)
        else:
            res = writePlistToString(second_stage_info)
            self.send_response(200)
            self.send_header("Content-Length", len(res))
            self.send_header("Content-Type", HTTP_CT_BPLIST)
            self.send_header("Server", self.version_string())
            self.send_header("CSeq", self.headers["CSeq"])
            self.end_headers()
            self.wfile.write(res)

def register_mdns(receiver_name):
    addresses = []
    for ifen in ni.interfaces():
        ifenaddr = ni.ifaddresses(ifen)
        if ni.AF_INET in ifenaddr:
            addresses.append(socket.inet_pton(ni.AF_INET,
                ifenaddr[ni.AF_INET][0]["addr"]))
        if ni.AF_INET6 in ifenaddr:
            addresses.append(socket.inet_pton(ni.AF_INET6,
                ifenaddr[ni.AF_INET6][0]["addr"].split("%")[0]))

    info = ServiceInfo(
            "_airplay._tcp.local.",
            "%s._airplay._tcp.local." % receiver_name,
            # addresses=[socket.inet_aton("127.0.0.1")],
            addresses=addresses,
            port=7000,
            properties=mdns_props,
            server="%s.local." % receiver_name,
            )

    zeroconf = Zeroconf(ip_version=IPVersion.V4Only)
    zeroconf.register_service(info)
    print("mDNS service registered")
    return (zeroconf, info)

def unregister_mdns(zeroconf, info):
    print("Unregistering...")
    zeroconf.unregister_service(info)
    zeroconf.close()


def get_free_port():
    free_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    free_socket.bind(('0.0.0.0', 0))
    free_socket.listen(5)
    port = free_socket.getsockname()[1]
    free_socket.close()
    return port


def event_server(port):
    def parse_data(data):
        pass

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    addr = ("0.0.0.0", port)
    sock.bind(addr)
    sock.listen(1)

    try:
        while True:
            conn, addr = sock.accept()
            try:
                data = conn.recv(4096)
                parse_data(data)
            finally:
                conn.close()
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()

def spawn_event_server():
    port = get_free_port()
    p = multiprocessing.Process(target=event_server, args=(port,))
    p.start()
    return port, p

def data_server(port, queue):

    iv = queue.get()
    key = queue.get()
    cipher = AES.new(key, AES.MODE_CBC, iv)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    addr = ("0.0.0.0", port)
    sock.bind(addr)
    
    with open("dump.bin", "wb") as f:
        try:
            while True:
                data, address = sock.recvfrom(4096)
                if data:
                    plen = len(data)
                    pplen = plen - 12
                    data = data[:pplen]
                    cplen = pplen & ~0xf
                    ddata = cipher.decrypt(data[:cplen])
                    f.write(ddata + data[cplen:])
        except KeyboardInterrupt:
            pass
        except Excetion as e:
            f.write(e)
        finally:
            sock.close()

def spawn_data_server(q):
    port = get_free_port()
    p = multiprocessing.Process(target=data_server, args=(port, q))
    p.start()
    return port, p

def control_server(port):
    def parse_data(data):
        pass

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    addr = ("0.0.0.0", port)
    sock.bind(addr)

    try:
        while True:
            data, address = sock.recvfrom(4096)
            if data:
                parse_data(data)
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()

def spawn_control_server():
    port = get_free_port()
    p = multiprocessing.Process(target=control_server, args=(port,))
    p.start()
    return port, p


if __name__ == "__main__":

    parser = argparse.ArgumentParser(prog='rareport-proto')
    parser.add_argument("-m", "--mdns", required=True, help="mDNS name to announce")
    parser.add_argument("-e", "--event-port", type=int, help="Event port")
    parser.add_argument("-d", "--data-port", type=int,  help="Data port")
    parser.add_argument("-c", "--control-port", type=int, help="Control port")
    args = parser.parse_args()

    setup_global_structs(args)

    queue_aes = multiprocessing.Queue()

    if not args.event_port:
        EVENT_PORT, event_p = spawn_event_server()
    else:
        EVENT_PORT = args.event_port
        event_p = None

    if not args.data_port:
        DATA_PORT, data_p = spawn_data_server(queue_aes)
    else:
        DATA_PORT = args.data_port
        data_p = None

    if not args.control_port:
        CONTROL_PORT, control_p = spawn_control_server()
    else:
        CONTROL_PORT = args.control_port
        control_p = None

    print("Interface: %s" % IFEN)
    print("IPv4: %s" % IPV4)
    print("IPv6: %s" % IPV6)
    print("[TCP] eventPort: %d" % EVENT_PORT)
    print("[UDP] dataPort: %d" % DATA_PORT)
    print("[UDP] controlPort: %d" % CONTROL_PORT)
    print()

    mdns = register_mdns(args.mdns)
    print("Starting RSTP server, press Ctrl-C to exit...")
    try:
        PORT = 7000

        with socketserver.TCPServer(("0.0.0.0", PORT), AP2RTSP) as httpd:
            httpd.queue_aes = queue_aes
            print("serving at port", PORT)
            httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        print("Shutting down mDNS...")
        unregister_mdns(*mdns)

        if event_p:
            print("Shutting down event server...")
            event_p.terminate()
            event_p.join()
        if data_p:
            print("Shutting down data server...")
            data_p.terminate()
            data_p.join()
        if control_p:
            print("Shutting down control server...")
            control_p.terminate()
            control_p.join()
        queue_aes.close()
        queue_aes.join_thread()
