import os
import sys
import time
import struct
import socket
import argparse
import tempfile
import multiprocessing

import pprint

import http.server
import socketserver

import pyaudio
import netifaces as ni
from hexdump import hexdump
from Crypto.Cipher import ChaCha20_Poly1305, AES
from zeroconf import IPVersion, ServiceInfo, Zeroconf
from biplist import readPlistFromString, writePlistToString

from libalac import *

FEATURES = 2255099430193664
FEATURES ^= (1 << 14) # FairPlay auth not really needed in this weird situation

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
HTTP_CT_IMAGE = "image/jpeg"
HTTP_CT_DMAP = "application/x-dmap-tagged"

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
        'statusFlags': 4,
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
        print(self.headers)
        if self.path == "/info":
            print("GET /info")
            self.handle_info()
        else:
            print("GET %s Not implemented!" % self.path)
            self.send_error(404)

    def do_POST(self):
        print(self.headers)
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
        print(self.headers)
        if self.headers["Content-Type"] == HTTP_CT_BPLIST:
            content_len = int(self.headers["Content-Length"])
            if content_len > 0:
                body = self.rfile.read(content_len)
                hexdump(body)
                plist = readPlistFromString(body)
                self.pp.pprint(plist)
                if "streams" not in plist:
                    print("Sending EVENT:")
                    sonos_one_setup["eventPort"] = EVENT_PORT

                    self.server.queue_aes.put(plist["eiv"])
                    self.server.queue_aes.put(plist["ekey"])
                    print("EKEY=%d EIV=%d" % (len(plist["eiv"]), len(plist["eiv"])))
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
                    self.server.queue_aes.put(plist["streams"][0]["shk"])
                    print("SHK=%d" % (len(plist["streams"][0]["shk"])))
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
            hexdump(body)
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
        content_type = self.headers["Content-Type"]
        content_len = int(self.headers["Content-Length"])
        if content_type == HTTP_CT_PARAM:
            if content_len > 0:
                body = self.rfile.read(content_len)
                hexdump(body)
                params = body.splitlines()
                for p in params:
                    pp = p.split(b":")
                    if pp[0] in [b"volume", b"progress"]:
                        print("SET_PARAMETER: %s => %s" % (pp[0], pp[1]))
                    else:
                        print("Ops SET_PARAMETER: %s" % p)
        elif content_type == HTTP_CT_IMAGE:
            if content_len > 0:
                fname = None
                with tempfile.NamedTemporaryFile(prefix="artwork", dir=".", delete=False) as f:
                    f.write(self.rfile.read(content_len))
                    fname = f.name
                print("Artwork saved to %s" % fname)
        elif content_type == HTTP_CT_DMAP:
            if content_len > 0:
                self.rfile.read(content_len)
                print("Now plaing DAAP info. (need a daap parser here)")
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
                hexdump(body)
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
                hexdump(body)
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
            hexdump(body)
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
        if self.headers["Content-Type"] == HTTP_CT_BPLIST:
            content_len = int(self.headers["Content-Length"])
            if content_len > 0:
                body = self.rfile.read(content_len)
                hexdump(body)
                plist = readPlistFromString(body)
                newin = []
                if "mrSupportedCommandsFromSender" in plist["params"]:
                    for p in plist["params"]["mrSupportedCommandsFromSender"]:
                        iplist = readPlistFromString(p)
                        newin.append(iplist)
                    plist["params"]["mrSupportedCommandsFromSender"] = newin
                if "params" in plist["params"] and "kMRMediaRemoteNowPlayingInfoArtworkData" in plist["params"]["params"]:
                    plist["params"]["params"]["kMRMediaRemoteNowPlayingInfoArtworkData"] = "<redacted ..too long>"
                self.pp.pprint(plist)
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def handle_feedback(self):
        if self.headers["Content-Type"] == HTTP_CT_BPLIST:
            content_len = int(self.headers["Content-Length"])
            if content_len > 0:
                body = self.rfile.read(content_len)
                hexdump(body)
                plist = readPlistFromString(body)
                self.pp.pprint(plist)
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def handle_audiomode(self):
        if self.headers["Content-Type"] == HTTP_CT_BPLIST:
            content_len = int(self.headers["Content-Length"])
            if content_len > 0:
                body = self.rfile.read(content_len)
                hexdump(body)
                plist = readPlistFromString(body)
                self.pp.pprint(plist)
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def handle_info(self):
        if "Content-Type" in self.headers:
            if self.headers["Content-Type"] == HTTP_CT_BPLIST:
                content_len = int(self.headers["Content-Length"])
                if content_len > 0:
                    body = self.rfile.read(content_len)
                    hexdump(body)
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
    def decrypt(data, key, nonce, tag, aad):
        c = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        c.update(aad)
        data = c.decrypt_and_verify(data, tag)
        return data

    def process_packet(data, key):
        aad = data[4:12]
        nonce = data[-8:]
        tag = data[-24:-8]
        payload = data[12:-24]
        plain = decrypt(payload, key, nonce, tag, aad)
        err, decoded = libalac_decode_frame(plain)
        return decoded

    def parse_data(f, data):
        version = (data[0] & 0b11000000) >> 6
        padding = (data[0] & 0b00100000) >> 5
        extension = (data[0] & 0b00010000) >> 4
        csrc_count = data[0] & 0b00001111
        marker = (data[1] & 0b10000000) >> 7
        payload_type = data[1] & 0b01111111
        sequence_no = struct.unpack(">H", data[2:4])[0]
        timestamp = struct.unpack(">I", data[4:8])[0]
        ssrc = struct.unpack(">I", data[8:12])[0]
        # nonce = data[-8:]
        # tag = data[-24:-8]
        # aad = data[4:12]

        f.write(b"v=%d p=%d x=%d cc=%d m=%d pt=%d seq=%d ts=%d ssrc=%d len=%d\n" % (version, padding,
             extension, csrc_count,
             marker, payload_type,
             sequence_no, timestamp,
             ssrc, len(data)))
        # payload = data[12:-24]
        # plain = decrypt(payload, key, nonce, tag, aad)
        # err, decoded = libalac_decode_frame(plain)
        # f.write(res.encode()+b"\n")

    try:
        iv = queue.get()
        key = queue.get()
        shk = queue.get()
    except KeyboardInterrupt:
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    addr = ("0.0.0.0", port)
    sock.bind(addr)

    with open("data.txt", "wb", buffering=0) as f:
        res = libalac_init()
        f.write(b"libalac_init=%d\n" % res)
        pa = pyaudio.PyAudio()
        stream = pa.open(format=pa.get_format_from_width(2),
                         channels=2,
                         rate=44100,
                         output=True)
        try:
            while True:
                data, address = sock.recvfrom(4096)
                if data:
                    # parse_data(f, data)
                    audio = process_packet(data, shk)
                    stream.write(audio)
        except KeyboardInterrupt:
            pass
        except Exception as e:
            f.write(e)
        finally:
            sock.close()
            stream.close()
            pa.terminate()
            libalac_terminate()

def spawn_data_server(q):
    port = get_free_port()
    p = multiprocessing.Process(target=data_server, args=(port, q))
    p.start()
    return port, p

def control_server(port):
    def parse_data(f, data):
        version = (data[0] & 0b11000000) >> 6
        padding = (data[0] & 0b00100000) >> 5
        count = data[0] & 0b00011111
        ptype = data[1]
        plen = ((data[3] | data[2] << 8) + 1) * 4

        if ptype == 215:
            rtpTimeRemote = struct.unpack(">I", data[4:8])[0]
            net = struct.unpack(">Q", data[8:16])[0] / 10**9
            rtpTime = struct.unpack(">I", data[16:20])[0]
            net_base = struct.unpack(">Q", data[20:28])[0]
            f.write(b"vs=%d pad=%d cn=%d type=%d len=%d plen=%d\n" % (version, padding, count, ptype, plen,  len(data)))
            f.write(b"    Time announce (215): rtpTimeRemote=%d rtpTime=%d net=%1.7f (%d)\n" % (rtpTimeRemote, rtpTime, net, net_base))
        else:
            f.write(b"vs=%d pad=%d cn=%d type=%d len=%d ssync=%d plen=%d\n" % (version, padding, count, ptype, plen, syncs, len(data)))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    addr = ("0.0.0.0", port)
    sock.bind(addr)

    with open("control.txt", "wb", buffering=0) as f:
        try:
            while True:
                data, address = sock.recvfrom(4096)
                if data:
                    parse_data(f, data)
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
