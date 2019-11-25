import os
import sys
import time
import struct
import socket
import argparse

import pprint

import http.server
import socketserver

import netifaces as ni
from zeroconf import IPVersion, ServiceInfo, Zeroconf

from biplist import readPlistFromString, writePlistToString


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
    global mdns_props

    EVENT_PORT= args.event_port
    DATA_PORT = args.data_port
    CONTROL_PORT = args.control_port

    sonos_one_info = {   'OSInfo': 'Linux 3.10.53',
        'PTPInfo': 'OpenAVNU ArtAndLogic-aPTP-changes a5d7f94-0.0.1',
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
        'build': '16.0',
        'deviceID': DEVICE_ID,
        'features': 2255099430193664,
        # 'features': 496155769145856, # Sonos One
        'firmwareBuildDate': 'Nov  5 2019',
        'firmwareRevision': '53.3-71050',
        'hardwareRevision': '1.21.1.8-2',
        'keepAliveLowPower': True,
        'keepAliveSendStatsAsBody': True,
        'manufacturer': 'Sonos',
        'model': 'One',
        'name': 'Camera da letto',
        'nameIsFactoryDefault': False,
        'pi': 'ba5cb8df-7f14-4249-901a-5e748ce57a93', # UUID generated casually..
        # 'pi': 'fe4826f8-c9b1-499f-9972-4449a2682337',
        'protocolVersion': '1.1',
        'sdk': 'AirPlay;2.0.2',
        'sourceVersion': '366.0',
        'statusFlags': 4
        # 'statusFlags': 0x404 # Sonos One
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
            "features": "0x40784a00,0x80300",
            "flags": "0x4",
            "name": "GINO", # random
            "model": "GIO", # random
            "manufacturer": "Pino", # random
            "serialNumber": "01234xX321", # random
            "protovers": "1.1",
            "acl": "0",
            "rsf": "0x0",
            "fv": "p20.78000.12",
            "pi": "5dccfd20-b166-49cc-a593-6abd5f724ddb", # UUID generated casually
            "gid": "5dccfd20-b166-49cc-a593-6abd5f724ddb", # UUID generated casually
            # "pi": "1698df64-e8c9-4e4f-9663-5797ee57dcea",
            # "gid": "1698df64-e8c9-4e4f-9663-5797ee57dcea",
            "gcgl": "0",
            "vn": "65537",
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
                    params_res[p] = b"-10.1"
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
            res = writePlistToString(sonos_one_info)
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


if __name__ == "__main__":

    parser = argparse.ArgumentParser(prog='rareport-proto')
    parser.add_argument("-m", "--mdns", required=True, help="mDNS name to announce")
    parser.add_argument("-e", "--event-port", type=int, required=True, help="Event port")
    parser.add_argument("-d", "--data-port", type=int, required=True, help="Data port")
    parser.add_argument("-c", "--control-port", type=int, required=True, help="Control port")
    args = parser.parse_args()

    setup_global_structs(args)

    print("Interface: %s" % IFEN)
    print("IPv4: %s" % IPV4)
    print("IPv6: %s" % IPV6)
    print("[TCP] eventPort: %d" % EVENT_PORT)
    print("[UDP] dataPort: %d" % DATA_PORT)
    print("[UDP] controlPort: %d" % CONTROL_PORT)
    print()
    input("Open thos ports and press enter when ready...")

    mdns = register_mdns(args.mdns)
    print("Starting RSTP server, press Ctrl-C to exit...")
    try:
        PORT = 7000

        with socketserver.TCPServer(("0.0.0.0", PORT), AP2RTSP) as httpd:
            print("serving at port", PORT)
            httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        print("Shutting down...")
        unregister_mdns(*mdns)

