#!/usr/bin/env python3
#
# Minimal DNS and CLDAP locator for Windows SSPI Kerberos tests. It does not
# issue Kerberos tickets; it only makes Windows DC locator select the Heimdal
# KDC exposed on localhost by WSL.

import argparse
import ipaddress
import logging
import socket
import socketserver
import struct
import subprocess
import threading
import uuid


TYPE_A = 1
TYPE_SRV = 33
CLASS_IN = 1


def dns_pack_name(name):
    out = bytearray()
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def dns_read_name(data, offset):
    labels = []
    jumped = False
    original = offset
    while True:
        length = data[offset]
        if (length & 0xc0) == 0xc0:
            ptr = ((length & 0x3f) << 8) | data[offset + 1]
            if not jumped:
                original = offset + 2
                jumped = True
            offset = ptr
            continue
        offset += 1
        if length == 0:
            break
        labels.append(data[offset:offset + length].decode("ascii"))
        offset += length
    return ".".join(labels), (original if jumped else offset)


def dns_rr(name, qtype, payload, ttl=300):
    return (
        dns_pack_name(name) +
        struct.pack("!HHIH", qtype, CLASS_IN, ttl, len(payload)) +
        payload
    )


def dns_response(data, server):
    tid, flags, qdcount, _, _, _ = struct.unpack("!HHHHHH", data[:12])
    offset = 12
    questions = []
    answers = []

    for _ in range(qdcount):
        qname, offset = dns_read_name(data, offset)
        qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
        offset += 4
        questions.append(data[12:offset])
        qlower = qname.lower()
        logging.info("DNS %s type %s", qlower, qtype)

        if qclass != CLASS_IN:
            continue
        if qtype == TYPE_A and qlower in server.a_records:
            answers.append(dns_rr(qname, TYPE_A, server.a_records[qlower].packed))
        elif qtype == TYPE_SRV and qlower in server.srv_records:
            target, port = server.srv_records[qlower]
            payload = struct.pack("!HHH", 0, 100, port) + dns_pack_name(target)
            answers.append(dns_rr(qname, TYPE_SRV, payload))

    rcode = 0 if answers else 3
    response = bytearray()
    response.extend(struct.pack(
        "!HHHHHH", tid, 0x8580 | rcode, qdcount, len(answers), 0, 0))
    for question in questions:
        response.extend(question)
    for answer in answers:
        response.extend(answer)
    return bytes(response)


class DnsUdpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(dns_response(data, self.server), self.client_address)


class DnsTcpHandler(socketserver.StreamRequestHandler):
    def handle(self):
        length_raw = self.rfile.read(2)
        if len(length_raw) != 2:
            return
        length = struct.unpack("!H", length_raw)[0]
        data = self.rfile.read(length)
        if len(data) != length:
            return
        response = dns_response(data, self.server)
        self.wfile.write(struct.pack("!H", len(response)) + response)


def ber_len(length):
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def ber(tag, payload):
    return bytes([tag]) + ber_len(len(payload)) + payload


def ber_int(value):
    if value == 0:
        raw = b"\x00"
    else:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
    return ber(0x02, raw)


def ber_octet(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return ber(0x04, value)


def ber_enum(value):
    return ber(0x0a, bytes([value]))


def ber_sequence(payload):
    return ber(0x30, payload)


def ber_set(payload):
    return ber(0x31, payload)


def ber_read_len(data, offset):
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7f
    return int.from_bytes(data[offset:offset + count], "big"), offset + count


def ldap_message_id(data):
    if data[0] != 0x30:
        raise ValueError("LDAP message is not a sequence")
    _, offset = ber_read_len(data, 1)
    if data[offset] != 0x02:
        raise ValueError("LDAP message id is missing")
    length, offset = ber_read_len(data, offset + 1)
    return int.from_bytes(data[offset:offset + length], "big")


DS_FLAGS = (
    0x00000001 |  # PDC
    0x00000004 |  # GC
    0x00000008 |  # LDAP
    0x00000010 |  # DS
    0x00000020 |  # KDC
    0x00000040 |  # TIMESERV
    0x00000080 |  # CLOSEST
    0x00000100 |  # WRITABLE
    0x00000200 |  # GOOD_TIMESERV
    0x00001000 |  # FULL_SECRET_DOMAIN_6
    0x00002000 |  # WS
    0x00004000 |  # DS_8
    0x00008000 |  # DS_9
    0x00010000 |  # DS_10
    0x00020000 |  # KEY_LIST
    0x00040000    # DS_13
)


def netlogon_response(realm, dc_host):
    site = "Default-First-Site-Name"
    out = bytearray()
    out.extend(struct.pack("<hhI", 23, 0, DS_FLAGS))
    out.extend(uuid.uuid4().bytes_le)
    for value in (realm, realm, dc_host, "", "", "", site, site):
        out.extend(dns_pack_name(value) if value else b"\x00")
    out.extend(struct.pack("<Ihh", 5, -1, -1))
    return bytes(out)


class LdapHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        server = self.server
        msgid = ldap_message_id(data)
        logging.info("CLDAP ping from %s message %s", self.client_address, msgid)

        attr = ber_sequence(
            ber_octet("Netlogon") +
            ber_set(ber_octet(server.netlogon_blob)))
        entry = ber_sequence(
            ber_int(msgid) +
            ber(0x64, ber_octet("") + ber_sequence(attr)))
        done = ber_sequence(
            ber_int(msgid) +
            ber(0x65, ber_enum(0) + ber_octet("") + ber_octet("")))
        sock.sendto(entry + done, self.client_address)


class KdcUdpProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        server = self.server
        logging.info(
            "KDC UDP proxy %s bytes from %s", len(data), self.client_address)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream:
            upstream.settimeout(5)
            upstream.sendto(data, (server.target_host, server.target_port))
            try:
                response, _ = upstream.recvfrom(65535)
            except socket.timeout:
                logging.info("KDC UDP proxy upstream timeout")
                return
        sock.sendto(response, self.client_address)


def read_exact(sock, length):
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            return None
        data.extend(chunk)
    return bytes(data)


WSL_KDC_RELAY = r"""
import socket
import struct
import sys


def read_exact(sock, length):
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise SystemExit(2)
        data.extend(chunk)
    return bytes(data)


request = sys.stdin.buffer.read()
with socket.create_connection(("127.0.0.1", 88), timeout=5) as kdc:
    kdc.settimeout(10)
    kdc.sendall(request)
    header = read_exact(kdc, 4)
    length = struct.unpack("!I", header)[0]
    response = read_exact(kdc, length)
sys.stdout.buffer.write(header + response)
"""


def relay_tcp_frame_via_wsl(frame):
    result = subprocess.run(
        ["wsl.exe", "-u", "root", "--", "python3", "-c", WSL_KDC_RELAY],
        input=frame,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
        check=False)
    if result.returncode != 0:
        logging.info(
            "KDC TCP WSL relay failed rc=%s stderr=%r",
            result.returncode, result.stderr.decode("utf-8", "replace"))
        return None
    return result.stdout


class KdcTcpProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        server = self.server
        logging.info("KDC TCP proxy connection from %s", self.client_address)
        self.request.settimeout(10)
        upstream = None
        if not server.use_wsl_tcp:
            upstream = socket.create_connection(
                (server.target_host, server.target_port), timeout=5)
            upstream.settimeout(10)
        try:
            while True:
                header = read_exact(self.request, 4)
                if header is None:
                    return
                length = struct.unpack("!I", header)[0]
                data = read_exact(self.request, length)
                if data is None:
                    return
                frame = header + data
                logging.info("KDC TCP proxy request %s bytes", length)

                if server.use_wsl_tcp:
                    response_frame = relay_tcp_frame_via_wsl(frame)
                    if response_frame is None:
                        return
                    self.request.sendall(response_frame)
                    continue

                upstream.sendall(frame)
                response_header = read_exact(upstream, 4)
                if response_header is None:
                    return
                response_length = struct.unpack("!I", response_header)[0]
                response = read_exact(upstream, response_length)
                if response is None:
                    return
                logging.info("KDC TCP proxy response %s bytes", response_length)
                self.request.sendall(response_header + response)
        finally:
            if upstream is not None:
                upstream.close()


class ThreadedUdpServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True


class ThreadedTcpServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--realm", required=True)
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--kdc-udp-target")
    parser.add_argument("--kdc-udp-port", type=int, default=88)
    parser.add_argument("--kdc-tcp-via-wsl", action="store_true")
    parser.add_argument("--log", required=True)
    args = parser.parse_args()

    logging.basicConfig(
        filename=args.log,
        level=logging.INFO,
        format="%(asctime)s %(message)s")

    realm = args.realm.lower()
    dc_host = f"dc01.{realm}"
    listen = args.listen

    a_records = {
        dc_host: ipaddress.ip_address(listen),
        f"kdc1.{realm}": ipaddress.ip_address(listen),
    }
    srv_records = {
        f"_kerberos._tcp.dc._msdcs.{realm}": (dc_host, 88),
        f"_ldap._tcp.dc._msdcs.{realm}": (dc_host, 389),
        f"_kerberos._tcp.{realm}": (dc_host, 88),
        f"_kerberos._udp.{realm}": (dc_host, 88),
    }

    dns_udp = ThreadedUdpServer((listen, 53), DnsUdpHandler)
    dns_tcp = ThreadedTcpServer((listen, 53), DnsTcpHandler)
    for dns in (dns_udp, dns_tcp):
        dns.a_records = a_records
        dns.srv_records = srv_records

    ldap = ThreadedUdpServer((listen, 389), LdapHandler)
    ldap.netlogon_blob = netlogon_response(realm, dc_host)

    servers = [dns_udp, dns_tcp, ldap]
    if args.kdc_udp_target:
        kdc_udp = ThreadedUdpServer((listen, 88), KdcUdpProxyHandler)
        kdc_udp.target_host = args.kdc_udp_target
        kdc_udp.target_port = args.kdc_udp_port
        kdc_tcp = ThreadedTcpServer((listen, 88), KdcTcpProxyHandler)
        kdc_tcp.target_host = args.kdc_udp_target
        kdc_tcp.target_port = args.kdc_udp_port
        kdc_tcp.use_wsl_tcp = args.kdc_tcp_via_wsl
        servers.append(kdc_udp)
        servers.append(kdc_tcp)

    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    logging.info("locator started for %s on %s", realm, listen)
    threading.Event().wait()


if __name__ == "__main__":
    main()
