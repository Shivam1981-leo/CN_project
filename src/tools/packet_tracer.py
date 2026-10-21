#!/usr/bin/env python3
"""
ECCP Packet Tracer & Wireshark PCAP Generator
Generates authentic Wireshark-compatible .pcap files and provides packet inspection
and terminal-based Wireshark tracing for the ECCP framework.

Supports pure Python Libpcap 2.4 generation (zero external dependencies required).
"""

import os
import sys
import time
import struct
import json
import uuid
import hmac
import hashlib
from typing import List, Dict, Any, Tuple, Optional
from datetime import datetime

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# Adjust path for internal module imports
_src_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_root_dir = os.path.dirname(_src_dir)
for p in [_src_dir, _root_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    from common.protocol import MessageType, StatusCode, PROTOCOL_VERSION
    from common.crypto_utils import CryptoUtils
except ImportError:
    pass


# ============================================================================
# Pure Python PCAP & Packet Engine (RFC 1071, RFC 791, RFC 793, RFC 8446)
# ============================================================================

def calc_ip_checksum(data: bytes) -> int:
    """Calculate 16-bit one's complement Internet Checksum (RFC 1071)"""
    if len(data) % 2 != 0:
        data += b'\x00'
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    while (s >> 16):
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def calc_tcp_checksum(src_ip: bytes, dst_ip: bytes, tcp_seg: bytes) -> int:
    """Calculate TCP checksum including IPv4 pseudo-header"""
    pseudo_hdr = struct.pack(
        "!4s4sBBH",
        src_ip,
        dst_ip,
        0,              # Reserved
        6,              # Protocol: TCP
        len(tcp_seg)
    )
    combined = pseudo_hdr + tcp_seg
    if len(combined) % 2 != 0:
        combined += b'\x00'
    s = sum(struct.unpack(f"!{len(combined)//2}H", combined))
    while (s >> 16):
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


class PcapWriter:
    """Standard Libpcap 2.4 binary PCAP file writer"""

    def __init__(self, filename: str):
        self.filename = filename
        self.file = None
        self.packet_count = 0

    def open(self):
        os.makedirs(os.path.dirname(os.path.abspath(self.filename)), exist_ok=True)
        self.file = open(self.filename, "wb")
        # Global Header: magic(4B), maj(2B), min(2B), zone(4B), sig(4B), snap(4B), link(4B)
        # Magic: 0xa1b2c3d4 (standard microseconds PCAP)
        # Link type: 1 (LINKTYPE_ETHERNET)
        hdr = struct.pack("!IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        self.file.write(hdr)
        self.packet_count = 0
        return self

    def write_packet(self, packet_bytes: bytes, timestamp: float):
        if not self.file:
            raise RuntimeError("PCAP file is not open")
        ts_sec = int(timestamp)
        ts_usec = int((timestamp - ts_sec) * 1_000_000)
        pkt_len = len(packet_bytes)
        # Packet Record Header: ts_sec(4B), ts_usec(4B), incl_len(4B), orig_len(4B)
        rec_hdr = struct.pack("!IIII", ts_sec, ts_usec, pkt_len, pkt_len)
        self.file.write(rec_hdr)
        self.file.write(packet_bytes)
        self.packet_count += 1

    def close(self):
        if self.file:
            self.file.flush()
            self.file.close()
            self.file = None

    def __enter__(self):
        return self.open()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class PacketFrame:
    """Represents a parsed or generated network frame with layer inspection"""

    def __init__(
        self,
        frame_num: int,
        timestamp: float,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        info: str,
        raw_bytes: bytes,
        layers: Dict[str, Any] = None,
        plain_payload: Optional[str] = None
    ):
        self.frame_num = frame_num
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.info = info
        self.raw_bytes = raw_bytes
        self.length = len(raw_bytes)
        self.layers = layers or {}
        self.plain_payload = plain_payload

    def to_dict(self) -> Dict[str, Any]:
        return {
            "frame_num": self.frame_num,
            "timestamp": round(self.timestamp, 6),
            "src": f"{self.src_ip}:{self.src_port}" if self.src_port else self.src_ip,
            "dst": f"{self.dst_ip}:{self.dst_port}" if self.dst_port else self.dst_ip,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "length": self.length,
            "info": self.info,
            "layers": self.layers,
            "hex_dump": self.get_hex_dump(),
            "plain_payload": self.plain_payload
        }

    def get_hex_dump(self) -> str:
        """Format raw bytes as standard Wireshark hex + ASCII dump"""
        lines = []
        for i in range(0, len(self.raw_bytes), 16):
            chunk = self.raw_bytes[i:i+16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            if len(chunk) < 16:
                hex_part = hex_part.ljust(47)
            # ASCII characters
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"{i:04x}   {hex_part[:23]}  {hex_part[24:]}   |{ascii_part}|")
        return "\n".join(lines)


class PacketBuilder:
    """Helper to synthesize valid Ethernet/IPv4/TCP/TLS packets for PCAP export"""

    def __init__(self, client_ip="127.0.0.1", server_ip="127.0.0.1", client_port=54321, server_port=5000):
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.client_port = client_port
        self.server_port = server_port
        self.c_seq = 1000000
        self.s_seq = 2000000
        self.c_ip_bytes = bytes(map(int, client_ip.split(".")))
        self.s_ip_bytes = bytes(map(int, server_ip.split(".")))
        self.client_mac = b"\x00\x1a\x2b\x3c\x4d\x5e"
        self.server_mac = b"\x5e\x4d\x3c\x2b\x1a\x00"

    def build_frame(
        self,
        from_client: bool,
        flags: int,
        seq: int,
        ack: int,
        payload: bytes = b"",
        ip_id: int = 1
    ) -> bytes:
        """Construct Ethernet + IPv4 + TCP + Payload bytes with valid checksums"""
        src_mac = self.client_mac if from_client else self.server_mac
        dst_mac = self.server_mac if from_client else self.client_mac
        src_ip = self.c_ip_bytes if from_client else self.s_ip_bytes
        dst_ip = self.s_ip_bytes if from_client else self.c_ip_bytes
        src_port = self.client_port if from_client else self.server_port
        dst_port = self.server_port if from_client else self.client_port

        # 1. Ethernet Header (14 bytes)
        eth_hdr = dst_mac + src_mac + struct.pack("!H", 0x0800)  # EtherType IPv4

        # 2. TCP Header (20 bytes)
        tcp_offset_flags = (5 << 12) | flags  # 5 * 4 = 20 bytes header
        tcp_hdr_no_chk = struct.pack(
            "!HHIIHHHH",
            src_port,
            dst_port,
            seq,
            ack,
            tcp_offset_flags,
            64240,     # Window size
            0,         # Checksum placeholder
            0          # Urgent pointer
        )
        tcp_chk = calc_tcp_checksum(src_ip, dst_ip, tcp_hdr_no_chk + payload)
        tcp_hdr = struct.pack(
            "!HHIIHHHH",
            src_port,
            dst_port,
            seq,
            ack,
            tcp_offset_flags,
            64240,
            tcp_chk,
            0
        )
        tcp_segment = tcp_hdr + payload

        # 3. IPv4 Header (20 bytes)
        ip_total_len = 20 + len(tcp_segment)
        ip_hdr_no_chk = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,              # Version 4, IHL 5
            0,                 # DSCP / ECN
            ip_total_len,      # Total length
            ip_id & 0xffff,    # Identification
            0x4000,            # Flags: Don't Fragment
            64,                # TTL
            6,                 # Protocol: TCP
            0,                 # Checksum placeholder
            src_ip,
            dst_ip
        )
        ip_chk = calc_ip_checksum(ip_hdr_no_chk)
        ip_hdr = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            ip_total_len,
            ip_id & 0xffff,
            0x4000,
            64,
            6,
            ip_chk,
            src_ip,
            dst_ip
        )

        return eth_hdr + ip_hdr + tcp_segment


# TCP Flag constants
TCP_SYN = 0x02
TCP_ACK = 0x10
TCP_PSH = 0x08
TCP_FIN = 0x01
TCP_RST = 0x04


# ============================================================================
# Scenario Generators for Simulation & PCAP Creation
# ============================================================================

class ScenarioEngine:
    """Prepares structured simulation packets and authentic PCAP streams"""

    @staticmethod
    def get_tls13_handshake_scenario(start_time: float = None) -> List[PacketFrame]:
        """Scenario 1: TCP 3-Way Handshake + TLS 1.3 Key Exchange"""
        t = start_time or time.time()
        builder = PacketBuilder()
        frames = []
        fn = 1

        # 1. TCP SYN (Client -> Server)
        syn_raw = builder.build_frame(True, TCP_SYN, builder.c_seq, 0, ip_id=101)
        frames.append(PacketFrame(
            fn, t + 0.000, "127.0.0.1", "127.0.0.1", 54321, 5000, "TCP",
            "54321 → 5000 [SYN] Seq=0 Win=65535 Len=0 MSS=65495",
            syn_raw,
            layers={
                "Frame": "Frame 1: 54 bytes on wire",
                "Ethernet II": "Src: 00:1a:2b:3c:4d:5e, Dst: 5e:4d:3c:2b:1a:00",
                "IPv4": "Src: 127.0.0.1, Dst: 127.0.0.1, Prot: TCP (6), Len: 40",
                "TCP": "Src Port: 54321, Dst Port: 5000, Seq: 0, Flags: [SYN], Win: 65535"
            }
        ))
        fn += 1

        # 2. TCP SYN-ACK (Server -> Client)
        syn_ack_raw = builder.build_frame(False, TCP_SYN | TCP_ACK, builder.s_seq, builder.c_seq + 1, ip_id=201)
        frames.append(PacketFrame(
            fn, t + 0.0008, "127.0.0.1", "127.0.0.1", 5000, 54321, "TCP",
            "5000 → 54321 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=65495",
            syn_ack_raw,
            layers={
                "Frame": "Frame 2: 54 bytes on wire",
                "IPv4": "Src: 127.0.0.1, Dst: 127.0.0.1, Prot: TCP (6)",
                "TCP": "Src Port: 5000, Dst Port: 54321, Seq: 0, Ack: 1, Flags: [SYN, ACK]"
            }
        ))
        fn += 1

        # 3. TCP ACK (Client -> Server)
        builder.c_seq += 1
        builder.s_seq += 1
        ack_raw = builder.build_frame(True, TCP_ACK, builder.c_seq, builder.s_seq, ip_id=102)
        frames.append(PacketFrame(
            fn, t + 0.0014, "127.0.0.1", "127.0.0.1", 54321, 5000, "TCP",
            "54321 → 5000 [ACK] Seq=1 Ack=1 Win=65535 Len=0",
            ack_raw,
            layers={
                "Frame": "Frame 3: 54 bytes on wire",
                "IPv4": "Src: 127.0.0.1, Dst: 127.0.0.1, Prot: TCP (6)",
                "TCP": "Src Port: 54321, Dst Port: 5000, Seq: 1, Ack: 1, Flags: [ACK]"
            }
        ))
        fn += 1

        # 4. TLS 1.3 Client Hello
        client_hello_payload = b"".join([
            b"\x16\x03\x01\x01\xfc",           # Handshake, TLS 1.0 record header, Len 508
            b"\x01\x00\x01\xf8",               # Client Hello, Handshake length
            b"\x03\x03",                       # Client Version (TLS 1.2 legacy)
            b"\x1a\x2b\x3c\x4d" * 8,           # Random (32 bytes)
            b"\x20", (b"\xaa" * 32),           # Legacy Session ID (32 bytes)
            b"\x00\x08",                       # Cipher Suites Length: 4 suites
            b"\x13\x02\x13\x03\x13\x01\xc0\x2f", # TLS_AES_256_GCM_SHA384, TLS_CHACHA20, TLS_AES_128, etc.
            b"\x01\x00",                       # Compression methods (null)
            b"\x01\x9b",                       # Extensions Length
            b"\x00\x2b\x00\x03\x02\x03\x04",   # Supported Versions: TLS 1.3 (0x0304)
            b"\x00\x33\x00\x26\x00\x24\x00\x1d\x00\x20", (b"\x55" * 32) # Key Share (X25519)
        ])
        ch_raw = builder.build_frame(True, TCP_PSH | TCP_ACK, builder.c_seq, builder.s_seq, client_hello_payload, ip_id=103)
        builder.c_seq += len(client_hello_payload)
        frames.append(PacketFrame(
            fn, t + 0.0035, "127.0.0.1", "127.0.0.1", 54321, 5000, "TLSv1.3",
            "Client Hello (Cipher Suites: TLS_AES_256_GCM_SHA384, KeyShare: X25519)",
            ch_raw,
            layers={
                "Frame": f"Frame 4: {len(ch_raw)} bytes on wire",
                "IPv4": "Src: 127.0.0.1, Dst: 127.0.0.1",
                "TCP": f"Src Port: 54321, Dst Port: 5000, Len: {len(client_hello_payload)}",
                "TLSv1.3 Record Layer": "Handshake Protocol: Client Hello",
                "  Handshake Protocol": {
                    "Type": "Client Hello (1)",
                    "Version": "TLS 1.2 (0x0303) [Supported Versions Extension: TLS 1.3 (0x0304)]",
                    "Cipher Suites": ["TLS_AES_256_GCM_SHA384 (0x1302)", "TLS_CHACHA20_POLY1305_SHA256 (0x1303)", "TLS_AES_128_GCM_SHA256 (0x1301)"],
                    "Extension: supported_versions": "TLS 1.3 (0x0304)",
                    "Extension: key_share": "ECDHE Key Share (Group: X25519)"
                }
            }
        ))
        fn += 1

        # 5. TLS 1.3 Server Hello + ChangeCipherSpec + Encrypted Extensions + Cert + Finished
        server_hello_payload = b"".join([
            b"\x16\x03\x03\x00\x7a",           # Handshake, TLS 1.2 record, Len 122
            b"\x02\x00\x00\x76",               # Server Hello
            b"\x03\x03",                       # Server Version
            b"\xfe\xdc\xba\x98" * 8,           # Server Random (32 bytes)
            b"\x20", (b"\xaa" * 32),           # Echoed Session ID
            b"\x13\x02",                       # Selected: TLS_AES_256_GCM_SHA384
            b"\x00",                           # Compression: null
            b"\x00\x2e",                       # Extensions Length
            b"\x00\x2b\x00\x02\x03\x04",       # Supported Versions: TLS 1.3
            b"\x00\x33\x00\x24\x00\x1d\x00\x20", (b"\x77" * 32), # Server Key Share
            # Change Cipher Spec (compatibility)
            b"\x14\x03\x03\x00\x01\x01",
            # Encrypted Handshake Message (EncryptedExtensions, Certificate, CertVerify, Finished)
            b"\x17\x03\x03\x04\xb0", (b"\x99" * 1200)
        ])
        sh_raw = builder.build_frame(False, TCP_PSH | TCP_ACK, builder.s_seq, builder.c_seq, server_hello_payload, ip_id=202)
        builder.s_seq += len(server_hello_payload)
        frames.append(PacketFrame(
            fn, t + 0.0078, "127.0.0.1", "127.0.0.1", 5000, 54321, "TLSv1.3",
            "Server Hello, Change Cipher Spec, Application Data (Encrypted Handshake: Certificate, Finished)",
            sh_raw,
            layers={
                "Frame": f"Frame 5: {len(sh_raw)} bytes on wire",
                "TCP": f"Src Port: 5000, Dst Port: 54321, Len: {len(server_hello_payload)}",
                "TLSv1.3 Record Layer (Server Hello)": {
                    "Type": "Handshake (22)",
                    "Selected Cipher Suite": "TLS_AES_256_GCM_SHA384 (0x1302)",
                    "Extension: key_share": "ECDHE Key Share (Group: X25519)"
                },
                "TLSv1.3 Record Layer (Change Cipher Spec)": "Change Cipher Spec (20)",
                "TLSv1.3 Record Layer (Encrypted Handshake)": "Content Type: Application Data (23) [Encrypted: Certificate, CertificateVerify, Finished]"
            }
        ))
        fn += 1

        # 6. TLS 1.3 Client Finished (Encrypted)
        client_finished_payload = b"\x17\x03\x03\x00\x34" + (b"\x33" * 52)
        cf_raw = builder.build_frame(True, TCP_PSH | TCP_ACK, builder.c_seq, builder.s_seq, client_finished_payload, ip_id=104)
        builder.c_seq += len(client_finished_payload)
        frames.append(PacketFrame(
            fn, t + 0.0095, "127.0.0.1", "127.0.0.1", 54321, 5000, "TLSv1.3",
            "Application Data (Encrypted Client Finished) [TLS 1.3 Handshake Complete ✅]",
            cf_raw,
            layers={
                "Frame": f"Frame 6: {len(cf_raw)} bytes on wire",
                "TLSv1.3 Record Layer": "Application Data (23) - Encrypted Finished",
                "Security Status": "TLS 1.3 Secure Session Established. All future payload is encrypted with AES-256-GCM."
            }
        ))

        return frames

    @staticmethod
    def get_auth_scenario(start_time: float = None) -> List[PacketFrame]:
        """Scenario 2: User Authentication & Token Issuance (REGISTER & AUTH)"""
        t = start_time or time.time()
        builder = PacketBuilder()
        builder.c_seq = 1002500
        builder.s_seq = 2003800
        frames = []
        fn = 1

        # 1. Plaintext ECCP representation of AUTH_REQUEST
        plain_auth_req = json.dumps({
            "type": "AUTH_REQUEST",
            "username": "Alice",
            "password_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "timestamp": "2026-10-21T20:30:00"
        }, indent=2)

        # Wire TLS record: ContentType 0x17 (App Data), Ver 0x0303, Encrypted Ciphertext
        enc_auth_bytes = b"\x17\x03\x03\x00\x88" + hashlib.sha256(plain_auth_req.encode()).digest() + (b"\x44" * 104)
        pkt1_raw = builder.build_frame(True, TCP_PSH | TCP_ACK, builder.c_seq, builder.s_seq, enc_auth_bytes, ip_id=110)
        builder.c_seq += len(enc_auth_bytes)

        frames.append(PacketFrame(
            fn, t + 0.000, "127.0.0.1", "127.0.0.1", 54321, 5000, "TLSv1.3",
            "Application Data (Encrypted ECCP: AUTH_REQUEST for user 'Alice')",
            pkt1_raw,
            layers={
                "Frame": f"Frame 1: {len(pkt1_raw)} bytes on wire",
                "TLSv1.3 Record Layer": "Application Data (23), Length: 136 bytes (AES-256-GCM Ciphertext)",
                "Decrypted ECCP Wire Format": {
                    "Magic": "ECC (Encrypted Client Communication)",
                    "Message Type": "0x01 (AUTH_REQUEST)",
                    "Length": 104,
                    "HMAC-SHA256": "4b61fa93012bb298...",
                    "Payload": "JSON: username='Alice', password_hash=<bcrypt-hash>"
                }
            },
            plain_payload=plain_auth_req
        ))
        fn += 1

        # 2. Server TCP ACK
        ack1 = builder.build_frame(False, TCP_ACK, builder.s_seq, builder.c_seq, ip_id=210)
        frames.append(PacketFrame(
            fn, t + 0.0012, "127.0.0.1", "127.0.0.1", 5000, 54321, "TCP",
            "5000 → 54321 [ACK] Seq=2003800 Ack=1002641",
            ack1,
            layers={"TCP": "Flags: [ACK]"}
        ))
        fn += 1

        # 3. Server AUTH_RESPONSE with Session Token
        plain_auth_resp = json.dumps({
            "type": "AUTH_RESPONSE",
            "status": "SUCCESS (0x00)",
            "session_token": "tok_9f3a8b1c7e2d405a_eccp_alice",
            "expires_in": 3600
        }, indent=2)
        enc_auth_resp = b"\x17\x03\x03\x00\x7c" + hashlib.sha256(plain_auth_resp.encode()).digest() + (b"\x55" * 92)
        pkt2_raw = builder.build_frame(False, TCP_PSH | TCP_ACK, builder.s_seq, builder.c_seq, enc_auth_resp, ip_id=211)
        builder.s_seq += len(enc_auth_resp)

        frames.append(PacketFrame(
            fn, t + 0.0045, "127.0.0.1", "127.0.0.1", 5000, 54321, "TLSv1.3",
            "Application Data (Encrypted ECCP: AUTH_RESPONSE - Status: SUCCESS, Token Issued ✅)",
            pkt2_raw,
            layers={
                "Frame": f"Frame 3: {len(pkt2_raw)} bytes on wire",
                "TLSv1.3 Record Layer": "Application Data (23), Length: 124 bytes (AES-256-GCM Ciphertext)",
                "Decrypted ECCP Wire Format": {
                    "Magic": "ECC",
                    "Message Type": "0x02 (AUTH_RESPONSE)",
                    "Status": "0x00 (SUCCESS)",
                    "Session Token": "tok_9f3a8b1c7e2d405a_eccp_alice",
                    "HMAC-SHA256": "Verified Valid ✅"
                }
            },
            plain_payload=plain_auth_resp
        ))

        return frames

    @staticmethod
    def get_messaging_scenario(start_time: float = None) -> List[PacketFrame]:
        """Scenario 3: End-to-End Encrypted Messaging (Alice -> Server -> Bob)"""
        t = start_time or time.time()
        builder = PacketBuilder()
        builder.c_seq = 1005000
        builder.s_seq = 2007000
        frames = []
        fn = 1

        # Message from Alice to Bob
        plain_msg = json.dumps({
            "type": "MESSAGE_SEND",
            "recipient": "Bob",
            "content": "Hey Bob! Here is the secret encryption design plan for our CN Mini Project.",
            "session_token": "tok_9f3a8b1c7e2d405a",
            "timestamp": "2026-10-21T20:31:15"
        }, indent=2)

        enc_msg = b"\x17\x03\x03\x00\xa0" + hashlib.sha256(plain_msg.encode()).digest() + (b"\x77" * 128)
        pkt1_raw = builder.build_frame(True, TCP_PSH | TCP_ACK, builder.c_seq, builder.s_seq, enc_msg, ip_id=120)
        builder.c_seq += len(enc_msg)

        frames.append(PacketFrame(
            fn, t + 0.000, "127.0.0.1", "127.0.0.1", 54321, 5000, "TLSv1.3",
            "Application Data (Encrypted ECCP: MESSAGE_SEND to 'Bob' with HMAC-SHA256)",
            pkt1_raw,
            layers={
                "Frame": f"Frame 1: {len(pkt1_raw)} bytes on wire",
                "TLSv1.3 Record Layer": "Application Data (23) - 160 Bytes Ciphertext",
                "ECCP Header": "Type: MESSAGE_SEND (0x10), Length: 128",
                "Integrity Tag": "HMAC-SHA256: 8f23d10ab2... (Guarantees no tampering in transit)"
            },
            plain_payload=plain_msg
        ))
        fn += 1

        # Server ACK back to Alice
        plain_ack = json.dumps({
            "type": "MESSAGE_ACK",
            "status": "SUCCESS (0x00)",
            "info": "Message routed to Bob"
        }, indent=2)
        enc_ack = b"\x17\x03\x03\x00\x48" + hashlib.sha256(plain_ack.encode()).digest() + (b"\x88" * 40)
        pkt2_raw = builder.build_frame(False, TCP_PSH | TCP_ACK, builder.s_seq, builder.c_seq, enc_ack, ip_id=220)
        builder.s_seq += len(enc_ack)

        frames.append(PacketFrame(
            fn, t + 0.0022, "127.0.0.1", "127.0.0.1", 5000, 54321, "TLSv1.3",
            "Application Data (Encrypted ECCP: MESSAGE_ACK - Delivered to Bob ✅)",
            pkt2_raw,
            layers={
                "Frame": f"Frame 2: {len(pkt2_raw)} bytes on wire",
                "TLSv1.3 Record Layer": "Application Data (23) - Encrypted ACK"
            },
            plain_payload=plain_ack
        ))
        fn += 1

        # Relay from Server to Bob (simulated Bob port 54322)
        builder_bob = PacketBuilder(client_port=54322, server_port=5000)
        plain_bob_recv = json.dumps({
            "type": "MESSAGE_RECEIVE",
            "sender": "Alice",
            "content": "Hey Bob! Here is the secret encryption design plan for our CN Mini Project."
        }, indent=2)
        enc_bob_recv = b"\x17\x03\x03\x00\x9c" + hashlib.sha256(plain_bob_recv.encode()).digest() + (b"\x99" * 124)
        pkt3_raw = builder_bob.build_frame(False, TCP_PSH | TCP_ACK, 3001000, 4001000, enc_bob_recv, ip_id=221)

        frames.append(PacketFrame(
            fn, t + 0.0041, "127.0.0.1", "127.0.0.1", 5000, 54322, "TLSv1.3",
            "Application Data (Encrypted ECCP: Server delivers MESSAGE_RECEIVE to Bob)",
            pkt3_raw,
            layers={
                "Frame": f"Frame 3: {len(pkt3_raw)} bytes on wire",
                "Destination": "Bob (Client 2)",
                "Security Status": "Delivered over TLS 1.3 encrypted tunnel. HMAC verified valid."
            },
            plain_payload=plain_bob_recv
        ))

        return frames

    @staticmethod
    def get_file_transfer_scenario(start_time: float = None) -> List[PacketFrame]:
        """Scenario 4: Secure File Transfer with SHA-256 Checksum & Chunking"""
        t = start_time or time.time()
        builder = PacketBuilder()
        builder.c_seq = 1010000
        builder.s_seq = 2012000
        frames = []
        fn = 1

        # File metadata & transfer
        plain_file_hdr = json.dumps({
            "type": "FILE_SEND",
            "recipient": "Bob",
            "filename": "project_report_final.pdf",
            "file_size": 184520,
            "sha256_checksum": "a3f5b7c9e1d2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4",
            "chunks_total": 12
        }, indent=2)

        enc_file_hdr = b"\x17\x03\x03\x01\x10" + hashlib.sha256(plain_file_hdr.encode()).digest() + (b"\xaa" * 240)
        pkt1_raw = builder.build_frame(True, TCP_PSH | TCP_ACK, builder.c_seq, builder.s_seq, enc_file_hdr, ip_id=130)
        builder.c_seq += len(enc_file_hdr)

        frames.append(PacketFrame(
            fn, t + 0.000, "127.0.0.1", "127.0.0.1", 54321, 5000, "TLSv1.3",
            "Application Data (Encrypted ECCP: FILE_SEND_REQUEST - 'project_report_final.pdf', 184 KB, SHA-256)",
            pkt1_raw,
            layers={
                "Frame": f"Frame 1: {len(pkt1_raw)} bytes on wire",
                "TLSv1.3 Record Layer": "Application Data (23)",
                "File Transfer Metadata": {
                    "Filename": "project_report_final.pdf",
                    "Size": "184,520 bytes",
                    "SHA-256": "a3f5b7c9e1d2...",
                    "Integrity Method": "Cryptographic Hash Validation (SHA-256) upon assembly"
                }
            },
            plain_payload=plain_file_hdr
        ))
        fn += 1

        # File data chunk transmission (Chunk 1/12)
        chunk_data = b"\x17\x03\x03\x05\xb4" + (b"\xbb" * 1460)  # Max TCP segment size
        pkt2_raw = builder.build_frame(True, TCP_PSH | TCP_ACK, builder.c_seq, builder.s_seq, chunk_data, ip_id=131)
        builder.c_seq += len(chunk_data)

        frames.append(PacketFrame(
            fn, t + 0.0028, "127.0.0.1", "127.0.0.1", 54321, 5000, "TLSv1.3",
            "Application Data (Encrypted ECCP: FILE_CHUNK #1 - 1,460 Bytes Ciphertext)",
            pkt2_raw,
            layers={
                "Frame": f"Frame 2: {len(pkt2_raw)} bytes on wire",
                "TCP": "MSS: 1460 bytes",
                "Payload": "Encrypted Base64 binary slice"
            }
        ))
        fn += 1

        # Server ACK & Verification complete
        plain_file_ack = json.dumps({
            "type": "FILE_ACK",
            "status": "SUCCESS (0x00)",
            "message": "File verified and saved to received_files/project_report_final.pdf",
            "sha256_verified": True
        }, indent=2)
        enc_file_ack = b"\x17\x03\x03\x00\x50" + hashlib.sha256(plain_file_ack.encode()).digest() + (b"\xcc" * 48)
        pkt3_raw = builder.build_frame(False, TCP_PSH | TCP_ACK, builder.s_seq, builder.c_seq, enc_file_ack, ip_id=230)
        builder.s_seq += len(enc_file_ack)

        frames.append(PacketFrame(
            fn, t + 0.0062, "127.0.0.1", "127.0.0.1", 5000, 54321, "TLSv1.3",
            "Application Data (Encrypted ECCP: FILE_ACK - SHA-256 Checksum Verified ✅)",
            pkt3_raw,
            layers={
                "Frame": f"Frame 3: {len(pkt3_raw)} bytes on wire",
                "Checksum Status": "SHA-256 verification successful. Output saved to disk."
            },
            plain_payload=plain_file_ack
        ))

        return frames

    @staticmethod
    def get_mitm_attack_scenario(start_time: float = None) -> List[PacketFrame]:
        """Scenario 5: Active Man-In-The-Middle (MITM) Tampering Attack & Defense"""
        t = start_time or time.time()
        builder = PacketBuilder()
        builder.c_seq = 1020000
        builder.s_seq = 2025000
        frames = []
        fn = 1

        # 1. Original message from Alice
        orig_plain = "Transfer $50 to Bob"
        plain_msg = json.dumps({
            "type": "MESSAGE_SEND",
            "recipient": "Bob",
            "content": orig_plain,
            "session_token": "tok_valid_session"
        })
        enc_msg = b"\x17\x03\x03\x00\x60" + hashlib.sha256(plain_msg.encode()).digest() + (b"\xee" * 64)
        pkt1_raw = builder.build_frame(True, TCP_PSH | TCP_ACK, builder.c_seq, builder.s_seq, enc_msg, ip_id=140)
        builder.c_seq += len(enc_msg)

        frames.append(PacketFrame(
            fn, t + 0.000, "127.0.0.1", "127.0.0.1", 54321, 5000, "TLSv1.3",
            "Application Data (Original Packet: 'Transfer $50 to Bob', HMAC: valid)",
            pkt1_raw,
            layers={
                "Status": "Original untampered frame transmitted by client",
                "Integrity HMAC": "Valid SHA-256 HMAC tag attached"
            },
            plain_payload=plain_msg
        ))
        fn += 1

        # 2. Tampered Wire Packet (Eve flips bits on the wire)
        tampered_bytes = bytearray(enc_msg)
        # Flip bits in the middle of ciphertext
        tampered_bytes[25] ^= 0xff
        tampered_bytes[26] ^= 0xaa
        pkt2_raw = builder.build_frame(True, TCP_PSH | TCP_ACK, builder.c_seq, builder.s_seq, bytes(tampered_bytes), ip_id=141)

        frames.append(PacketFrame(
            fn, t + 0.0025, "127.0.0.1", "127.0.0.1", 54321, 5000, "ATTACK",
            "⚠️ [MITM TAMPERING DETECTED] Adversary altered ciphertext bytes on the wire!",
            pkt2_raw,
            layers={
                "Frame": "Frame 2: Intercepted and modified by Active Wire Adversary",
                "Tampered Bytes": "Offset 25-26 corrupted on wire",
                "Attack Goal": "Adversary attempted to modify payload without cryptographic key"
            },
            plain_payload="[TAMPERED / CORRUPTED CIPHERTEXT]"
        ))
        fn += 1

        # 3. Server defense: HMAC check fails -> Connection terminated
        plain_err = json.dumps({
            "type": "ERROR",
            "status": "CHECKSUM_MISMATCH (0x07)",
            "message": "HMAC-SHA256 integrity validation failed! Possible tampering or bit corruption."
        }, indent=2)
        enc_err = b"\x17\x03\x03\x00\x50" + (b"\x00" * 80)
        pkt3_raw = builder.build_frame(False, TCP_PSH | TCP_ACK, builder.s_seq, builder.c_seq, enc_err, ip_id=240)
        builder.s_seq += len(enc_err)

        frames.append(PacketFrame(
            fn, t + 0.0048, "127.0.0.1", "127.0.0.1", 5000, 54321, "SECURITY",
            "🚨 SECURITY ALERT: HMAC Mismatch (0x07) - Packet Dropped & Socket Reset [TCP RST] 🛡️",
            pkt3_raw,
            layers={
                "Protocol": "ECCP Security Enforcement",
                "Diagnostic": "Constant-time HMAC comparison failed (hmac.compare_digest)",
                "Action Taken": "Server rejects forged data, refuses execution, and tears down socket with TCP RST"
            },
            plain_payload=plain_err
        ))
        fn += 1

        # 4. TCP RST
        rst_raw = builder.build_frame(False, TCP_RST, builder.s_seq, 0, ip_id=241)
        frames.append(PacketFrame(
            fn, t + 0.0055, "127.0.0.1", "127.0.0.1", 5000, 54321, "TCP",
            "5000 → 54321 [RST] Connection Reset by Peer due to Security Violation",
            rst_raw,
            layers={"TCP": "Flags: [RST]"}
        ))

        return frames


# ============================================================================
# PCAP Export & CLI Tracing
# ============================================================================

def export_all_pcaps(output_dir: str = "pcaps") -> Dict[str, str]:
    """Generates all 5 scenario PCAP files ready for Wireshark inspection"""
    os.makedirs(output_dir, exist_ok=True)
    generated = {}

    scenarios = [
        ("1_tls13_handshake.pcap", ScenarioEngine.get_tls13_handshake_scenario()),
        ("2_user_auth_session.pcap", ScenarioEngine.get_auth_scenario()),
        ("3_encrypted_chat.pcap", ScenarioEngine.get_messaging_scenario()),
        ("4_secure_file_transfer.pcap", ScenarioEngine.get_file_transfer_scenario()),
        ("5_mitm_tampering_attack.pcap", ScenarioEngine.get_mitm_attack_scenario()),
    ]

    for fname, frames in scenarios:
        out_path = os.path.join(output_dir, fname)
        with PcapWriter(out_path) as writer:
            for f in frames:
                writer.write_packet(f.raw_bytes, f.timestamp)
        generated[fname] = out_path

    return generated


def print_terminal_wireshark(frames: List[PacketFrame], title: str = "Wireshark Packet Capture Trace"):
    """Render a colored terminal-based Wireshark trace table with layer inspector"""
    print("\n" + "=" * 100)
    print(f"  📡 {title}")
    print("=" * 100)
    print(f"{'No.':<4} | {'Time (s)':<9} | {'Source':<21} | {'Destination':<21} | {'Proto':<8} | {'Len':<5} | {'Info'}")
    print("-" * 100)

    for f in frames:
        t_str = f"{f.timestamp - frames[0].timestamp:0.4f}"
        src_str = f"{f.src_ip}:{f.src_port}" if f.src_port else f.src_ip
        dst_str = f"{f.dst_ip}:{f.dst_port}" if f.dst_port else f.dst_ip
        print(f"{f.frame_num:<4} | {t_str:<9} | {src_str:<21} | {dst_str:<21} | {f.protocol:<8} | {f.length:<5} | {f.info}")

    print("-" * 100)
    print(f"Total Packets: {len(frames)} | Capture format: Standard Libpcap (Wireshark 4.x compatible)")
    print("=" * 100 + "\n")


def print_packet_detail(frame: PacketFrame):
    """Print deep packet inspection (DPI) and hex dump for a frame"""
    print("\n" + "#" * 80)
    print(f"  Frame #{frame.frame_num}: {frame.info}")
    print("#" * 80)
    print(f"• Timestamp: {frame.timestamp}")
    print(f"• Protocol:  {frame.protocol} | Length: {frame.length} bytes")
    print(f"• Endpoints: {frame.src_ip}:{frame.src_port} → {frame.dst_ip}:{frame.dst_port}\n")

    print("--- [ Packet Layers ] ---")
    for layer, content in frame.layers.items():
        if isinstance(content, dict):
            print(f"▼ {layer}:")
            for k, v in content.items():
                print(f"    • {k}: {v}")
        else:
            print(f"▼ {layer}: {content}")

    if frame.plain_payload:
        print("\n--- [ Application Plaintext View (Before Wire Encryption) ] ---")
        print(frame.plain_payload)

    print("\n--- [ Hex Dump & ASCII (Over-The-Wire Wireshark Capture) ] ---")
    print(frame.get_hex_dump())
    print("#" * 80 + "\n")


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="ECCP Packet Tracer & Wireshark PCAP Generator")
    parser.add_argument("--generate-all", action="store_true", help="Generate all 5 PCAP files into pcaps/ folder")
    parser.add_argument("--scenario", choices=["1", "2", "3", "4", "5", "all"], default="all",
                        help="Select scenario to trace in terminal: 1=TLS Handshake, 2=Auth, 3=Chat, 4=File, 5=Tampering")
    parser.add_argument("--inspect", type=int, default=None, help="Inspect packet details & hex dump for specific frame number")
    parser.add_argument("--outdir", default="pcaps", help="Directory to save PCAPs")

    args = parser.parse_args()

    scenario_map = {
        "1": ("Scenario 1: TLS 1.3 Handshake & Key Exchange", ScenarioEngine.get_tls13_handshake_scenario),
        "2": ("Scenario 2: User Authentication & Token Issuance", ScenarioEngine.get_auth_scenario),
        "3": ("Scenario 3: End-to-End Encrypted Messaging (Alice → Bob)", ScenarioEngine.get_messaging_scenario),
        "4": ("Scenario 4: Secure File Transfer & SHA-256 Checksum", ScenarioEngine.get_file_transfer_scenario),
        "5": ("Scenario 5: Active MITM Tampering Attack & Defense", ScenarioEngine.get_mitm_attack_scenario)
    }

    if args.generate_all:
        print(f"Generating Wireshark PCAP files in '{args.outdir}/'...")
        gen = export_all_pcaps(args.outdir)
        for name, path in gen.items():
            print(f"  ✅ Saved: {path} ({os.path.getsize(path)} bytes)")
        print("\nAll PCAP files generated successfully! You can now open them directly in Wireshark.")
        sys.exit(0)

    # Render terminal trace
    to_run = ["1", "2", "3", "4", "5"] if args.scenario == "all" else [args.scenario]
    all_frames = []
    for sc in to_run:
        title, func = scenario_map[sc]
        frames = func()
        all_frames.extend(frames)
        print_terminal_wireshark(frames, title)

    if args.inspect is not None:
        matched = [f for f in all_frames if f.frame_num == args.inspect]
        if matched:
            print_packet_detail(matched[0])
        else:
            print(f"Frame #{args.inspect} not found.")
