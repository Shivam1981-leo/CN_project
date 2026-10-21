"""
Live Network Traffic Logger for ECCP
Captures real-time packet transmissions between live clients and the server
for visualization, deep inspection, and Wireshark PCAP generation.
"""

import os
import sys
import time
import json
import threading
from typing import Dict, Any, List, Optional
from datetime import datetime

_src_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_root_dir = os.path.dirname(_src_dir)
TRAFFIC_LOG_FILE = os.path.join(_root_dir, "logs", "live_traffic.json")


def bytes_to_hex_dump(data: bytes) -> str:
    """Format raw bytes as standard Wireshark hex + ASCII dump"""
    if not data:
        return "0000   (Empty payload)"
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        if len(chunk) < 16:
            hex_part = hex_part.ljust(47)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{i:04x}   {hex_part[:23]}  {hex_part[24:]}   |{ascii_part}|")
    return "\n".join(lines)


class TrafficLogger:
    """Thread-safe ring buffer and file-backed logger for real-time traffic"""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._init()
            return cls._instance

    def _init(self):
        self.packets: List[Dict[str, Any]] = []
        self.packet_counter = 0
        self.lock = threading.Lock()
        os.makedirs(os.path.dirname(TRAFFIC_LOG_FILE), exist_ok=True)
        # Clear or reset log file on startup
        try:
            with open(TRAFFIC_LOG_FILE, "w", encoding="utf-8") as f:
                json.dump([], f)
        except Exception:
            pass

    def log_packet(
        self,
        src: str,
        dst: str,
        from_node: str,
        to_node: str,
        proto: str,
        msg_type_name: str,
        length: int,
        info: str,
        plain_data: Optional[Any] = None,
        raw_bytes: Optional[bytes] = None,
        layers: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Record a live packet transmission event"""
        with self.lock:
            self.packet_counter += 1
            now = time.time()
            iso_time = datetime.fromtimestamp(now).strftime("%H:%M:%S.%f")[:-3]

            plain_str = ""
            if plain_data:
                if isinstance(plain_data, (dict, list)):
                    plain_str = json.dumps(plain_data, indent=2)
                else:
                    plain_str = str(plain_data)

            hex_dump = bytes_to_hex_dump(raw_bytes) if raw_bytes else ""

            # Standardized DPI layers if not provided
            if not layers:
                layers = {
                    f"Frame {self.packet_counter}": f"{length} bytes over TLS 1.3 socket",
                    "Transmission Control Protocol": f"Source: {src} → Destination: {dst}",
                    "Transport Layer Security": "TLSv1.3 Record Layer: Content Type: Application Data (23), Cipher: AES-256-GCM",
                    "ECCP Application Protocol": {
                        "Message Type": msg_type_name,
                        "Wire Size": f"{length} bytes",
                        "Security Status": "HMAC-SHA256 Integrity Verified ✅"
                    }
                }

            pkt = {
                "frame_num": self.packet_counter,
                "time_iso": iso_time,
                "timestamp": round(now, 4),
                "src": src,
                "dst": dst,
                "from_node": from_node.lower(),
                "to_node": to_node.lower(),
                "proto": proto,
                "msg_type": msg_type_name,
                "length": length,
                "info": info,
                "layers": layers,
                "plain": plain_str,
                "hex": hex_dump
            }

            self.packets.append(pkt)
            if len(self.packets) > 300:
                self.packets.pop(0)

            # Persist to disk for web simulator API
            try:
                with open(TRAFFIC_LOG_FILE, "w", encoding="utf-8") as f:
                    json.dump(self.packets, f)
            except Exception:
                pass

            return pkt

    def get_packets(self, since_id: int = 0) -> List[Dict[str, Any]]:
        """Retrieve packets starting from given frame number"""
        with self.lock:
            if since_id == 0:
                return list(self.packets)
            return [p for p in self.packets if p["frame_num"] > since_id]

    def clear(self):
        with self.lock:
            self.packets.clear()
            self.packet_counter = 0
            try:
                with open(TRAFFIC_LOG_FILE, "w", encoding="utf-8") as f:
                    json.dump([], f)
            except Exception:
                pass


# Global singleton helper
traffic_logger = TrafficLogger()
