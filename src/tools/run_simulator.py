#!/usr/bin/env python3
"""
ECCP Network Simulator & Wireshark Packet Visualizer Launcher
Serves the interactive web simulator dashboard and provides one-click PCAP exports.
"""

import os
import sys
import webbrowser
import urllib.parse
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

# Adjust path for tools module
_tools_dir = os.path.dirname(os.path.abspath(__file__))
_src_dir = os.path.dirname(_tools_dir)
_root_dir = os.path.dirname(_src_dir)
for p in [_tools_dir, _src_dir, _root_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

from tools.packet_tracer import export_all_pcaps

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass


class SimulatorHTTPHandler(SimpleHTTPRequestHandler):
    """Custom HTTP handler serving simulator UI and Wireshark PCAPs"""

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # Serve Simulator HTML
        if path == "/" or path == "/index.html":
            html_path = os.path.join(_tools_dir, "packet_visualizer.html")
            try:
                with open(html_path, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return
            except Exception as e:
                self.send_error(500, f"Error reading simulator HTML: {e}")
                return

        # Serve PCAP download
        elif path == "/download_pcap":
            pcap_name = query.get("file", ["1_tls13_handshake.pcap"])[0]
            # Sanitize filename
            safe_name = os.path.basename(pcap_name)
            pcap_path = os.path.join(_root_dir, "pcaps", safe_name)

            if not os.path.exists(pcap_path):
                # Regenerate if missing
                export_all_pcaps(os.path.join(_root_dir, "pcaps"))

            if os.path.exists(pcap_path):
                try:
                    with open(pcap_path, "rb") as f:
                        data = f.read()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/vnd.tcpdump.pcap")
                    self.send_header("Content-Disposition", f'attachment; filename="{safe_name}"')
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    return
                except Exception as e:
                    self.send_error(500, f"Failed to read PCAP: {e}")
                    return
            else:
                self.send_error(404, f"PCAP file {safe_name} not found")
                return

        # Default fallback
        super().do_GET()

    def log_message(self, format, *args):
        # Keep terminal output quiet and clean
        return


def start_server(port: int = 8080, open_browser: bool = True):
    pcaps_dir = os.path.join(_root_dir, "pcaps")
    print("=" * 70)
    print("  🌐 ECCP Network Simulator & Wireshark Packet Tracer")
    print("=" * 70)
    print("Preparing Wireshark-compatible PCAP traces...")
    export_all_pcaps(pcaps_dir)
    print(f"  [OK] PCAP files ready in: {pcaps_dir}")

    # Find available port
    server = None
    target_port = port
    for p in range(port, port + 10):
        try:
            server = HTTPServer(("127.0.0.1", p), SimulatorHTTPHandler)
            target_port = p
            break
        except OSError:
            continue

    if not server:
        print(f"Error: Could not bind HTTP server on ports {port}-{port+9}")
        return

    url = f"http://127.0.0.1:{target_port}"
    print(f"\n🚀 Simulator running at: {url}")
    print("Features available in the interactive dashboard:")
    print("  • Animated 4-Node Network Topology (Alice → Tap/MITM → Server → Bob)")
    print("  • 5 Interactive Scenarios (Handshake, Auth, Chat, File, MITM Attack)")
    print("  • Live Wireshark Packet Table with Deep Packet Inspection (DPI)")
    print("  • Plaintext vs Encrypted Wire Comparison (Why TLS 1.3 works)")
    print("  • Download authentic .pcap files directly to open in Wireshark")
    print("\nPress Ctrl+C in this terminal to stop the simulator server.\n")

    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nSimulator server stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    start_server(port=8080, open_browser=True)
