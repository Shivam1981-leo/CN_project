"""
Graphical User Interface (GUI) for Secure Client Application
Modern Tkinter-based interface for encrypted messaging and file transfer
"""

import sys
import os
import threading
import queue
import time
import base64
import json
import subprocess
from datetime import datetime
from typing import Any, Optional, Dict, List
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# Add parent and root directory to path
_src_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_root_dir = os.path.dirname(_src_dir)
for p in [_src_dir, _root_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    from client.client import SecureClient
except (ImportError, ModuleNotFoundError):
    from client import SecureClient

from common.protocol import MessageType, StatusCode
from common.crypto_utils import verify_file_checksum

try:
    from tools.packet_tracer import ScenarioEngine, export_all_pcaps
except ImportError:
    try:
        from src.tools.packet_tracer import ScenarioEngine, export_all_pcaps
    except ImportError:
        ScenarioEngine = None
        export_all_pcaps = None

try:
    from common.traffic_logger import traffic_logger, bytes_to_hex_dump
except ImportError:
    try:
        from src.common.traffic_logger import traffic_logger, bytes_to_hex_dump
    except ImportError:
        traffic_logger = None
        bytes_to_hex_dump = None


class ModernChatGUI:
    """Modern Tkinter GUI for the ECCP Secure Client"""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("ECCP Secure Messenger - TLS 1.3")
        self.root.geometry("1060x660")
        self.root.minsize(850, 520)

        # Apply dark theme styling
        self._setup_styles()

        self.client = SecureClient()
        self.ui_queue = queue.Queue()
        self.is_connected = False
        self.active_recipient = None

        # Build UI screens
        self.container = ttk.Frame(self.root, style="Main.TFrame")
        self.container.pack(fill="both", expand=True)

        self.auth_frame = None
        self.chat_frame = None

        self._show_auth_screen()

        # Poll UI queue for incoming messages from background threads
        self.root.after(100, self._process_ui_queue)

        # Clean shutdown
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _setup_styles(self):
        """Configure ttk styles with a modern dark palette"""
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        self.bg_dark = "#1e1e2e"
        self.bg_panel = "#252538"
        self.bg_chat = "#181825"
        self.accent = "#89b4fa"
        self.accent_hover = "#b4befe"
        self.text_light = "#cdd6f4"
        self.text_dim = "#a6adc8"
        self.success_color = "#a6e3a1"
        self.error_color = "#f38ba8"

        self.root.configure(bg=self.bg_dark)

        style.configure("Main.TFrame", background=self.bg_dark)
        style.configure("Panel.TFrame", background=self.bg_panel)
        style.configure("TLabel", background=self.bg_dark, foreground=self.text_light, font=("Segoe UI", 10))
        style.configure("Header.TLabel", background=self.bg_dark, foreground=self.accent, font=("Segoe UI", 16, "bold"))
        style.configure("SubHeader.TLabel", background=self.bg_dark, foreground=self.text_dim, font=("Segoe UI", 9))
        style.configure("Status.TLabel", background=self.bg_panel, foreground=self.success_color, font=("Segoe UI", 9, "bold"))

        style.configure("Modern.TButton", font=("Segoe UI", 10, "bold"),
                        background="#313244", foreground=self.text_light, borderwidth=0, padding=6)
        style.map("Modern.TButton", background=[("active", self.accent), ("pressed", "#45475a")])

        style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"),
                        background=self.accent, foreground="#11111b", borderwidth=0, padding=6)
        style.map("Accent.TButton", background=[("active", self.accent_hover)])

    def _show_auth_screen(self):
        """Render login and registration view"""
        if self.chat_frame:
            self.chat_frame.destroy()

        self.auth_frame = ttk.Frame(self.container, style="Main.TFrame")
        self.auth_frame.pack(fill="both", expand=True, padx=40, pady=30)

        # Header Title
        title_lbl = ttk.Label(self.auth_frame, text="🔒 ECCP Secure Messenger", style="Header.TLabel")
        title_lbl.pack(pady=(10, 5))

        subtitle = ttk.Label(self.auth_frame, text="TLS 1.3 Encrypted Client-Server Communication Framework", style="SubHeader.TLabel")
        subtitle.pack(pady=(0, 25))

        card = ttk.Frame(self.auth_frame, style="Panel.TFrame", padding=25)
        card.pack(fill="x", padx=100)

        notebook = ttk.Notebook(card)
        notebook.pack(fill="both", expand=True)

        # --- Login Tab ---
        login_tab = ttk.Frame(notebook, style="Panel.TFrame", padding=15)
        notebook.add(login_tab, text="  Login  ")

        ttk.Label(login_tab, text="Username:", background=self.bg_panel).pack(anchor="w", pady=(5, 2))
        self.login_user_entry = ttk.Entry(login_tab, font=("Segoe UI", 10))
        self.login_user_entry.pack(fill="x", pady=(0, 10))

        ttk.Label(login_tab, text="Password:", background=self.bg_panel).pack(anchor="w", pady=(5, 2))
        self.login_pwd_entry = ttk.Entry(login_tab, show="•", font=("Segoe UI", 10))
        self.login_pwd_entry.pack(fill="x", pady=(0, 15))
        self.login_pwd_entry.bind("<Return>", lambda e: self._on_login())

        login_btn = ttk.Button(login_tab, text="Login Securely", style="Accent.TButton", command=self._on_login)
        login_btn.pack(fill="x", pady=5)

        # --- Register Tab ---
        reg_tab = ttk.Frame(notebook, style="Panel.TFrame", padding=15)
        notebook.add(reg_tab, text="  Register  ")

        ttk.Label(reg_tab, text="Choose Username:", background=self.bg_panel).pack(anchor="w", pady=(5, 2))
        self.reg_user_entry = ttk.Entry(reg_tab, font=("Segoe UI", 10))
        self.reg_user_entry.pack(fill="x", pady=(0, 10))

        ttk.Label(reg_tab, text="Choose Password (min 6 chars):", background=self.bg_panel).pack(anchor="w", pady=(5, 2))
        self.reg_pwd_entry = ttk.Entry(reg_tab, show="•", font=("Segoe UI", 10))
        self.reg_pwd_entry.pack(fill="x", pady=(0, 10))

        ttk.Label(reg_tab, text="Confirm Password:", background=self.bg_panel).pack(anchor="w", pady=(5, 2))
        self.reg_pwd2_entry = ttk.Entry(reg_tab, show="•", font=("Segoe UI", 10))
        self.reg_pwd2_entry.pack(fill="x", pady=(0, 15))
        self.reg_pwd2_entry.bind("<Return>", lambda e: self._on_register())

        reg_btn = ttk.Button(reg_tab, text="Create Account", style="Modern.TButton", command=self._on_register)
        reg_btn.pack(fill="x", pady=5)

        # Status Label
        self.auth_status_lbl = ttk.Label(self.auth_frame, text="", style="SubHeader.TLabel")
        self.auth_status_lbl.pack(pady=10)

        # Bottom Tools Bar for Packet Tracing & Simulation
        tools_frame = ttk.Frame(self.auth_frame, style="Main.TFrame")
        tools_frame.pack(pady=10)

        tracer_btn = ttk.Button(tools_frame, text="📡 Wireshark Packet Tracer", style="Modern.TButton", command=self._open_packet_inspector)
        tracer_btn.pack(side="left", padx=6)

        sim_btn = ttk.Button(tools_frame, text="🌐 Packet Flow Simulator", style="Accent.TButton", command=self._open_web_simulator)
        sim_btn.pack(side="left", padx=6)

    def _show_chat_screen(self):
        """Render authenticated chat view"""
        if self.auth_frame:
            self.auth_frame.destroy()

        self.chat_frame = ttk.Frame(self.container, style="Main.TFrame")
        self.chat_frame.pack(fill="both", expand=True)

        # Top Bar
        top_bar = ttk.Frame(self.chat_frame, style="Panel.TFrame", padding=10)
        top_bar.pack(fill="x", side="top")

        user_info = ttk.Label(top_bar, text=f"👤 Logged in as: {self.client.username}", font=("Segoe UI", 11, "bold"), background=self.bg_panel)
        user_info.pack(side="left", padx=10)

        tls_badge = ttk.Label(top_bar, text="🔒 TLS 1.3 Encrypted", style="Status.TLabel")
        tls_badge.pack(side="left", padx=10)

        logout_btn = ttk.Button(top_bar, text="Logout", style="Modern.TButton", command=self._on_logout)
        logout_btn.pack(side="right", padx=5)

        sim_btn = ttk.Button(top_bar, text="🌐 Flow Simulator", style="Accent.TButton", command=self._open_web_simulator)
        sim_btn.pack(side="right", padx=5)

        packet_btn = ttk.Button(top_bar, text="📡 Packet Tracer", style="Modern.TButton", command=self._open_packet_inspector)
        packet_btn.pack(side="right", padx=5)

        # Body Pane
        body_paned = ttk.PanedWindow(self.chat_frame, orient="horizontal")
        body_paned.pack(fill="both", expand=True, padx=10, pady=10)

        # Left: Users list
        sidebar = ttk.Frame(body_paned, style="Panel.TFrame", padding=10, width=220)
        body_paned.add(sidebar, weight=1)

        ttk.Label(sidebar, text="Online Users", font=("Segoe UI", 11, "bold"), background=self.bg_panel).pack(anchor="w", pady=(0, 5))

        self.user_listbox = tk.Listbox(
            sidebar, bg=self.bg_chat, fg=self.text_light,
            selectbackground=self.accent, selectforeground="#000000",
            font=("Segoe UI", 10), bd=0, highlightthickness=0
        )
        self.user_listbox.pack(fill="both", expand=True, pady=(0, 10))
        self.user_listbox.bind("<<ListboxSelect>>", self._on_user_selected)

        refresh_btn = ttk.Button(sidebar, text="🔄 Refresh Users", style="Modern.TButton", command=self._refresh_users)
        refresh_btn.pack(fill="x")

        # Right: Chat history and input
        chat_pane = ttk.Frame(body_paned, style="Main.TFrame", padding=5)
        body_paned.add(chat_pane, weight=4)

        # Chat recipient label
        self.recipient_lbl = ttk.Label(chat_pane, text="Select a user from the list to chat", font=("Segoe UI", 11, "italic"))
        self.recipient_lbl.pack(anchor="w", pady=(0, 5))

        # Chat display area
        self.chat_display = tk.Text(
            chat_pane, bg=self.bg_chat, fg=self.text_light,
            wrap="word", font=("Consolas", 10), state="disabled",
            bd=0, padx=10, pady=10
        )
        self.chat_display.pack(fill="both", expand=True, pady=(0, 10))

        # Text tags for coloring
        self.chat_display.tag_configure("self", foreground=self.accent)
        self.chat_display.tag_configure("peer", foreground=self.success_color)
        self.chat_display.tag_configure("system", foreground=self.text_dim, font=("Consolas", 9, "italic"))
        self.chat_display.tag_configure("file", foreground="#f9e2af", font=("Consolas", 10, "bold"))

        # Input bar
        input_frame = ttk.Frame(chat_pane, style="Main.TFrame")
        input_frame.pack(fill="x", side="bottom")

        self.msg_entry = ttk.Entry(input_frame, font=("Segoe UI", 10))
        self.msg_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        self.msg_entry.bind("<Return>", lambda e: self._send_message())

        send_btn = ttk.Button(input_frame, text="Send ✉", style="Accent.TButton", command=self._send_message)
        send_btn.pack(side="left", padx=2)

        file_btn = ttk.Button(input_frame, text="Attach File 📎", style="Modern.TButton", command=self._send_file_dialog)
        file_btn.pack(side="left", padx=2)

        open_folder_btn = ttk.Button(input_frame, text="📂 Files", style="Modern.TButton", command=self._open_downloads_folder)
        open_folder_btn.pack(side="left", padx=2)

        # Right: Live Wireshark Packet Sniffer Pane
        self.sniffer_pane = ttk.Frame(body_paned, style="Panel.TFrame", padding=8, width=340)
        body_paned.add(self.sniffer_pane, weight=3)

        sniff_hdr = ttk.Frame(self.sniffer_pane, style="Panel.TFrame")
        sniff_hdr.pack(fill="x", pady=(0, 4))

        ttk.Label(sniff_hdr, text="📡 Live Wireshark Sniffer", font=("Segoe UI", 10, "bold"),
                  foreground=self.accent, background=self.bg_panel).pack(side="left")

        clear_btn = ttk.Button(sniff_hdr, text="Clear", style="Modern.TButton", command=self._clear_live_sniffer)
        clear_btn.pack(side="right")

        ttk.Label(self.sniffer_pane, text="Real-time encrypted frames as you chat:",
                  style="SubHeader.TLabel", background=self.bg_panel).pack(anchor="w", pady=(0, 4))

        # Sniffer Tree
        sniff_cols = ("dir", "proto", "type", "size", "hmac")
        self.sniff_tree = ttk.Treeview(self.sniffer_pane, columns=sniff_cols, show="headings", height=8, selectmode="browse")
        self.sniff_tree.heading("dir", text="Dir")
        self.sniff_tree.heading("proto", text="Proto")
        self.sniff_tree.heading("type", text="Type")
        self.sniff_tree.heading("size", text="Bytes")
        self.sniff_tree.heading("hmac", text="HMAC")

        self.sniff_tree.column("dir", width=38, anchor="center")
        self.sniff_tree.column("proto", width=62, anchor="center")
        self.sniff_tree.column("type", width=125)
        self.sniff_tree.column("size", width=48, anchor="center")
        self.sniff_tree.column("hmac", width=60, anchor="center")

        sniff_vsb = ttk.Scrollbar(self.sniffer_pane, orient="vertical", command=self.sniff_tree.yview)
        self.sniff_tree.configure(yscrollcommand=sniff_vsb.set)
        self.sniff_tree.pack(fill="x", pady=(0, 6))

        # Sniffer Detail Text
        ttk.Label(self.sniffer_pane, text="Wire Payload (Hex + Plaintext):", font=("Segoe UI", 9, "bold"),
                  background=self.bg_panel).pack(anchor="w", pady=(2, 2))
        self.sniff_detail = tk.Text(self.sniffer_pane, bg=self.bg_chat, fg=self.text_dim, font=("Consolas", 9),
                                    wrap="word", height=8, bd=0, padx=6, pady=6)
        self.sniff_detail.pack(fill="both", expand=True)

        self.live_packets_cache = []
        self.sniff_tree.bind("<<TreeviewSelect>>", self._on_sniff_packet_selected)
        self._start_gui_receiver()
        self._refresh_users()
        self._schedule_auto_refresh()

    def _schedule_auto_refresh(self):
        """Periodically refresh online users list every 3 seconds"""
        if self.is_connected and self.chat_frame:
            self._refresh_users()
        if getattr(self, 'root', None):
            self.root.after(3000, self._schedule_auto_refresh)

    def _append_chat(self, text: str, tag: str = "system"):
        """Append text to chat history area"""
        self.chat_display.config(state="normal")
        self.chat_display.insert("end", text + "\n", tag)
        self.chat_display.see("end")
        self.chat_display.config(state="disabled")

    def _on_user_selected(self, event):
        """Handle user selection in listbox"""
        selection = self.user_listbox.curselection()
        if selection:
            username = self.user_listbox.get(selection[0])
            if username.startswith("("):
                return
            self.active_recipient = username
            self.recipient_lbl.config(text=f"💬 Chatting with: {username}", font=("Segoe UI", 11, "bold"))

    def _ensure_connected(self) -> bool:
        """Connect to server if not connected"""
        if not self.is_connected:
            if not self.client.connect():
                self.auth_status_lbl.config(text="❌ Connection failed. Ensure server is running.", foreground=self.error_color)
                return False
            self.is_connected = True
        return True

    def _on_login(self):
        """Handle login submission"""
        username = self.login_user_entry.get().strip()
        password = self.login_pwd_entry.get()

        if not username or not password:
            messagebox.showwarning("Validation", "Username and password are required.")
            return

        if not self._ensure_connected():
            return

        self.auth_status_lbl.config(text="Authenticating...", foreground=self.text_light)

        def bg_login():
            success = self.client.login(username, password)
            self.ui_queue.put(("login_result", success))

        threading.Thread(target=bg_login, daemon=True).start()

    def _on_register(self):
        """Handle user registration"""
        username = self.reg_user_entry.get().strip()
        pwd1 = self.reg_pwd_entry.get()
        pwd2 = self.reg_pwd2_entry.get()

        if not username or not pwd1:
            messagebox.showwarning("Validation", "Username and password are required.")
            return

        if pwd1 != pwd2:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        if len(pwd1) < 6:
            messagebox.showwarning("Validation", "Password must be at least 6 characters.")
            return

        if not self._ensure_connected():
            return

        def bg_reg():
            success = self.client.register(username, pwd1)
            if success:
                login_success = self.client.login(username, pwd1)
                self.ui_queue.put(("login_result", login_success))
            else:
                self.ui_queue.put(("register_result", False))

        threading.Thread(target=bg_reg, daemon=True).start()

    def _refresh_users(self):
        """Fetch list of online users"""
        def bg_users():
            users = self.client.list_users()
            self.ui_queue.put(("users_list", users))

        threading.Thread(target=bg_users, daemon=True).start()

    def _send_message(self):
        """Send chat message to active recipient"""
        text = self.msg_entry.get().strip()
        if not text:
            return

        recipient = self.active_recipient
        if not recipient:
            messagebox.showinfo("Select User", "Please select a recipient from the Online Users list.")
            return

        self.msg_entry.delete(0, "end")
        timestamp = datetime.now().strftime("%H:%M:%S")
        self._append_chat(f"[{timestamp}] You -> {recipient}: {text}", "self")

        def bg_send():
            ok = self.client.send_message(recipient, text)
            if not ok:
                self.ui_queue.put(("system_msg", f"⚠️ Failed to deliver message to {recipient}"))

        threading.Thread(target=bg_send, daemon=True).start()

    def _send_file_dialog(self):
        """Open file dialog and transmit file"""
        recipient = self.active_recipient
        if not recipient:
            messagebox.showinfo("Select User", "Please select a recipient from the Online Users list.")
            return

        filepath = filedialog.askopenfilename(title="Select file to send")
        if not filepath:
            return

        timestamp = datetime.now().strftime("%H:%M:%S")
        filename = os.path.basename(filepath)
        self._append_chat(f"[{timestamp}] 📤 Sending '{filename}' to {recipient}...", "file")

        def bg_send_file():
            success = self.client.send_file(recipient, filepath)
            if success:
                self.ui_queue.put(("system_msg", f"✅ File '{filename}' successfully sent to {recipient}"))
            else:
                self.ui_queue.put(("system_msg", f"❌ Failed to send file '{filename}' to {recipient}"))

        threading.Thread(target=bg_send_file, daemon=True).start()

    def _open_downloads_folder(self):
        """Open received files directory"""
        folder = os.path.abspath("received_files")
        os.makedirs(folder, exist_ok=True)
        if sys.platform == 'win32':
            os.startfile(folder)
        else:
            subprocess.run(["xdg-open", folder])

    def _start_gui_receiver(self):
        """Hook into SecureClient callbacks for thread-safe UI updates"""
        self.client.on_message_callback = lambda sender, content: self.ui_queue.put(("chat_msg", (sender, content)))
        self.client.on_file_callback = lambda sender, filename, is_valid, path: self.ui_queue.put(("file_received", (sender, filename, is_valid, path)))
        self.client.on_packet_callback = lambda direction, mtype, length, raw_bytes, plain, valid: self.ui_queue.put(("live_packet", (direction, mtype, length, raw_bytes, plain, valid)))

    def _process_ui_queue(self):
        """Consume queued events from background worker threads"""
        try:
            while not self.ui_queue.empty():
                try:
                    event_type, payload = self.ui_queue.get_nowait()
                except queue.Empty:
                    break

                try:
                    if event_type == "login_result":
                        if payload:
                            self._show_chat_screen()
                        else:
                            self.auth_status_lbl.config(text="❌ Invalid username or password", foreground=self.error_color)

                    elif event_type == "register_result":
                        if payload:
                            messagebox.showinfo("Registration", "Account created successfully! Please login.")
                            self.auth_status_lbl.config(text="✅ Registration successful! You can now login.", foreground=self.success_color)
                        else:
                            messagebox.showerror("Registration", "Registration failed. Username may already exist.")

                    elif event_type == "users_list":
                        if self.chat_frame:
                            users_data = payload or []
                            active_peers = [u for u in users_data if u and u != self.client.username]
                            prev_sel = self.active_recipient
                            self.user_listbox.delete(0, "end")
                            if active_peers:
                                for user in active_peers:
                                    self.user_listbox.insert("end", user)
                                # Restore selection or auto-select first user
                                if prev_sel and prev_sel in active_peers:
                                    idx = active_peers.index(prev_sel)
                                    self.user_listbox.selection_set(idx)
                                else:
                                    self.user_listbox.selection_set(0)
                                    self._on_user_selected(None)
                            else:
                                self.user_listbox.insert("end", "(No other users online yet)")
                                self.recipient_lbl.config(text="Waiting for another user to connect...", font=("Segoe UI", 11, "italic"))
                                self.active_recipient = None

                    elif event_type == "chat_msg":
                        sender, content = payload
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        if sender == "SYSTEM":
                            self._append_chat(f"[{timestamp}] 📢 {content}", "system")
                            self._refresh_users()
                        else:
                            self._append_chat(f"[{timestamp}] {sender}: {content}", "peer")

                    elif event_type == "file_received":
                        sender, filename, is_valid, save_path = payload
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        status_text = "Verified ✅" if is_valid else "TAMPERED ❌"
                        self._append_chat(
                            f"[{timestamp}] 📎 Received '{filename}' from {sender} -> Saved to {save_path} [{status_text}]",
                            "file"
                        )

                    elif event_type == "live_packet":
                        direction, mtype, length, raw_bytes, plain, valid = payload
                        self._add_live_packet(direction, mtype, length, raw_bytes, plain, valid)

                    elif event_type == "system_msg":
                        self._append_chat(payload, "system")

                except Exception as inner_err:
                    print(f"Error handling UI event '{event_type}': {inner_err}")

        finally:
            if getattr(self, 'root', None):
                self.root.after(100, self._process_ui_queue)

    def _add_live_packet(self, direction: str, mtype: str, length: int, raw_bytes: bytes, plain: Any, valid: bool):
        """Append live packet to the in-app Wireshark sniffer tree"""
        if not hasattr(self, "sniff_tree") or not self.sniff_tree:
            return

        pkt_id = len(self.live_packets_cache) + 1
        hmac_status = "Valid ✅" if valid else "FAIL ❌"
        dir_icon = "➔ OUT" if direction == "OUT" else "⬅ IN"

        # Format hex dump
        hex_dump = bytes_to_hex_dump(raw_bytes) if bytes_to_hex_dump else ""

        # Format plain text summary
        plain_str = json.dumps(plain, indent=2) if isinstance(plain, (dict, list)) else str(plain or "")

        pkt_record = {
            "id": pkt_id,
            "dir": dir_icon,
            "proto": "TLSv1.3",
            "type": mtype,
            "length": length,
            "hmac": hmac_status,
            "hex": hex_dump,
            "plain": plain_str,
            "time": datetime.now().strftime("%H:%M:%S")
        }
        self.live_packets_cache.append(pkt_record)

        self.sniff_tree.insert("", "end", iid=str(pkt_id), values=(dir_icon, "TLSv1.3", mtype, length, hmac_status))

        # Auto-scroll and select latest packet
        self.sniff_tree.selection_set(str(pkt_id))
        self.sniff_tree.see(str(pkt_id))
        self._show_sniff_detail(pkt_record)

    def _show_sniff_detail(self, pkt: dict):
        if not hasattr(self, "sniff_detail") or not self.sniff_detail:
            return
        self.sniff_detail.config(state="normal")
        self.sniff_detail.delete("1.0", "end")
        content = (
            f"Frame #{pkt['id']} [{pkt['time']}] {pkt['dir']} {pkt['type']} ({pkt['length']} Bytes)\n"
            f"Protocol: TLSv1.3 / ECCP Wire Record | Integrity: {pkt['hmac']}\n\n"
            f"--- [ Decrypted Memory Plaintext ] ---\n{pkt['plain']}\n\n"
            f"--- [ Over-The-Wire Encrypted Hex Dump ] ---\n{pkt['hex']}"
        )
        self.sniff_detail.insert("end", content)
        self.sniff_detail.config(state="disabled")

    def _on_sniff_packet_selected(self, event):
        sel = self.sniff_tree.selection()
        if not sel:
            return
        try:
            pkt_id = int(sel[0])
            matched = [p for p in self.live_packets_cache if p["id"] == pkt_id]
            if matched:
                self._show_sniff_detail(matched[0])
        except Exception:
            pass

    def _clear_live_sniffer(self):
        if hasattr(self, "sniff_tree") and self.sniff_tree:
            self.sniff_tree.delete(*self.sniff_tree.get_children())
            self.live_packets_cache.clear()
            if hasattr(self, "sniff_detail") and self.sniff_detail:
                self.sniff_detail.config(state="normal")
                self.sniff_detail.delete("1.0", "end")
                self.sniff_detail.config(state="disabled")

    def _open_web_simulator(self):
        """Launch the interactive web-based packet flow simulator"""
        sim_script = os.path.join(_root_dir, "src", "tools", "run_simulator.py")
        html_file = os.path.join(_root_dir, "src", "tools", "packet_visualizer.html")

        try:
            subprocess.Popen([sys.executable, sim_script], cwd=_root_dir)
            if self.chat_frame:
                self._append_chat("🌐 Launched Interactive Packet Simulator at http://127.0.0.1:8080", "system")
        except Exception:
            try:
                import webbrowser
                webbrowser.open("file://" + os.path.abspath(html_file))
            except Exception as e:
                messagebox.showerror("Simulator Error", f"Could not launch simulator: {e}")

    def _open_packet_inspector(self):
        """Open embedded desktop Wireshark Packet Tracer & Dissector window"""
        if not ScenarioEngine:
            messagebox.showerror("Packet Tracer", "Packet tracer scenario engine not found.")
            return

        win = tk.Toplevel(self.root)
        win.title("📡 ECCP Wireshark Packet Tracer & Protocol Dissector")
        win.geometry("960x650")
        win.minsize(820, 520)
        win.configure(bg=self.bg_dark)

        # Scenario definitions
        scenarios = {
            "1. TLS 1.3 Handshake & Key Exchange (TCP SYN/ACK + Client/Server Hello)": ScenarioEngine.get_tls13_handshake_scenario,
            "2. Secure Authentication (bcrypt Hash over TLS + Session Token)": ScenarioEngine.get_auth_scenario,
            "3. End-to-End Encrypted Chat (Alice → Server → Bob with HMAC)": ScenarioEngine.get_messaging_scenario,
            "4. Secure File Transfer (Chunked Transmission + SHA-256)": ScenarioEngine.get_file_transfer_scenario,
            "5. MITM Attack & Integrity Defense (Tampered Packet Detected)": ScenarioEngine.get_mitm_attack_scenario
        }

        # Top Control Bar
        ctl_bar = ttk.Frame(win, style="Panel.TFrame", padding=10)
        ctl_bar.pack(fill="x", side="top")

        ttk.Label(ctl_bar, text="Scenario:", font=("Segoe UI", 10, "bold"), background=self.bg_panel).pack(side="left", padx=(0, 6))

        scen_combo = ttk.Combobox(ctl_bar, values=list(scenarios.keys()), state="readonly", width=55)
        scen_combo.current(2)  # Default: Scenario 3
        scen_combo.pack(side="left", padx=(0, 10))

        export_btn = ttk.Button(ctl_bar, text="📥 Export PCAP", style="Modern.TButton")
        export_btn.pack(side="right", padx=5)

        web_btn = ttk.Button(ctl_bar, text="🌐 Web Simulator", style="Accent.TButton", command=self._open_web_simulator)
        web_btn.pack(side="right", padx=5)

        # Paned Window (Top: Packet Table, Bottom: Inspection & Hex)
        main_paned = ttk.PanedWindow(win, orient="vertical")
        main_paned.pack(fill="both", expand=True, padx=10, pady=10)

        # --- Top Table Pane ---
        table_frame = ttk.Frame(main_paned, style="Panel.TFrame", padding=5)
        main_paned.add(table_frame, weight=3)

        cols = ("no", "time", "src", "dst", "proto", "len", "info")
        tree = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")
        tree.heading("no", text="No.")
        tree.heading("time", text="Time (s)")
        tree.heading("src", text="Source")
        tree.heading("dst", text="Destination")
        tree.heading("proto", text="Protocol")
        tree.heading("len", text="Length")
        tree.heading("info", text="Info")

        tree.column("no", width=45, anchor="center")
        tree.column("time", width=75, anchor="center")
        tree.column("src", width=140)
        tree.column("dst", width=140)
        tree.column("proto", width=75, anchor="center")
        tree.column("len", width=55, anchor="center")
        tree.column("info", width=380)

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        # --- Bottom Notebook Pane ---
        bottom_frame = ttk.Frame(main_paned, style="Panel.TFrame", padding=5)
        main_paned.add(bottom_frame, weight=4)

        notebook = ttk.Notebook(bottom_frame)
        notebook.pack(fill="both", expand=True)

        # Tab 1: Layer Dissection
        dpi_tab = ttk.Frame(notebook, style="Panel.TFrame", padding=10)
        notebook.add(dpi_tab, text="  Deep Packet Inspection (Layers)  ")

        dpi_text = tk.Text(dpi_tab, bg=self.bg_chat, fg=self.text_light, font=("Consolas", 10),
                           wrap="word", bd=0, padx=8, pady=8)
        dpi_text.pack(fill="both", expand=True)
        dpi_text.tag_configure("header", foreground=self.accent, font=("Consolas", 10, "bold"))
        dpi_text.tag_configure("highlight", foreground=self.success_color)
        dpi_text.tag_configure("alert", foreground=self.error_color, font=("Consolas", 10, "bold"))

        # Tab 2: Wire Comparison
        wire_tab = ttk.Frame(notebook, style="Panel.TFrame", padding=10)
        notebook.add(wire_tab, text="  Wire Comparison (Plaintext vs Ciphertext)  ")

        wire_paned = ttk.PanedWindow(wire_tab, orient="horizontal")
        wire_paned.pack(fill="both", expand=True)

        plain_box = ttk.Frame(wire_paned, style="Panel.TFrame", padding=5)
        wire_paned.add(plain_box, weight=1)
        ttk.Label(plain_box, text="🔓 Application Layer (Memory Plaintext)", foreground=self.success_color,
                  font=("Segoe UI", 10, "bold"), background=self.bg_panel).pack(anchor="w", pady=(0, 5))
        plain_text = tk.Text(plain_box, bg=self.bg_chat, fg=self.text_light, font=("Consolas", 10),
                             wrap="word", bd=0, padx=6, pady=6)
        plain_text.pack(fill="both", expand=True)

        cipher_box = ttk.Frame(wire_paned, style="Panel.TFrame", padding=5)
        wire_paned.add(cipher_box, weight=1)
        ttk.Label(cipher_box, text="🔒 Network Wire (Wireshark Encrypted Capture)", foreground=self.accent,
                  font=("Segoe UI", 10, "bold"), background=self.bg_panel).pack(anchor="w", pady=(0, 5))
        cipher_text = tk.Text(cipher_box, bg=self.bg_chat, fg=self.text_dim, font=("Consolas", 10),
                              wrap="word", bd=0, padx=6, pady=6)
        cipher_text.pack(fill="both", expand=True)

        # Tab 3: Hex Dump
        hex_tab = ttk.Frame(notebook, style="Panel.TFrame", padding=10)
        notebook.add(hex_tab, text="  Wireshark Hex & ASCII Dump  ")

        hex_text = tk.Text(hex_tab, bg="#0b0d14", fg="#38bdf8", font=("Consolas", 10),
                           wrap="none", bd=0, padx=10, pady=10)
        hex_vsb = ttk.Scrollbar(hex_tab, orient="vertical", command=hex_text.yview)
        hex_text.configure(yscrollcommand=hex_vsb.set)
        hex_text.pack(side="left", fill="both", expand=True)
        hex_vsb.pack(side="right", fill="y")

        current_frames = []

        def load_scenario(scen_name):
            nonlocal current_frames
            tree.delete(*tree.get_children())
            func = scenarios[scen_name]
            current_frames = func()

            for f in current_frames:
                t_str = f"{f.timestamp - current_frames[0].timestamp:0.4f}"
                src_str = f"{f.src_ip}:{f.src_port}" if f.src_port else f.src_ip
                dst_str = f"{f.dst_ip}:{f.dst_port}" if f.dst_port else f.dst_ip
                tree.insert("", "end", iid=str(f.frame_num),
                            values=(f.frame_num, t_str, src_str, dst_str, f.protocol, f.length, f.info))

            if current_frames:
                tree.selection_set(str(current_frames[0].frame_num))
                on_select_packet(None)

        def on_select_packet(event):
            sel = tree.selection()
            if not sel:
                return
            frame_num = int(sel[0])
            matched = [f for f in current_frames if f.frame_num == frame_num]
            if not matched:
                return
            pkt = matched[0]

            # 1. Update DPI text
            dpi_text.config(state="normal")
            dpi_text.delete("1.0", "end")
            dpi_text.insert("end", f"Frame #{pkt.frame_num}: {pkt.info}\n\n", "header")

            for layer, content in pkt.layers.items():
                is_alert = "ATTACK" in pkt.protocol or "SECURITY" in pkt.protocol
                tag = "alert" if is_alert else "header"
                dpi_text.insert("end", f"▼ {layer}\n", tag)
                if isinstance(content, dict):
                    for k, v in content.items():
                        dpi_text.insert("end", f"    • {k}: {v}\n")
                else:
                    dpi_text.insert("end", f"    {content}\n")
                dpi_text.insert("end", "\n")
            dpi_text.config(state="disabled")

            # 2. Update Wire Comparison
            plain_text.config(state="normal")
            plain_text.delete("1.0", "end")
            plain_text.insert("end", pkt.plain_payload or "(No application plaintext payload)")
            plain_text.config(state="disabled")

            cipher_text.config(state="normal")
            cipher_text.delete("1.0", "end")
            cipher_msg = (
                f"[TLS 1.3 Record - Length: {pkt.length} Bytes]\n"
                f"Protocol: {pkt.protocol} | Endpoints: {pkt.src_ip}:{pkt.src_port} -> {pkt.dst_ip}:{pkt.dst_port}\n\n"
                f"Wire Payload (AES-256-GCM Encrypted Ciphertext):\n\n"
                f"{pkt.get_hex_dump()}"
            )
            cipher_text.insert("end", cipher_msg)
            cipher_text.config(state="disabled")

            # 3. Update Hex Dump
            hex_text.config(state="normal")
            hex_text.delete("1.0", "end")
            hex_text.insert("end", pkt.get_hex_dump())
            hex_text.config(state="disabled")

        def on_export_pcaps():
            if export_all_pcaps:
                p_dir = os.path.join(_root_dir, "pcaps")
                gen = export_all_pcaps(p_dir)
                messagebox.showinfo("Export PCAPs", f"Successfully exported {len(gen)} PCAP files to:\n{p_dir}\n\nYou can now open them directly in Wireshark!")

        scen_combo.bind("<<ComboboxSelected>>", lambda e: load_scenario(scen_combo.get()))
        tree.bind("<<TreeviewSelect>>", on_select_packet)
        export_btn.config(command=on_export_pcaps)

        load_scenario(scen_combo.get())

    def _on_logout(self):
        """Handle logout action"""
        if self.client.connected:
            self.client.logout()
        self.is_connected = False
        self._show_auth_screen()

    def _on_close(self):
        """Handle window close event"""
        try:
            if self.client.connected:
                self.client.logout()
        except Exception:
            pass
        self.root.destroy()


def main():
    root = tk.Tk()
    app = ModernChatGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
