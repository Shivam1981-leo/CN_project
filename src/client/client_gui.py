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
import subprocess
from datetime import datetime
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


class ModernChatGUI:
    """Modern Tkinter GUI for the ECCP Secure Client"""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("ECCP Secure Messenger - TLS 1.3")
        self.root.geometry("880x640")
        self.root.minsize(720, 500)

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
        self.auth_status_lbl.pack(pady=15)

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
        logout_btn.pack(side="right", padx=10)

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

        self._refresh_users()
        self._start_gui_receiver()

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
            self.ui_queue.put(("register_result", success))

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

    def _process_ui_queue(self):
        """Consume queued events from background worker threads"""
        while not self.ui_queue.empty():
            try:
                event_type, payload = self.ui_queue.get_nowait()

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
                        self.user_listbox.delete(0, "end")
                        for user in payload:
                            if user != self.client.username:
                                self.user_listbox.insert("end", user)

                elif event_type == "chat_msg":
                    sender, content = payload
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    self._append_chat(f"[{timestamp}] {sender}: {content}", "peer")

                elif event_type == "file_received":
                    sender, filename, is_valid, save_path = payload
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    status_text = "Verified ✅" if is_valid else "TAMPERED ❌"
                    self._append_chat(
                        f"[{timestamp}] 📎 Received '{filename}' from {sender} -> Saved to {save_path} [{status_text}]",
                        "file"
                    )

                elif event_type == "system_msg":
                    self._append_chat(payload, "system")

            except queue.Empty:
                break

        self.root.after(100, self._process_ui_queue)

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
