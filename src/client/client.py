"""
Secure Client Application
Client for encrypted communication with the secure server
"""

import socket
import ssl
import sys
import os
import threading
import queue
from typing import Optional
import getpass
import base64

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except (AttributeError, Exception):
        pass

# Add parent and root directory to path
_src_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_root_dir = os.path.dirname(_src_dir)
for p in [_src_dir, _root_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

from common.protocol import (
    ProtocolMessage, MessageType, StatusCode,
    create_auth_request, create_register_request,
    create_message_send, create_file_send
)
from common.crypto_utils import CryptoUtils, generate_file_checksum, verify_file_checksum


class SecureClient:
    """Secure client with TLS/SSL encryption"""

    def __init__(self, host: str = 'localhost', port: int = 5000,
                 ca_cert: str = 'certs/server.crt'):
        self.host = host
        self.port = port
        self.ca_cert = ca_cert

        self.socket: Optional[ssl.SSLSocket] = None
        self.session_token: Optional[str] = None
        self.username: Optional[str] = None
        self.connected = False
        self.running = False

        # Protocol secret key (must match server)
        self.protocol_key = b'secure_protocol_key_change_in_production'

        # Lock for thread-safe operations
        self.lock = threading.Lock()

        # Thread-safe queue for responses to commands
        self.response_queue = queue.Queue()
        self.receiver_thread: Optional[threading.Thread] = None

        # Optional GUI / event callbacks
        self.on_message_callback = None
        self.on_file_callback = None
        self.on_packet_callback = None

    def connect(self) -> bool:
        """Connect to the server with TLS/SSL"""
        try:
            # Create SSL context
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.load_verify_locations(self.ca_cert)

            # For self-signed certificates in development
            # context.check_hostname = False
            # context.verify_mode = ssl.CERT_NONE

            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket = context.wrap_socket(sock, server_hostname=self.host)

            # Connect
            self.socket.connect((self.host, self.port))
            self.connected = True

            print(f" Connected to server at {self.host}:{self.port}")
            print(f"🔒 TLS version: {self.socket.version()}")

            return True

        except FileNotFoundError:
            print(f" Error: Certificate file not found: {self.ca_cert}")
            print("Run 'bash certs/generate_certs.sh' to generate certificates")
            return False
        except ConnectionRefusedError:
            print(f" Error: Connection refused. Is the server running?")
            return False
        except Exception as e:
            print(f" Connection failed: {e}")
            return False

    def register(self, username: str, password: str) -> bool:
        """Register a new user"""
        if not self.connected:
            print(" Not connected to server")
            return False

        # Hash password (deterministic pre-hash for secure transmission over TLS)
        password_hash = CryptoUtils.hash_data(password.encode('utf-8'))

        # Create registration request
        message = create_register_request(username, password_hash)

        # Send request
        self._send_message(message)

        # Receive response
        response = self._receive_message()
        if not response:
            print(" No response from server")
            return False

        message, checksum_valid = response

        if not checksum_valid:
            print(" Response integrity check failed")
            return False

        if message.msg_type == MessageType.REGISTER_RESPONSE:
            status = StatusCode(message.data.get('status'))

            if status == StatusCode.SUCCESS:
                print(f" Registration successful! You can now login.")
                return True
            elif status == StatusCode.USER_EXISTS:
                print(" Username already exists")
                return False
            else:
                print(f" Registration failed: {status}")
                return False
        else:
            print(f" Unexpected response: {message.msg_type}")
            return False

    def login(self, username: str, password: str) -> bool:
        """Login with credentials"""
        if not self.connected:
            print(" Not connected to server")
            return False

        # Hash password (deterministic pre-hash for secure transmission over TLS)
        password_hash = CryptoUtils.hash_data(password.encode('utf-8'))

        # Create authentication request
        message = create_auth_request(username, password_hash)

        # Send request
        self._send_message(message)

        # Receive response
        response = self._receive_message()
        if not response:
            print(" No response from server")
            return False

        message, checksum_valid = response

        if not checksum_valid:
            print(" Response integrity check failed")
            return False

        if message.msg_type == MessageType.AUTH_RESPONSE:
            status = StatusCode(message.data.get('status'))

            if status == StatusCode.SUCCESS:
                self.session_token = message.data.get('session_token')
                self.username = username
                print(f" Login successful! Welcome, {username}")

                # Start message receiver thread
                self.running = True
                self.receiver_thread = threading.Thread(
                    target=self._receive_messages_loop,
                    daemon=True
                )
                self.receiver_thread.start()

                return True
            else:
                print(f" Login failed: Invalid credentials")
                return False
        else:
            print(f" Unexpected response: {message.msg_type}")
            return False

    def send_message(self, recipient: str, content: str) -> bool:
        """Send a message to another user"""
        if not self.session_token:
            print(" Not authenticated")
            return False

        # Create message
        message = create_message_send(recipient, content, self.session_token)

        # Send message
        self._send_message(message)

        # Receive acknowledgment
        response = self._receive_message()
        if not response:
            print(" No response from server")
            return False

        message, checksum_valid = response

        if message.msg_type == MessageType.MESSAGE_ACK:
            status = StatusCode(message.data.get('status'))

            if status == StatusCode.SUCCESS:
                print(f" Message sent to {recipient}")
                return True
            elif status == StatusCode.USER_NOT_FOUND:
                print(f" User '{recipient}' not found")
                return False
            else:
                print(f" Failed to send message: {status}")
                return False
        else:
            print(f" Unexpected response: {message.msg_type}")
            return False

    def send_file(self, recipient: str, filepath: str) -> bool:
        """Send a file securely to another user"""
        if not self.session_token:
            print("❌ Not authenticated")
            return False

        if not os.path.exists(filepath):
            print(f"❌ File not found: {filepath}")
            return False

        filesize = os.path.getsize(filepath)
        if filesize > 10 * 1024 * 1024:
            print("❌ File too large (maximum size is 10 MB)")
            return False

        filename = os.path.basename(filepath)
        checksum = generate_file_checksum(filepath)

        try:
            with open(filepath, 'rb') as f:
                file_bytes = f.read()

            file_data_b64 = base64.b64encode(file_bytes).decode('utf-8')

            message = create_file_send(
                recipient=recipient,
                filename=filename,
                file_data_base64=file_data_b64,
                checksum=checksum,
                session_token=self.session_token,
                file_size=filesize
            )

            self._send_message(message)
            response = self._receive_message()
            if not response:
                print("❌ No response from server")
                return False

            resp_msg, checksum_valid = response
            if resp_msg.msg_type == MessageType.MESSAGE_ACK:
                status = StatusCode(resp_msg.data.get('status'))
                if status == StatusCode.SUCCESS:
                    print(f"✅ File '{filename}' sent successfully to {recipient} (SHA-256: {checksum[:12]}...)")
                    return True
                elif status == StatusCode.USER_NOT_FOUND:
                    print(f"❌ Recipient '{recipient}' not online or not found")
                    return False
                else:
                    print(f"❌ Failed to send file: {status.name}")
                    return False
            return False

        except Exception as e:
            print(f"❌ Error sending file: {e}")
            return False

    def list_users(self) -> list:
        """Get list of online users"""
        if not self.session_token:
            print(" Not authenticated")
            return []

        message = ProtocolMessage(MessageType.USER_LIST_REQUEST, {
            'session_token': self.session_token
        })

        self._send_message(message)

        response = self._receive_message()
        if not response:
            return []

        message, checksum_valid = response

        if message.msg_type == MessageType.USER_LIST_RESPONSE:
            users = message.data.get('users', [])
            return users
        else:
            return []

    def logout(self):
        """Logout and disconnect"""
        if self.session_token:
            message = ProtocolMessage(MessageType.LOGOUT, {
                'session_token': self.session_token
            })
            self._send_message(message)

        self.running = False
        self.session_token = None
        self.username = None

        if self.socket:
            self.socket.close()
            self.connected = False

        print("👋 Logged out")

    def _send_message(self, message: ProtocolMessage):
        """Send message to server"""
        with self.lock:
            data = message.pack(self.protocol_key)

            # Send length prefix
            length = len(data)
            self.socket.sendall(length.to_bytes(4, 'big'))

            # Send data
            self.socket.sendall(data)

            if self.on_packet_callback:
                try:
                    self.on_packet_callback("OUT", message.msg_type.name, length, data, message.data, True)
                except Exception:
                    pass

    def _read_raw_message(self) -> Optional[bytes]:
        """Low-level socket read of length-prefixed bytes"""
        try:
            length_bytes = self.socket.recv(4)
            if not length_bytes:
                return None

            length = int.from_bytes(length_bytes, 'big')

            data = b''
            while len(data) < length:
                chunk = self.socket.recv(min(length - len(data), 4096))
                if not chunk:
                    return None
                data += chunk

            return data
        except Exception:
            return None

    def _receive_message(self, timeout: float = 5.0) -> Optional[tuple]:
        """
        Receive message from server.
        If the background receiver thread is running, retrieves from response queue.
        Otherwise (e.g. during login/register), reads directly from the socket.
        """
        if self.running and self.receiver_thread and self.receiver_thread.is_alive():
            try:
                return self.response_queue.get(timeout=timeout)
            except queue.Empty:
                return None

        # Direct read on socket before receiver thread is active
        data = self._read_raw_message()
        if not data:
            return None
        try:
            res = ProtocolMessage.unpack(data, self.protocol_key)
            msg, valid = res
            if self.on_packet_callback:
                try:
                    self.on_packet_callback("IN", msg.msg_type.name, len(data), data, msg.data, valid)
                except Exception:
                    pass
            return res
        except Exception:
            return None

    def _receive_messages_loop(self):
        """Background thread to receive incoming messages and dispatch them"""
        while self.running:
            data = self._read_raw_message()
            if not data:
                break

            try:
                message, checksum_valid = ProtocolMessage.unpack(data, self.protocol_key)
                if self.on_packet_callback:
                    try:
                        self.on_packet_callback("IN", message.msg_type.name, len(data), data, message.data, checksum_valid)
                    except Exception:
                        pass
            except Exception:
                continue

            if not checksum_valid:
                print("\n⚠️ Warning: Received message with invalid checksum")
                continue

            # Incoming chat message
            if message.msg_type == MessageType.MESSAGE_RECEIVE:
                sender = message.data.get('sender')
                content = message.data.get('content')
                if self.on_message_callback:
                    self.on_message_callback(sender, content)
                else:
                    print(f"\n📨 New message from {sender}: {content}")
                    print("> ", end="", flush=True)

            # Incoming file transfer
            elif message.msg_type == MessageType.FILE_RECEIVE:
                sender = message.data.get('sender')
                filename = message.data.get('filename')
                file_data_b64 = message.data.get('file_data')
                expected_checksum = message.data.get('checksum')

                os.makedirs('received_files', exist_ok=True)
                save_path = os.path.join('received_files', filename)

                try:
                    file_bytes = base64.b64decode(file_data_b64.encode('utf-8'))
                    with open(save_path, 'wb') as f:
                        f.write(file_bytes)

                    is_valid = verify_file_checksum(save_path, expected_checksum)
                    if self.on_file_callback:
                        self.on_file_callback(sender, filename, is_valid, save_path)
                    else:
                        if is_valid:
                            print(f"\n📎 [FILE RECEIVED] '{filename}' from {sender} saved to '{save_path}' (Integrity: Verified ✅)")
                        else:
                            print(f"\n⚠️ [FILE RECEIVED] '{filename}' from {sender} CORRUPTED or TAMPERED! (Integrity check failed ❌)")
                        print("> ", end="", flush=True)
                except Exception as e:
                    print(f"\n❌ Error saving received file '{filename}': {e}")
                    print("> ", end="", flush=True)

            # Synchronous responses to commands (ACKs, User lists, etc.)
            else:
                self.response_queue.put((message, checksum_valid))

    def interactive_mode(self):
        """Interactive command-line interface"""
        print("\n" + "=" * 60)
        print("  Encrypted Client-Server Communication")
        print("=" * 60)

        if not self.connect():
            return

        # Login or register
        while True:
            print("\n1. Login")
            print("2. Register")
            print("3. Exit")

            choice = input("\nChoice: ").strip()

            if choice == '1':
                username = input("Username: ").strip()
                password = getpass.getpass("Password: ")

                if self.login(username, password):
                    break
            elif choice == '2':
                username = input("Username: ").strip()
                password = getpass.getpass("Password: ")
                password2 = getpass.getpass("Confirm password: ")

                if password != password2:
                    print(" Passwords don't match")
                    continue

                if len(password) < 6:
                    print(" Password must be at least 6 characters")
                    continue

                self.register(username, password)
            elif choice == '3':
                return
            else:
                print("Invalid choice")

        # Main command loop
        self._command_loop()

    def _command_loop(self):
        """Main command loop after authentication"""
        print("\n" + "=" * 60)
        print(f"  Logged in as: {self.username}")
        print("=" * 60)
        print("\nCommands:")
        print("  send <user> <message>      - Send a message")
        print("  sendfile <user> <filepath> - Send a file securely")
        print("  list                       - List online users")
        print("  help                       - Show this help")
        print("  logout                     - Logout and exit")
        print()

        while self.running:
            try:
                command = input("> ").strip()

                if not command:
                    continue

                parts = command.split(None, 2)
                cmd = parts[0].lower()

                if cmd == 'send':
                    if len(parts) < 3:
                        print("Usage: send <user> <message>")
                        continue

                    recipient = parts[1]
                    message = parts[2]
                    self.send_message(recipient, message)

                elif cmd == 'sendfile':
                    if len(parts) < 3:
                        print("Usage: sendfile <user> <filepath>")
                        continue

                    recipient = parts[1]
                    filepath = parts[2]
                    self.send_file(recipient, filepath)

                elif cmd == 'list':
                    users = self.list_users()
                    if users:
                        print("\n👥 Online users:")
                        for user in users:
                            if user != self.username:
                                print(f"  • {user}")
                    else:
                        print("No users online")

                elif cmd == 'help':
                    print("\nCommands:")
                    print("  send <user> <message>      - Send a message")
                    print("  sendfile <user> <filepath> - Send a file securely")
                    print("  list                       - List online users")
                    print("  help                       - Show this help")
                    print("  logout                     - Logout and exit")

                elif cmd == 'logout' or cmd == 'exit' or cmd == 'quit':
                    self.logout()
                    break

                else:
                    print(f"Unknown command: {cmd}")
                    print("Type 'help' for available commands")

            except KeyboardInterrupt:
                print("\n\nUse 'logout' to exit")
            except EOFError:
                self.logout()
                break


def main():
    """Main entry point"""
    client = SecureClient()
    client.interactive_mode()


if __name__ == "__main__":
    main()
