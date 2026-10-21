"""
Secure Server with TLS/SSL Support
Main server application handling client connections and message routing
"""

import socket
import ssl
import threading
import json
import logging
import sys
import os
from datetime import datetime
from typing import Dict, Optional

# Add parent directory to path
_src_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_root_dir = os.path.dirname(_src_dir)
for p in [_src_dir, _root_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

from common.protocol import (
    ProtocolMessage, MessageType, StatusCode,
    create_auth_response, create_register_response,
    create_message_receive, create_message_ack,
    create_error_response, create_user_list_response,
    create_file_receive, create_file_ack
)
from common.crypto_utils import CryptoUtils, SecureSessionManager

try:
    from common.traffic_logger import traffic_logger
except ImportError:
    traffic_logger = None

try:
    from server.user_db import UserDatabase
    from server.auth import AuthenticationHandler
except (ImportError, ModuleNotFoundError):
    from user_db import UserDatabase
    from auth import AuthenticationHandler


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/server.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('SecureServer')


class SecureServer:
    """Secure server with TLS/SSL encryption"""

    def __init__(self, host: str = 'localhost', port: int = 5050,
                 cert_file: str = 'certs/server.crt',
                 key_file: str = 'certs/server.key'):
        self.host = host
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file

        # Initialize components
        self.database = UserDatabase('data/users.db')
        self.session_manager = SecureSessionManager(os.urandom(32))
        self.auth_handler = AuthenticationHandler(self.database, self.session_manager)

        # Active connections: session_token -> (socket, username)
        self.active_clients: Dict[str, tuple] = {}
        # Username -> session_token mapping for quick lookup
        self.username_to_token: Dict[str, str] = {}

        self.server_socket = None
        self.running = False
        self.lock = threading.Lock()

        # Protocol secret key (shared with clients for HMAC)
        self.protocol_key = b'secure_protocol_key_change_in_production'

    def start(self):
        """Start the secure server"""
        try:
            # Create logs directory if it doesn't exist
            os.makedirs('logs', exist_ok=True)
            os.makedirs('data', exist_ok=True)

            # Create TCP socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            try:
                self.server_socket.bind((self.host, self.port))
            except OSError as err:
                if getattr(err, 'winerror', None) in (10013, 10048) or err.errno in (98, 48, 10048):
                    fallback_port = 5050 if self.port != 5050 else 5055
                    logger.warning(f"Port {self.port} is unavailable/restricted. Trying fallback port {fallback_port}...")
                    self.port = fallback_port
                    self.server_socket.bind((self.host, self.port))
                else:
                    raise

            self.server_socket.listen(5)

            # Wrap with SSL/TLS
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)

            # Use TLS 1.3 (most secure)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.maximum_version = ssl.TLSVersion.TLSv1_3

            self.ssl_socket = context.wrap_socket(
                self.server_socket,
                server_side=True
            )

            self.running = True
            logger.info(f"🔒 Secure server started on {self.host}:{self.port}")
            logger.info(f"Using TLS with certificate: {self.cert_file}")

            # Start session cleanup thread
            cleanup_thread = threading.Thread(target=self._cleanup_sessions, daemon=True)
            cleanup_thread.start()

            # Accept connections
            self._accept_connections()

        except FileNotFoundError as e:
            logger.error(f"Certificate files not found: {e}")
            logger.error("Run 'bash certs/generate_certs.sh' to generate certificates")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Failed to start server: {e}")
            sys.exit(1)

    def _accept_connections(self):
        """Accept incoming client connections"""
        logger.info("Waiting for client connections...")

        while self.running:
            try:
                client_socket, address = self.ssl_socket.accept()
                logger.info(f"New connection from {address}")

                # Handle client in separate thread
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, address),
                    daemon=True
                )
                client_thread.start()

            except Exception as e:
                if self.running:
                    logger.error(f"Error accepting connection: {e}")

    def _handle_client(self, client_socket: ssl.SSLSocket, address: tuple):
        """Handle individual client connection"""
        session_token = None
        username = None

        try:
            logger.info(f"Client {address} connected via TLS {client_socket.version()}")

            while self.running:
                # Receive message
                data = self._receive_message(client_socket)
                if not data:
                    break

                # Parse message
                try:
                    message, checksum_valid = ProtocolMessage.unpack(data, self.protocol_key)

                    if not checksum_valid:
                        logger.warning(f"Invalid checksum from {address}")
                        response = create_error_response(
                            StatusCode.CHECKSUM_MISMATCH,
                            "Message integrity check failed"
                        )
                        self._send_message(client_socket, response)
                        continue

                    # Handle message based on type
                    response = self._process_message(message, session_token, username)

                    # Log live incoming packet
                    if traffic_logger:
                        from_n = (username.lower() if username and username.lower() in ["alice", "bob"] else "alice")
                        traffic_logger.log_packet(
                            src=f"{address[0]}:{address[1]}",
                            dst=f"{self.host}:{self.port}",
                            from_node=from_n,
                            to_node="server",
                            proto="TLSv1.3",
                            msg_type_name=message.msg_type.name,
                            length=len(data),
                            info=f"[{message.msg_type.name}] from {username or address}",
                            plain_data=message.data,
                            raw_bytes=data
                        )

                    # Update session info if authentication was successful
                    if message.msg_type == MessageType.AUTH_REQUEST and response:
                        if response.data.get('status') == StatusCode.SUCCESS.value:
                            session_token = response.data.get('session_token')
                            _, username = self.session_manager.validate_session(session_token)

                            with self.lock:
                                self.active_clients[session_token] = (client_socket, username)
                                self.username_to_token[username] = session_token

                            logger.info(f"User '{username}' authenticated from {address}")

                            # Deliver offline messages
                            self._deliver_offline_messages(client_socket, username)

                    # Send response
                    if response:
                        self._send_message(client_socket, response)
                        if traffic_logger:
                            to_n = (username.lower() if username and username.lower() in ["alice", "bob"] else "alice")
                            traffic_logger.log_packet(
                                src=f"{self.host}:{self.port}",
                                dst=f"{address[0]}:{address[1]}",
                                from_node="server",
                                to_node=to_n,
                                proto="TLSv1.3",
                                msg_type_name=response.msg_type.name,
                                length=len(response.pack(self.protocol_key)),
                                info=f"Server response [{response.msg_type.name}] to {username or address}",
                                plain_data=response.data,
                                raw_bytes=response.pack(self.protocol_key)
                            )

                    # Broadcast presence when a user successfully authenticates
                    if message.msg_type == MessageType.AUTH_REQUEST and response:
                        if response.data.get('status') == StatusCode.SUCCESS.value and username:
                            self._broadcast_presence(username, joined=True)

                except ValueError as e:
                    logger.error(f"Protocol error from {address}: {e}")
                    response = create_error_response(
                        StatusCode.PROTOCOL_ERROR,
                        str(e)
                    )
                    self._send_message(client_socket, response)

        except Exception as e:
            logger.error(f"Error handling client {address}: {e}")
        finally:
            # Cleanup
            if session_token:
                with self.lock:
                    if session_token in self.active_clients:
                        del self.active_clients[session_token]
                    if username in self.username_to_token:
                        del self.username_to_token[username]

                self.session_manager.revoke_session(session_token)
                if username:
                    self._broadcast_presence(username, joined=False)

            client_socket.close()
            logger.info(f"Client {address} disconnected")

    def _process_message(self, message: ProtocolMessage,
                        session_token: Optional[str],
                        username: Optional[str]) -> Optional[ProtocolMessage]:
        """Process received message and generate response"""

        msg_type = message.msg_type
        data = message.data

        # Authentication messages
        if msg_type == MessageType.AUTH_REQUEST:
            return self._handle_auth_request(data)

        elif msg_type == MessageType.REGISTER_REQUEST:
            return self._handle_register_request(data)

        # Require authentication for other messages
        if not session_token:
            return create_error_response(
                StatusCode.INVALID_SESSION,
                "Authentication required"
            )

        # Validate session
        valid, _ = self.session_manager.validate_session(session_token)
        if not valid:
            return create_error_response(
                StatusCode.INVALID_SESSION,
                "Session expired or invalid"
            )

        # Authenticated message handlers
        if msg_type == MessageType.MESSAGE_SEND:
            return self._handle_message_send(data, username)

        elif msg_type in (MessageType.FILE_SEND_DATA, MessageType.FILE_SEND_REQUEST):
            return self._handle_file_send(data, username)

        elif msg_type == MessageType.USER_LIST_REQUEST:
            return self._handle_user_list_request()

        elif msg_type == MessageType.PING:
            return ProtocolMessage(MessageType.PONG, {'timestamp': datetime.now().isoformat()})

        elif msg_type == MessageType.LOGOUT:
            if session_token:
                self.session_manager.revoke_session(session_token)
            return None

        else:
            return create_error_response(
                StatusCode.PROTOCOL_ERROR,
                f"Unsupported message type: {msg_type}"
            )

    def _handle_auth_request(self, data: dict) -> ProtocolMessage:
        """Handle authentication request"""
        username = data.get('username')
        password_hash = data.get('password_hash')

        if not username or not password_hash:
            return create_auth_response(StatusCode.AUTH_FAILED)

        # Authenticate using AuthHandler
        status, session_token = self.auth_handler.authenticate(username, password_hash)
        return create_auth_response(status, session_token)

    def _handle_register_request(self, data: dict) -> ProtocolMessage:
        """Handle user registration request"""
        username = data.get('username')
        password_hash = data.get('password_hash')

        if not username or not password_hash:
            return create_register_response(StatusCode.SERVER_ERROR)

        # Register user using AuthHandler
        status, _ = self.auth_handler.register(username, password_hash)
        return create_register_response(status)

    def _handle_file_send(self, data: dict, sender: str) -> ProtocolMessage:
        """Handle file transfer send request"""
        recipient = data.get('recipient')
        filename = data.get('filename')
        file_data = data.get('file_data')
        checksum = data.get('checksum')
        filesize = data.get('filesize', 0)

        if not recipient or not filename or not file_data or not checksum:
            return create_file_ack(StatusCode.SERVER_ERROR, filename or "")

        if not self.database.user_exists(recipient):
            return create_file_ack(StatusCode.USER_NOT_FOUND, filename)

        with self.lock:
            recipient_token = self.username_to_token.get(recipient)

        if not recipient_token:
            return create_file_ack(StatusCode.USER_NOT_FOUND, filename)

        with self.lock:
            if recipient_token in self.active_clients:
                recipient_socket, _ = self.active_clients[recipient_token]
                file_msg = create_file_receive(sender, filename, file_data, checksum, filesize)
                try:
                    self._send_message(recipient_socket, file_msg)
                    logger.info(f"File '{filename}' ({filesize}B) routed from {sender} to {recipient}")
                    if traffic_logger:
                        traffic_logger.log_packet(
                            src=f"{self.host}:{self.port}",
                            dst=f"{recipient}:5000",
                            from_node="server",
                            to_node=recipient.lower() if recipient.lower() in ["alice", "bob"] else "bob",
                            proto="TLSv1.3",
                            msg_type_name="FILE_RECEIVE",
                            length=len(file_msg.pack(self.protocol_key)),
                            info=f"Encrypted file '{filename}' ({filesize}B) delivered to '{recipient}'",
                            plain_data={"sender": sender, "filename": filename, "checksum": checksum, "filesize": filesize},
                            raw_bytes=file_msg.pack(self.protocol_key)
                        )
                    return create_file_ack(StatusCode.SUCCESS, filename)
                except Exception as e:
                    logger.error(f"Failed to route file to {recipient}: {e}")
                    return create_file_ack(StatusCode.SERVER_ERROR, filename)

        return create_file_ack(StatusCode.SERVER_ERROR, filename)

    def _handle_message_send(self, data: dict, sender: str) -> ProtocolMessage:
        """Handle message send request"""
        recipient = data.get('recipient')
        content = data.get('content')

        if not recipient or not content:
            return create_message_ack(StatusCode.SERVER_ERROR)

        # Check if recipient exists
        if not self.database.user_exists(recipient):
            return create_message_ack(StatusCode.USER_NOT_FOUND)

        # Check if recipient is online
        with self.lock:
            recipient_token = self.username_to_token.get(recipient)

        if recipient_token:
            # Deliver immediately
            with self.lock:
                if recipient_token in self.active_clients:
                    recipient_socket, _ = self.active_clients[recipient_token]

                    message = create_message_receive(sender, content)
                    try:
                        self._send_message(recipient_socket, message)
                        logger.info(f"Message delivered from {sender} to {recipient}")
                        if traffic_logger:
                            traffic_logger.log_packet(
                                src=f"{self.host}:{self.port}",
                                dst=f"{recipient}:5000",
                                from_node="server",
                                to_node=recipient.lower() if recipient.lower() in ["alice", "bob"] else "bob",
                                proto="TLSv1.3",
                                msg_type_name="MESSAGE_RECEIVE",
                                length=len(message.pack(self.protocol_key)),
                                info=f"Encrypted message delivered to '{recipient}': {content[:35]}",
                                plain_data={"sender": sender, "recipient": recipient, "content": content},
                                raw_bytes=message.pack(self.protocol_key)
                            )
                    except Exception as e:
                        logger.error(f"Failed to deliver message: {e}")
                        # Store for offline delivery
                        self.database.store_message(sender, recipient, content)
        else:
            # Store for offline delivery
            self.database.store_message(sender, recipient, content)
            logger.info(f"Message stored for offline delivery: {sender} -> {recipient}")

        return create_message_ack(StatusCode.SUCCESS)

    def _handle_user_list_request(self) -> ProtocolMessage:
        """Handle request for online users list"""
        with self.lock:
            online_users = list(self.username_to_token.keys())

        return create_user_list_response(online_users)

    def _broadcast_presence(self, username: str, joined: bool = True):
        """Notify all active clients that a user has joined or left"""
        content = f"User '{username}' is now online" if joined else f"User '{username}' went offline"
        broadcast_msg = create_message_receive("SYSTEM", content)
        with self.lock:
            clients = list(self.active_clients.values())

        for sock, u in clients:
            if u != username:
                try:
                    self._send_message(sock, broadcast_msg)
                except Exception:
                    pass

    def _deliver_offline_messages(self, client_socket: ssl.SSLSocket, username: str):
        """Deliver stored offline messages to user"""
        messages = self.database.get_undelivered_messages(username)

        if messages:
            logger.info(f"Delivering {len(messages)} offline messages to {username}")

            for sender, content, timestamp in messages:
                message = create_message_receive(sender, content)
                try:
                    self._send_message(client_socket, message)
                except Exception as e:
                    logger.error(f"Failed to deliver offline message: {e}")
                    return

            # Mark as delivered
            self.database.mark_messages_delivered(username)

    def _send_message(self, client_socket: ssl.SSLSocket, message: ProtocolMessage):
        """Send message to client"""
        data = message.pack(self.protocol_key)

        # Send length prefix
        length = len(data)
        client_socket.sendall(length.to_bytes(4, 'big'))

        # Send data
        client_socket.sendall(data)

    def _receive_message(self, client_socket: ssl.SSLSocket) -> Optional[bytes]:
        """Receive message from client"""
        try:
            # Receive length prefix
            length_bytes = client_socket.recv(4)
            if not length_bytes:
                return None

            length = int.from_bytes(length_bytes, 'big')

            # Receive data
            data = b''
            while len(data) < length:
                chunk = client_socket.recv(min(length - len(data), 4096))
                if not chunk:
                    return None
                data += chunk

            return data

        except Exception as e:
            logger.error(f"Error receiving message: {e}")
            return None

    def _cleanup_sessions(self):
        """Periodically cleanup expired sessions"""
        import time

        while self.running:
            for _ in range(60):
                if not self.running:
                    return
                time.sleep(1)
            self.session_manager.cleanup_expired_sessions()

    def stop(self):
        """Stop the server"""
        logger.info("Shutting down server...")
        self.running = False

        with self.lock:
            for token, (sock, _) in list(self.active_clients.items()):
                try:
                    sock.close()
                except Exception:
                    pass
            self.active_clients.clear()
            self.username_to_token.clear()

        if hasattr(self, 'ssl_socket') and self.ssl_socket:
            try:
                self.ssl_socket.close()
            except Exception:
                pass

        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass

        logger.info("Server stopped")


def main():
    """Main entry point"""
    # Load configuration
    config_file = 'config/server_config.json'

    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            config = json.load(f)
    else:
        config = {
            'host': 'localhost',
            'port': 5050,
            'cert_file': 'certs/server.crt',
            'key_file': 'certs/server.key'
        }

    # Create and start server
    server = SecureServer(
        host=config['host'],
        port=config['port'],
        cert_file=config['cert_file'],
        key_file=config['key_file']
    )

    try:
        server.start()
    except KeyboardInterrupt:
        logger.info("\nReceived shutdown signal")
        server.stop()
    except Exception as e:
        logger.error(f"Server error: {e}")
        server.stop()
        sys.exit(1)


if __name__ == "__main__":
    main()
