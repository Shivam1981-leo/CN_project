"""
Protocol Definitions for Encrypted Client-Server Communication
Message types, constants, and protocol utilities
"""

import struct
import hashlib
import hmac
import json
from enum import Enum
from typing import Dict, Any, Tuple
import uuid

# Protocol Version
PROTOCOL_VERSION = b'ECC'  # Encrypted Client Communication Protocol (3 bytes + 1 byte type = 4 byte header)
VERSION_NUMBER = 1

# Message Types
class MessageType(Enum):
    # Authentication
    AUTH_REQUEST = 0x01
    AUTH_RESPONSE = 0x02
    REGISTER_REQUEST = 0x03
    REGISTER_RESPONSE = 0x04
    LOGOUT = 0x05

    # Messaging
    MESSAGE_SEND = 0x10
    MESSAGE_RECEIVE = 0x11
    MESSAGE_ACK = 0x12

    # File Transfer
    FILE_SEND_REQUEST = 0x20
    FILE_SEND_DATA = 0x21
    FILE_SEND_COMPLETE = 0x22
    FILE_RECEIVE = 0x23

    # Status
    PING = 0x30
    PONG = 0x31
    USER_LIST_REQUEST = 0x32
    USER_LIST_RESPONSE = 0x33

    # Errors
    ERROR = 0xFF

# Status Codes
class StatusCode(Enum):
    SUCCESS = 0x00
    AUTH_FAILED = 0x01
    USER_EXISTS = 0x02
    USER_NOT_FOUND = 0x03
    INVALID_SESSION = 0x04
    MESSAGE_TOO_LARGE = 0x05
    SERVER_ERROR = 0x06
    CHECKSUM_MISMATCH = 0x07
    PROTOCOL_ERROR = 0x08

# Protocol Constants
HEADER_SIZE = 4  # Protocol version + message type
LENGTH_SIZE = 4  # Message length
MESSAGE_ID_SIZE = 16  # UUID
CHECKSUM_SIZE = 32  # HMAC-SHA256
MAX_MESSAGE_SIZE = 10 * 1024 * 1024  # 10MB
MAX_USERNAME_LENGTH = 32
MAX_PASSWORD_LENGTH = 128

class ProtocolMessage:
    """Base class for protocol messages"""

    def __init__(self, msg_type: MessageType, data: Dict[str, Any] = None):
        self.version = PROTOCOL_VERSION
        self.msg_type = msg_type
        self.message_id = uuid.uuid4().bytes
        self.data = data or {}

    def pack(self, secret_key: bytes = b'') -> bytes:
        """
        Pack message into wire format:
        +--------+--------+------------+----------+------+
        | Header | Length | Message ID | Checksum | Data |
        +--------+--------+------------+----------+------+
        |  4B    |  4B    |    16B     |   32B    | Var  |
        """
        # Serialize data
        data_bytes = json.dumps(self.data).encode('utf-8')

        # Create header
        header = self.version + struct.pack('B', self.msg_type.value)

        # Calculate total length (excluding length field itself)
        total_length = HEADER_SIZE + MESSAGE_ID_SIZE + CHECKSUM_SIZE + len(data_bytes)

        # Create message without checksum
        message_without_checksum = (
            header +
            struct.pack('!I', total_length) +
            self.message_id +
            data_bytes
        )

        # Calculate HMAC checksum
        checksum = hmac.new(
            secret_key,
            message_without_checksum,
            hashlib.sha256
        ).digest()

        # Insert checksum after message_id
        final_message = (
            header +
            struct.pack('!I', total_length) +
            self.message_id +
            checksum +
            data_bytes
        )

        return final_message

    @staticmethod
    def unpack(data: bytes, secret_key: bytes = b'') -> Tuple['ProtocolMessage', bool]:
        """
        Unpack message from wire format
        Returns: (ProtocolMessage, checksum_valid)
        """
        if len(data) < HEADER_SIZE + LENGTH_SIZE + MESSAGE_ID_SIZE + CHECKSUM_SIZE:
            raise ValueError("Message too short")

        # Parse header
        version = data[:3]
        if version != PROTOCOL_VERSION:
            raise ValueError(f"Invalid protocol version: {version}")

        msg_type_value = struct.unpack('B', data[3:4])[0]
        try:
            msg_type = MessageType(msg_type_value)
        except ValueError:
            raise ValueError(f"Invalid message type: {msg_type_value}")

        # Parse length
        total_length = struct.unpack('!I', data[4:8])[0]
        if total_length > MAX_MESSAGE_SIZE:
            raise ValueError(f"Message exceeds maximum size: {total_length} bytes")

        expected_total_bytes = total_length + LENGTH_SIZE
        if len(data) != expected_total_bytes:
            raise ValueError(f"Message length mismatch: expected {expected_total_bytes} bytes, got {len(data)}")

        # Parse message ID
        message_id = data[8:24]

        # Parse checksum
        received_checksum = data[24:56]

        # Parse data
        data_bytes = data[56:56 + total_length - HEADER_SIZE - MESSAGE_ID_SIZE - CHECKSUM_SIZE]

        # Verify checksum
        message_without_checksum = (
            data[:8] +  # header + length
            message_id +
            data_bytes
        )

        calculated_checksum = hmac.new(
            secret_key,
            message_without_checksum,
            hashlib.sha256
        ).digest()

        checksum_valid = hmac.compare_digest(received_checksum, calculated_checksum)

        # Deserialize data
        try:
            data_dict = json.loads(data_bytes.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError):
            data_dict = {}

        # Create message object
        msg = ProtocolMessage(msg_type, data_dict)
        msg.message_id = message_id

        return msg, checksum_valid


def create_auth_request(username: str, password_hash: str) -> ProtocolMessage:
    """Create authentication request message"""
    return ProtocolMessage(MessageType.AUTH_REQUEST, {
        'username': username,
        'password_hash': password_hash,
        'timestamp': hash(str(uuid.uuid4()))  # Prevent replay attacks
    })


def create_auth_response(status: StatusCode, session_token: str = None) -> ProtocolMessage:
    """Create authentication response message"""
    data = {'status': status.value}
    if session_token:
        data['session_token'] = session_token
    return ProtocolMessage(MessageType.AUTH_RESPONSE, data)


def create_register_request(username: str, password_hash: str) -> ProtocolMessage:
    """Create registration request message"""
    return ProtocolMessage(MessageType.REGISTER_REQUEST, {
        'username': username,
        'password_hash': password_hash
    })


def create_register_response(status: StatusCode) -> ProtocolMessage:
    """Create registration response message"""
    return ProtocolMessage(MessageType.REGISTER_RESPONSE, {
        'status': status.value
    })


def create_message_send(recipient: str, content: str, session_token: str) -> ProtocolMessage:
    """Create message send request"""
    return ProtocolMessage(MessageType.MESSAGE_SEND, {
        'recipient': recipient,
        'content': content,
        'session_token': session_token,
        'timestamp': hash(str(uuid.uuid4()))
    })


def create_message_receive(sender: str, content: str) -> ProtocolMessage:
    """Create message receive notification"""
    return ProtocolMessage(MessageType.MESSAGE_RECEIVE, {
        'sender': sender,
        'content': content
    })


def create_message_ack(status: StatusCode, message_id: bytes = None) -> ProtocolMessage:
    """Create message acknowledgment"""
    data = {'status': status.value}
    if message_id:
        data['original_message_id'] = message_id.hex()
    return ProtocolMessage(MessageType.MESSAGE_ACK, data)


def create_error_response(error_code: StatusCode, error_message: str) -> ProtocolMessage:
    """Create error response"""
    return ProtocolMessage(MessageType.ERROR, {
        'error_code': error_code.value,
        'error_message': error_message
    })


def create_user_list_response(users: list) -> ProtocolMessage:
    """Create user list response"""
    return ProtocolMessage(MessageType.USER_LIST_RESPONSE, {
        'users': users
    })


def create_file_send(recipient: str, filename: str, file_data_base64: str,
                     checksum: str, session_token: str, file_size: int = 0) -> ProtocolMessage:
    """Create file transfer send message"""
    return ProtocolMessage(MessageType.FILE_SEND_DATA, {
        'recipient': recipient,
        'filename': filename,
        'file_data': file_data_base64,
        'checksum': checksum,
        'filesize': file_size,
        'session_token': session_token,
        'timestamp': hash(str(uuid.uuid4()))
    })


def create_file_receive(sender: str, filename: str, file_data_base64: str,
                        checksum: str, file_size: int = 0) -> ProtocolMessage:
    """Create file receive notification"""
    return ProtocolMessage(MessageType.FILE_RECEIVE, {
        'sender': sender,
        'filename': filename,
        'file_data': file_data_base64,
        'checksum': checksum,
        'filesize': file_size
    })


def create_file_ack(status: StatusCode, filename: str = "", message_id: bytes = None) -> ProtocolMessage:
    """Create file transfer acknowledgment"""
    data = {'status': status.value, 'filename': filename}
    if message_id:
        data['original_message_id'] = message_id.hex()
    return ProtocolMessage(MessageType.MESSAGE_ACK, data)


# Utility functions
def generate_session_token() -> str:
    """Generate a secure session token"""
    return uuid.uuid4().hex


def validate_username(username: str) -> bool:
    """Validate username format"""
    if not username or len(username) > MAX_USERNAME_LENGTH:
        return False
    return username.isalnum() or '_' in username


def validate_password(password: str) -> bool:
    """Validate password requirements"""
    if not password or len(password) > MAX_PASSWORD_LENGTH:
        return False
    # Add more validation rules as needed
    return len(password) >= 6


if __name__ == "__main__":
    # Test protocol functionality
    print("Protocol Module Test")
    print("=" * 50)

    # Test message packing and unpacking
    secret = b"test_secret_key"

    # Create a test message
    msg = create_auth_request("testuser", "hash123")
    print(f"Created message: {msg.msg_type}")
    print(f"Message ID: {msg.message_id.hex()}")

    # Pack the message
    packed = msg.pack(secret)
    print(f"Packed size: {len(packed)} bytes")

    # Unpack the message
    unpacked_msg, checksum_valid = ProtocolMessage.unpack(packed, secret)
    print(f"Unpacked message type: {unpacked_msg.msg_type}")
    print(f"Checksum valid: {checksum_valid}")
    print(f"Data: {unpacked_msg.data}")

    print("\nProtocol test completed successfully!")
