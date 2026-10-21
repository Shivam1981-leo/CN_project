"""
Message Formatting and Utilities
Provides standardized message models, serialization helpers, and formatters
"""

import sys
import os
from typing import Dict, Any, Optional

# Add common directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from protocol import (
    ProtocolMessage,
    MessageType,
    StatusCode,
    PROTOCOL_VERSION,
    create_auth_request,
    create_auth_response,
    create_register_request,
    create_register_response,
    create_message_send,
    create_message_receive,
    create_message_ack,
    create_error_response,
    create_user_list_response,
    create_file_send,
    create_file_receive,
    create_file_ack,
    generate_session_token,
    validate_username,
    validate_password
)


class MessageFormatter:
    """Helper for pretty formatting and inspection of messages"""

    @staticmethod
    def format_chat_message(sender: str, content: str, timestamp: Optional[str] = None) -> str:
        """Format a chat message for console or GUI display"""
        time_str = f"[{timestamp}] " if timestamp else ""
        return f"{time_str}{sender}: {content}"

    @staticmethod
    def format_system_event(event_type: str, details: str) -> str:
        """Format a system alert or status message"""
        return f"[SYSTEM - {event_type}] {details}"

    @staticmethod
    def format_file_notification(sender: str, filename: str, filesize: int, checksum: str) -> str:
        """Format an incoming file notification"""
        size_kb = filesize / 1024.0
        return (
            f"[FILE RECEIVED] From: {sender}\n"
            f"  File: {filename} ({size_kb:.1f} KB)\n"
            f"  SHA-256: {checksum[:16]}..."
        )


__all__ = [
    'ProtocolMessage',
    'MessageType',
    'StatusCode',
    'PROTOCOL_VERSION',
    'MessageFormatter',
    'create_auth_request',
    'create_auth_response',
    'create_register_request',
    'create_register_response',
    'create_message_send',
    'create_message_receive',
    'create_message_ack',
    'create_error_response',
    'create_user_list_response',
    'create_file_send',
    'create_file_receive',
    'create_file_ack',
    'generate_session_token',
    'validate_username',
    'validate_password'
]
