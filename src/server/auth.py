"""
Authentication Handler
Handles user credential verification, session management, and brute-force mitigation
"""

import time
import logging
from typing import Tuple, Optional, Dict
from common.crypto_utils import CryptoUtils, SecureSessionManager
from common.protocol import StatusCode, validate_username, validate_password

try:
    from server.user_db import UserDatabase
except (ImportError, ModuleNotFoundError):
    from user_db import UserDatabase

logger = logging.getLogger('AuthHandler')


class AuthenticationHandler:
    """Authentication and session management controller"""

    def __init__(self, database: UserDatabase, session_manager: SecureSessionManager,
                 max_failed_attempts: int = 5, lockout_seconds: int = 60):
        self.database = database
        self.session_manager = session_manager
        self.max_failed_attempts = max_failed_attempts
        self.lockout_seconds = lockout_seconds

        # Track failed attempts: username -> (count, first_failure_timestamp)
        self.failed_attempts: Dict[str, Tuple[int, float]] = {}

    def is_locked_out(self, username: str) -> bool:
        """Check if an account is temporarily locked due to failed attempts"""
        if username not in self.failed_attempts:
            return False

        count, first_time = self.failed_attempts[username]
        now = time.time()

        if now - first_time > self.lockout_seconds:
            # Lockout period expired
            del self.failed_attempts[username]
            return False

        return count >= self.max_failed_attempts

    def record_failure(self, username: str):
        """Record a failed login attempt"""
        now = time.time()
        if username in self.failed_attempts:
            count, first_time = self.failed_attempts[username]
            if now - first_time > self.lockout_seconds:
                self.failed_attempts[username] = (1, now)
            else:
                self.failed_attempts[username] = (count + 1, first_time)
        else:
            self.failed_attempts[username] = (1, now)

    def record_success(self, username: str):
        """Clear failed attempts on successful login"""
        if username in self.failed_attempts:
            del self.failed_attempts[username]

    def register(self, username: str, password_hash: str) -> Tuple[StatusCode, str]:
        """
        Validate and register a new user
        Returns: (StatusCode, message)
        """
        if not username or not password_hash:
            return StatusCode.SERVER_ERROR, "Username and password required"

        if not validate_username(username):
            return StatusCode.SERVER_ERROR, "Invalid username format"

        success, msg = self.database.register_user(username, password_hash)
        if success:
            logger.info(f"User '{username}' registered successfully")
            return StatusCode.SUCCESS, "Registration successful"
        else:
            if "already exists" in msg.lower():
                return StatusCode.USER_EXISTS, "Username already exists"
            return StatusCode.SERVER_ERROR, msg

    def authenticate(self, username: str, password_hash: str) -> Tuple[StatusCode, Optional[str]]:
        """
        Authenticate user credentials and create a session
        Returns: (StatusCode, Optional[session_token])
        """
        if not username or not password_hash:
            return StatusCode.AUTH_FAILED, None

        if self.is_locked_out(username):
            logger.warning(f"Login rejected for '{username}': account temporarily locked")
            return StatusCode.AUTH_FAILED, None

        success, _ = self.database.authenticate_user(username, password_hash)

        if success:
            self.record_success(username)
            token = self.session_manager.create_session(username, duration=3600)
            logger.info(f"Authentication successful for '{username}'")
            return StatusCode.SUCCESS, token
        else:
            self.record_failure(username)
            logger.warning(f"Authentication failed for '{username}'")
            return StatusCode.AUTH_FAILED, None

    def validate_session(self, token: str) -> Tuple[bool, str]:
        """Validate an active session token"""
        return self.session_manager.validate_session(token)

    def revoke_session(self, token: str):
        """Revoke a session token upon logout"""
        self.session_manager.revoke_session(token)
