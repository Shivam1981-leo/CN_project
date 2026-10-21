"""
Cryptographic Utilities for Encrypted Communication
Handles password hashing, encryption, and secure key generation
"""

import hashlib
import hmac
import os
import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from typing import Tuple
import base64


class CryptoUtils:
    """Cryptographic utility functions"""

    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash password using bcrypt
        Returns: Base64-encoded hash
        """
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return base64.b64encode(hashed).decode('utf-8')

    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """
        Verify password against bcrypt hash
        """
        try:
            hashed_bytes = base64.b64decode(hashed.encode('utf-8'))
            return bcrypt.checkpw(password.encode('utf-8'), hashed_bytes)
        except Exception:
            return False

    @staticmethod
    def generate_hmac(data: bytes, key: bytes) -> bytes:
        """
        Generate HMAC-SHA256 for data integrity
        """
        return hmac.new(key, data, hashlib.sha256).digest()

    @staticmethod
    def verify_hmac(data: bytes, key: bytes, received_hmac: bytes) -> bool:
        """
        Verify HMAC-SHA256
        """
        calculated_hmac = CryptoUtils.generate_hmac(data, key)
        return hmac.compare_digest(calculated_hmac, received_hmac)

    @staticmethod
    def generate_key_from_password(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        """
        Derive encryption key from password using PBKDF2
        Returns: (key, salt)
        """
        if salt is None:
            salt = os.urandom(32)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode('utf-8'))
        return key, salt

    @staticmethod
    def encrypt_data(data: bytes, key: bytes) -> bytes:
        """
        Encrypt data using Fernet (symmetric encryption)
        """
        # Fernet requires base64-encoded 32-byte key
        fernet_key = base64.urlsafe_b64encode(key)
        f = Fernet(fernet_key)
        return f.encrypt(data)

    @staticmethod
    def decrypt_data(encrypted_data: bytes, key: bytes) -> bytes:
        """
        Decrypt data using Fernet
        """
        fernet_key = base64.urlsafe_b64encode(key)
        f = Fernet(fernet_key)
        return f.decrypt(encrypted_data)

    @staticmethod
    def generate_random_key(length: int = 32) -> bytes:
        """
        Generate a cryptographically secure random key
        """
        return os.urandom(length)

    @staticmethod
    def hash_data(data: bytes) -> str:
        """
        Generate SHA256 hash of data
        Returns hex string
        """
        return hashlib.sha256(data).hexdigest()


class SecureSessionManager:
    """Manages secure session tokens and validation"""

    def __init__(self, secret_key: bytes):
        self.secret_key = secret_key
        self.sessions = {}  # session_token -> (username, expiry_timestamp)

    def create_session(self, username: str, duration: int = 3600) -> str:
        """
        Create a new session token
        duration: session lifetime in seconds
        """
        import time

        # Generate session token
        token_data = f"{username}:{time.time()}:{os.urandom(16).hex()}"
        token = hashlib.sha256(token_data.encode()).hexdigest()

        # Store session
        expiry = time.time() + duration
        self.sessions[token] = (username, expiry)

        return token

    def validate_session(self, token: str) -> Tuple[bool, str]:
        """
        Validate session token
        Returns: (is_valid, username)
        """
        import time

        if token not in self.sessions:
            return False, ""

        username, expiry = self.sessions[token]

        if time.time() > expiry:
            # Session expired
            del self.sessions[token]
            return False, ""

        return True, username

    def revoke_session(self, token: str):
        """Revoke a session token"""
        if token in self.sessions:
            del self.sessions[token]

    def cleanup_expired_sessions(self):
        """Remove expired sessions"""
        import time
        current_time = time.time()

        expired_tokens = [
            token for token, (_, expiry) in self.sessions.items()
            if current_time > expiry
        ]

        for token in expired_tokens:
            del self.sessions[token]


def generate_file_checksum(filepath: str) -> str:
    """
    Generate SHA256 checksum for a file
    """
    sha256_hash = hashlib.sha256()

    with open(filepath, "rb") as f:
        # Read file in chunks to handle large files
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)

    return sha256_hash.hexdigest()


def verify_file_checksum(filepath: str, expected_checksum: str) -> bool:
    """
    Verify file checksum
    """
    actual_checksum = generate_file_checksum(filepath)
    return actual_checksum == expected_checksum


if __name__ == "__main__":
    # Test cryptographic functions
    print("Cryptographic Utilities Test")
    print("=" * 50)

    # Test password hashing
    password = "SecurePassword123!"
    hashed = CryptoUtils.hash_password(password)
    print(f"Password: {password}")
    print(f"Hashed: {hashed[:50]}...")
    print(f"Verification: {CryptoUtils.verify_password(password, hashed)}")

    # Test encryption/decryption
    key = CryptoUtils.generate_random_key()
    data = b"This is secret data"
    encrypted = CryptoUtils.encrypt_data(data, key)
    decrypted = CryptoUtils.decrypt_data(encrypted, key)
    print(f"\nOriginal: {data}")
    print(f"Encrypted: {encrypted[:50]}...")
    print(f"Decrypted: {decrypted}")
    print(f"Match: {data == decrypted}")

    # Test HMAC
    hmac_result = CryptoUtils.generate_hmac(data, key)
    verification = CryptoUtils.verify_hmac(data, key, hmac_result)
    print(f"\nHMAC verification: {verification}")

    # Test session management
    session_manager = SecureSessionManager(key)
    token = session_manager.create_session("testuser", duration=10)
    valid, username = session_manager.validate_session(token)
    print(f"\nSession token: {token[:20]}...")
    print(f"Session valid: {valid}, Username: {username}")

    print("\nCrypto utilities test completed successfully!")
