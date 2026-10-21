"""
User Database Management
SQLite database for user authentication and storage
"""

import sqlite3
import os
import sys
from typing import Optional, List, Tuple
from datetime import datetime
import threading

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from common.crypto_utils import CryptoUtils
except ImportError:
    try:
        from src.common.crypto_utils import CryptoUtils
    except ImportError:
        CryptoUtils = None


class UserDatabase:
    """Manages user data with SQLite"""

    def __init__(self, db_path: str = "users.db"):
        self.db_path = db_path
        self.lock = threading.RLock()
        self._initialize_database()

    def _initialize_database(self):
        """Create database tables if they don't exist"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()

                # Users table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_login TIMESTAMP
                    )
                ''')

                # Messages table (for storing offline messages)
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS messages (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        sender TEXT NOT NULL,
                        recipient TEXT NOT NULL,
                        content TEXT NOT NULL,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        delivered BOOLEAN DEFAULT 0,
                        FOREIGN KEY (sender) REFERENCES users(username),
                        FOREIGN KEY (recipient) REFERENCES users(username)
                    )
                ''')

                # Sessions table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS sessions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        session_token TEXT UNIQUE NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        expires_at TIMESTAMP NOT NULL,
                        FOREIGN KEY (username) REFERENCES users(username)
                    )
                ''')

                conn.commit()
            finally:
                conn.close()

    def register_user(self, username: str, password_hash: str) -> Tuple[bool, str]:
        """
        Register a new user
        Returns: (success, message)
        """
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()

                # If CryptoUtils is available and password_hash is not yet bcrypt-hashed, hash it
                stored_hash = password_hash
                if CryptoUtils and not (password_hash.startswith("JDJi") or password_hash.startswith("$2b$")):
                    stored_hash = CryptoUtils.hash_password(password_hash)

                cursor.execute(
                    'INSERT INTO users (username, password_hash) VALUES (?, ?)',
                    (username, stored_hash)
                )

                conn.commit()
                return True, "User registered successfully"

            except sqlite3.IntegrityError:
                return False, "Username already exists"
            except Exception as e:
                return False, f"Database error: {str(e)}"
            finally:
                conn.close()

    def authenticate_user(self, username: str, password_hash: str) -> Tuple[bool, str]:
        """
        Authenticate user credentials
        Returns: (success, message)
        """
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()

                cursor.execute(
                    'SELECT password_hash FROM users WHERE username = ?',
                    (username,)
                )

                result = cursor.fetchone()
                if result is None:
                    return False, "User not found"

                stored_hash = result[0]
                matched = False
                # Direct equality match
                if stored_hash == password_hash:
                    matched = True
                # Bcrypt verification
                elif CryptoUtils and CryptoUtils.verify_password(password_hash, stored_hash):
                    matched = True

                if matched:
                    cursor.execute(
                        'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE username = ?',
                        (username,)
                    )
                    conn.commit()
                    return True, "Authentication successful"

                return False, "Invalid password"

            except Exception as e:
                return False, f"Database error: {str(e)}"
            finally:
                conn.close()

    def _update_last_login(self, username: str):
        """Update last login timestamp"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()

                cursor.execute(
                    'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE username = ?',
                    (username,)
                )

                conn.commit()
            finally:
                conn.close()

    def user_exists(self, username: str) -> bool:
        """Check if user exists"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()

                cursor.execute('SELECT 1 FROM users WHERE username = ?', (username,))
                result = cursor.fetchone()
                return result is not None
            finally:
                conn.close()

    def store_message(self, sender: str, recipient: str, content: str) -> bool:
        """Store a message (for offline delivery)"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()

                cursor.execute(
                    'INSERT INTO messages (sender, recipient, content) VALUES (?, ?, ?)',
                    (sender, recipient, content)
                )

                conn.commit()
                return True

            except Exception as e:
                print(f"Error storing message: {e}")
                return False
            finally:
                conn.close()

    def get_undelivered_messages(self, username: str) -> List[Tuple[str, str, str]]:
        """
        Get all undelivered messages for a user
        Returns: List of (sender, content, timestamp)
        """
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()

                cursor.execute('''
                    SELECT sender, content, timestamp FROM messages
                    WHERE recipient = ? AND delivered = 0
                    ORDER BY timestamp ASC
                ''', (username,))

                messages = cursor.fetchall()
                return messages
            finally:
                conn.close()

    def mark_messages_delivered(self, username: str):
        """Mark all messages for user as delivered"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()

                cursor.execute(
                    'UPDATE messages SET delivered = 1 WHERE recipient = ?',
                    (username,)
                )

                conn.commit()
            finally:
                conn.close()

    def get_user_stats(self, username: str) -> dict:
        """Get statistics for a user"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()

                # Get user info
                cursor.execute('''
                    SELECT created_at, last_login FROM users WHERE username = ?
                ''', (username,))
                user_info = cursor.fetchone()

                # Count messages
                cursor.execute('''
                    SELECT COUNT(*) FROM messages WHERE sender = ?
                ''', (username,))
                sent_count = cursor.fetchone()[0]

                cursor.execute('''
                    SELECT COUNT(*) FROM messages WHERE recipient = ?
                ''', (username,))
                received_count = cursor.fetchone()[0]

                if user_info:
                    return {
                        'username': username,
                        'created_at': user_info[0],
                        'last_login': user_info[1],
                        'messages_sent': sent_count,
                        'messages_received': received_count
                    }
                else:
                    return {}
            finally:
                conn.close()

    def list_all_users(self) -> List[str]:
        """Get list of all usernames"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()

                cursor.execute('SELECT username FROM users ORDER BY username')
                users = [row[0] for row in cursor.fetchall()]
                return users
            finally:
                conn.close()

    def cleanup_old_messages(self, days: int = 30):
        """Delete messages older than specified days"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()

                cursor.execute('''
                    DELETE FROM messages
                    WHERE delivered = 1
                    AND timestamp < datetime('now', '-' || ? || ' days')
                ''', (days,))

                deleted = cursor.rowcount
                conn.commit()
                return deleted
            finally:
                conn.close()


if __name__ == "__main__":
    # Test database functionality
    print("User Database Test")
    print("=" * 50)

    # Create test database
    test_db = UserDatabase("test_users.db")

    # Test user registration
    success, msg = test_db.register_user("alice", "hash_alice_123")
    print(f"Register alice: {success} - {msg}")

    success, msg = test_db.register_user("bob", "hash_bob_456")
    print(f"Register bob: {success} - {msg}")

    # Test duplicate registration
    success, msg = test_db.register_user("alice", "hash_alice_789")
    print(f"Duplicate registration: {success} - {msg}")

    # Test authentication
    success, msg = test_db.authenticate_user("alice", "hash_alice_123")
    print(f"Auth alice (correct): {success} - {msg}")

    success, msg = test_db.authenticate_user("alice", "wrong_hash")
    print(f"Auth alice (wrong): {success} - {msg}")

    # Test message storage
    test_db.store_message("alice", "bob", "Hello Bob!")
    test_db.store_message("alice", "bob", "How are you?")

    # Get messages
    messages = test_db.get_undelivered_messages("bob")
    print(f"\nUndelivered messages for bob: {len(messages)}")
    for sender, content, timestamp in messages:
        print(f"  From {sender}: {content} ({timestamp})")

    # Get stats
    stats = test_db.get_user_stats("alice")
    print(f"\nStats for alice: {stats}")

    # List users
    users = test_db.list_all_users()
    print(f"\nAll users: {users}")

    # Cleanup
    os.remove("test_users.db")
    print("\nDatabase test completed successfully!")
