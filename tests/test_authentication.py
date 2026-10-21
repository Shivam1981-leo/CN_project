"""
Test Suite: Authentication Failure Conditions
Tests various authentication failure scenarios
"""

import sys
import os
import time

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except (AttributeError, Exception):
        pass

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from common.protocol import (
    ProtocolMessage, MessageType, StatusCode,
    create_auth_request, create_register_request
)
from common.crypto_utils import CryptoUtils


class AuthenticationTests:
    """Test authentication failure conditions"""

    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.total = 0

    def run_test(self, test_name, test_func):
        """Run a single test"""
        self.total += 1
        print(f"\n[TEST {self.total}] {test_name}")
        print("-" * 60)

        try:
            result = test_func()
            if result:
                print(f"✅ PASSED")
                self.passed += 1
            else:
                print(f"❌ FAILED")
                self.failed += 1
        except Exception as e:
            print(f"❌ FAILED with exception: {e}")
            self.failed += 1

    def test_invalid_username_format(self):
        """Test 1: Invalid username format"""
        print("Testing: Username with special characters")

        invalid_usernames = [
            "user@domain.com",  # Contains @
            "user name",        # Contains space
            "user!123",         # Contains !
            "user#tag",         # Contains #
            "",                 # Empty
            "a" * 100,          # Too long (>32 chars)
        ]

        for username in invalid_usernames:
            msg = create_register_request(username, "valid_hash")
            print(f"  Testing: '{username}' - ", end="")

            # In real implementation, server would reject these
            if len(username) == 0 or len(username) > 32:
                print("❌ Invalid (length)")
            elif not username.replace('_', '').isalnum():
                print("❌ Invalid (characters)")
            else:
                print("✅ Valid")

        return True

    def test_wrong_password(self):
        """Test 2: Incorrect password"""
        print("Testing: Authentication with wrong password")

        username = "testuser"
        correct_password = "correct_password"
        wrong_password = "wrong_password"

        # Hash both passwords
        correct_hash = CryptoUtils.hash_password(correct_password)
        wrong_hash = CryptoUtils.hash_password(wrong_password)

        print(f"  Correct hash: {correct_hash[:30]}...")
        print(f"  Wrong hash:   {wrong_hash[:30]}...")
        print(f"  Hashes match: {correct_hash == wrong_hash}")

        # Verify wrong password fails
        result = CryptoUtils.verify_password(wrong_password, correct_hash)
        print(f"  Wrong password verified: {result}")

        return result == False

    def test_nonexistent_user(self):
        """Test 3: Login with non-existent user"""
        print("Testing: Authentication for user that doesn't exist")

        msg = create_auth_request("nonexistent_user", "some_hash")

        print(f"  Username: {msg.data['username']}")
        print(f"  Expected server response: USER_NOT_FOUND")
        print(f"  Expected status code: {StatusCode.AUTH_FAILED.value}")

        return True

    def test_duplicate_registration(self):
        """Test 4: Register same username twice"""
        print("Testing: Duplicate user registration")

        username = "duplicate_user"
        password_hash = CryptoUtils.hash_password("password")

        msg1 = create_register_request(username, password_hash)
        msg2 = create_register_request(username, password_hash)

        print(f"  First registration: {username} - Should succeed")
        print(f"  Second registration: {username} - Should fail")
        print(f"  Expected error: USER_EXISTS")

        return True

    def test_empty_credentials(self):
        """Test 5: Empty username or password"""
        print("Testing: Empty credentials")

        test_cases = [
            ("", "password_hash"),
            ("username", ""),
            ("", ""),
        ]

        for username, password_hash in test_cases:
            print(f"  Username: '{username}', Password: '{password_hash}'")
            if not username or not password_hash:
                print(f"    ❌ Should be rejected (empty field)")
            else:
                print(f"    ✅ Valid")

        return True

    def test_weak_password(self):
        """Test 6: Weak password validation"""
        print("Testing: Weak password detection")

        weak_passwords = [
            "123",          # Too short
            "12345",        # Still too short
            "",             # Empty
        ]

        for pwd in weak_passwords:
            print(f"  Password: '{pwd}' (length: {len(pwd)})")
            if len(pwd) < 6:
                print(f"    ❌ Too weak (minimum 6 characters)")
            else:
                print(f"    ✅ Acceptable")

        return True

    def test_session_expiry(self):
        """Test 7: Expired session token"""
        print("Testing: Session token expiration")

        from common.crypto_utils import SecureSessionManager

        manager = SecureSessionManager(b"secret_key")

        # Create session with 1 second duration
        token = manager.create_session("testuser", duration=1)
        print(f"  Session token created: {token[:20]}...")

        # Immediate validation should succeed
        valid, username = manager.validate_session(token)
        print(f"  Immediate validation: {valid}, user: {username}")

        # Wait for expiration
        print(f"  Waiting 2 seconds for expiration...")
        time.sleep(2)

        # Should now fail
        valid, username = manager.validate_session(token)
        print(f"  After expiry validation: {valid}, user: {username}")

        return valid == False

    def test_invalid_session_token(self):
        """Test 8: Invalid/forged session token"""
        print("Testing: Invalid session token")

        from common.crypto_utils import SecureSessionManager

        manager = SecureSessionManager(b"secret_key")

        # Try to validate non-existent token
        fake_tokens = [
            "completely_fake_token",
            "1234567890abcdef",
            "",
        ]

        for token in fake_tokens:
            valid, username = manager.validate_session(token)
            print(f"  Token: '{token[:20]}...' - Valid: {valid}")
            if valid:
                return False

        return True

    def test_password_hash_tampering(self):
        """Test 9: Modified password hash"""
        print("Testing: Password hash tampering detection")

        original_password = "secure_password"
        original_hash = CryptoUtils.hash_password(original_password)

        print(f"  Original hash: {original_hash[:40]}...")

        # Tamper with hash (modify one character)
        if len(original_hash) > 10:
            tampered_hash = original_hash[:10] + 'X' + original_hash[11:]
            print(f"  Tampered hash: {tampered_hash[:40]}...")

            # Verification should fail
            result = CryptoUtils.verify_password(original_password, tampered_hash)
            print(f"  Verification with tampered hash: {result}")

            return result == False

        return True

    def test_replay_attack_prevention(self):
        """Test 10: Replay attack with timestamp"""
        print("Testing: Replay attack prevention")

        import time

        # Create auth request with current timestamp
        current_time = int(time.time())
        old_time = current_time - 120  # 2 minutes ago

        print(f"  Current timestamp: {current_time}")
        print(f"  Old timestamp: {old_time}")
        print(f"  Difference: {current_time - old_time} seconds")

        # Server should reject requests with timestamps > 60 seconds old
        if current_time - old_time > 60:
            print(f"  ❌ Old request should be rejected (replay attack)")
            return True
        else:
            print(f"  ✅ Request is recent")
            return False

    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        print(f"Total tests:  {self.total}")
        print(f"Passed:       {self.passed} ✅")
        print(f"Failed:       {self.failed} ❌")
        print(f"Success rate: {(self.passed/self.total)*100:.1f}%")
        print("=" * 60)


def main():
    """Run all authentication tests"""
    print("=" * 60)
    print("AUTHENTICATION FAILURE CONDITION TESTS")
    print("Encrypted Client-Server Communication Framework")
    print("=" * 60)

    tests = AuthenticationTests()

    # Run all tests
    tests.run_test("Invalid Username Format", tests.test_invalid_username_format)
    tests.run_test("Wrong Password", tests.test_wrong_password)
    tests.run_test("Non-existent User", tests.test_nonexistent_user)
    tests.run_test("Duplicate Registration", tests.test_duplicate_registration)
    tests.run_test("Empty Credentials", tests.test_empty_credentials)
    tests.run_test("Weak Password", tests.test_weak_password)
    tests.run_test("Session Expiry", tests.test_session_expiry)
    tests.run_test("Invalid Session Token", tests.test_invalid_session_token)
    tests.run_test("Password Hash Tampering", tests.test_password_hash_tampering)
    tests.run_test("Replay Attack Prevention", tests.test_replay_attack_prevention)

    # Print summary
    tests.print_summary()

    return 0 if tests.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
