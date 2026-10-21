"""
Test Suite: Message Integrity and Tampering Detection
Tests HMAC-based integrity verification
"""

import sys
import os

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except (AttributeError, Exception):
        pass

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from common.protocol import (
    ProtocolMessage, MessageType, StatusCode,
    create_message_send
)
from common.crypto_utils import CryptoUtils
import struct


class TamperingTests:
    """Test message integrity and tampering detection"""

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

    def test_valid_message_integrity(self):
        """Test 1: Valid message passes integrity check"""
        print("Testing: Valid message with correct HMAC")

        secret_key = b"test_secret_key"
        msg = create_message_send("bob", "Hello World", "session123")

        # Pack message
        packed = msg.pack(secret_key)
        print(f"  Message size: {len(packed)} bytes")

        # Unpack and verify
        unpacked, checksum_valid = ProtocolMessage.unpack(packed, secret_key)
        print(f"  Checksum valid: {checksum_valid}")
        print(f"  Message type: {unpacked.msg_type}")
        print(f"  Content: {unpacked.data.get('content')}")

        return checksum_valid == True

    def test_tampered_data_detection(self):
        """Test 2: Detect tampered message content"""
        print("Testing: Tampering with message data")

        secret_key = b"test_secret_key"
        msg = create_message_send("bob", "Original message", "session123")

        # Pack message
        packed = msg.pack(secret_key)
        print(f"  Original message: 'Original message'")

        # Tamper with the data section (after checksum)
        tampered = bytearray(packed)
        # Modify a byte in the data section
        if len(tampered) > 60:
            tampered[-10] = (tampered[-10] + 1) % 256
            print(f"  Tampered byte at position -10")

        # Try to unpack
        try:
            unpacked, checksum_valid = ProtocolMessage.unpack(bytes(tampered), secret_key)
            print(f"  Checksum valid: {checksum_valid}")

            if not checksum_valid:
                print(f"  ✅ Tampering detected!")
                return True
            else:
                print(f"  ❌ Tampering NOT detected!")
                return False
        except Exception as e:
            print(f"  ✅ Exception raised (tampering detected): {e}")
            return True

    def test_tampered_checksum(self):
        """Test 3: Modified checksum detection"""
        print("Testing: Tampering with HMAC checksum")

        secret_key = b"test_secret_key"
        msg = create_message_send("bob", "Test message", "session123")

        # Pack message
        packed = msg.pack(secret_key)

        # Tamper with checksum (bytes 24-56)
        tampered = bytearray(packed)
        if len(tampered) > 56:
            tampered[30] = (tampered[30] + 1) % 256
            print(f"  Modified checksum byte at position 30")

        # Try to unpack
        unpacked, checksum_valid = ProtocolMessage.unpack(bytes(tampered), secret_key)
        print(f"  Checksum valid: {checksum_valid}")

        return checksum_valid == False

    def test_wrong_secret_key(self):
        """Test 4: Wrong secret key detection"""
        print("Testing: Message with wrong secret key")

        correct_key = b"correct_key_12345"
        wrong_key = b"wrong_key_67890xxx"

        msg = create_message_send("bob", "Secret message", "session123")

        # Pack with correct key
        packed = msg.pack(correct_key)
        print(f"  Packed with key: {correct_key}")

        # Try to unpack with wrong key
        unpacked, checksum_valid = ProtocolMessage.unpack(packed, wrong_key)
        print(f"  Unpacked with key: {wrong_key}")
        print(f"  Checksum valid: {checksum_valid}")

        return checksum_valid == False

    def test_message_truncation(self):
        """Test 5: Detect truncated messages"""
        print("Testing: Truncated message detection")

        secret_key = b"test_secret_key"
        msg = create_message_send("bob", "Complete message", "session123")

        # Pack message
        packed = msg.pack(secret_key)
        print(f"  Original size: {len(packed)} bytes")

        # Truncate message (remove last 20 bytes)
        truncated = packed[:-20]
        print(f"  Truncated size: {len(truncated)} bytes")

        # Try to unpack
        try:
            unpacked, checksum_valid = ProtocolMessage.unpack(truncated, secret_key)
            print(f"  ❌ Truncation NOT detected!")
            return False
        except Exception as e:
            print(f"  ✅ Exception raised (truncation detected): {type(e).__name__}")
            return True

    def test_replayed_message(self):
        """Test 6: Replay attack detection"""
        print("Testing: Replay attack (same message twice)")

        secret_key = b"test_secret_key"
        msg = create_message_send("bob", "Message", "session123")

        # Pack message
        packed = msg.pack(secret_key)

        # Unpack first time
        unpacked1, valid1 = ProtocolMessage.unpack(packed, secret_key)
        print(f"  First delivery - ID: {unpacked1.message_id.hex()[:16]}...")
        print(f"  First delivery - Valid: {valid1}")

        # Unpack second time (replay)
        unpacked2, valid2 = ProtocolMessage.unpack(packed, secret_key)
        print(f"  Second delivery - ID: {unpacked2.message_id.hex()[:16]}...")
        print(f"  Second delivery - Valid: {valid2}")

        # Note: Both will be valid at protocol level
        # Replay prevention requires message ID tracking server-side
        print(f"  Note: Message ID is same - server should track and reject")

        return unpacked1.message_id == unpacked2.message_id

    def test_modified_message_length(self):
        """Test 7: Modified length field"""
        print("Testing: Tampering with length field")

        secret_key = b"test_secret_key"
        msg = create_message_send("bob", "Test", "session123")

        # Pack message
        packed = msg.pack(secret_key)

        # Tamper with length field (bytes 4-8)
        tampered = bytearray(packed)
        if len(tampered) >= 8:
            # Change length to wrong value
            wrong_length = struct.pack('!I', 9999)
            tampered[4:8] = wrong_length
            print(f"  Modified length field to 9999")

        # Try to unpack
        try:
            unpacked, checksum_valid = ProtocolMessage.unpack(bytes(tampered), secret_key)
            print(f"  ❌ Length tampering NOT detected!")
            return False
        except Exception as e:
            print(f"  ✅ Exception raised: {type(e).__name__}")
            return True

    def test_hmac_verification_process(self):
        """Test 8: HMAC generation and verification"""
        print("Testing: HMAC-SHA256 generation and verification")

        data = b"Important message data"
        key = b"secret_key_12345"

        # Generate HMAC
        hmac1 = CryptoUtils.generate_hmac(data, key)
        print(f"  HMAC: {hmac1.hex()[:40]}...")
        print(f"  HMAC length: {len(hmac1)} bytes")

        # Verify with correct data and key
        result1 = CryptoUtils.verify_hmac(data, key, hmac1)
        print(f"  Verify with correct data: {result1}")

        # Verify with modified data
        modified_data = b"Important message data!"  # Added exclamation
        result2 = CryptoUtils.verify_hmac(modified_data, key, hmac1)
        print(f"  Verify with modified data: {result2}")

        # Verify with wrong key
        wrong_key = b"wrong_key_67890x"
        result3 = CryptoUtils.verify_hmac(data, wrong_key, hmac1)
        print(f"  Verify with wrong key: {result3}")

        return result1 == True and result2 == False and result3 == False

    def test_message_injection(self):
        """Test 9: Injected malicious message"""
        print("Testing: Injected message without valid HMAC")

        secret_key = b"server_secret_key"

        # Attacker creates message without knowing secret key
        fake_msg = create_message_send("bob", "Malicious content", "fake_token")
        fake_packed = fake_msg.pack(b"attacker_guess_key")

        print(f"  Attacker's message created")
        print(f"  Size: {len(fake_packed)} bytes")

        # Server tries to verify with correct key
        try:
            unpacked, checksum_valid = ProtocolMessage.unpack(fake_packed, secret_key)
            print(f"  Checksum valid: {checksum_valid}")

            if not checksum_valid:
                print(f"  ✅ Injection rejected!")
                return True
            else:
                print(f"  ❌ Injection accepted!")
                return False
        except Exception as e:
            print(f"  ✅ Exception: {e}")
            return True

    def test_bit_flip_attack(self):
        """Test 10: Single bit flip detection"""
        print("Testing: Single bit flip in message")

        secret_key = b"test_secret_key"
        msg = create_message_send("bob", "Critical data", "session123")

        # Pack message
        packed = msg.pack(secret_key)

        # Flip a single bit in the data section
        tampered = bytearray(packed)
        if len(tampered) > 60:
            # Flip bit 0 of byte at position -5
            tampered[-5] ^= 0x01
            print(f"  Flipped bit 0 at position -5")

        # Try to unpack
        unpacked, checksum_valid = ProtocolMessage.unpack(bytes(tampered), secret_key)
        print(f"  Checksum valid: {checksum_valid}")

        if not checksum_valid:
            print(f"  ✅ Single bit flip detected!")
            return True
        else:
            print(f"  ❌ Bit flip NOT detected!")
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
    """Run all tampering detection tests"""
    print("=" * 60)
    print("MESSAGE INTEGRITY & TAMPERING DETECTION TESTS")
    print("Encrypted Client-Server Communication Framework")
    print("=" * 60)

    tests = TamperingTests()

    # Run all tests
    tests.run_test("Valid Message Integrity", tests.test_valid_message_integrity)
    tests.run_test("Tampered Data Detection", tests.test_tampered_data_detection)
    tests.run_test("Tampered Checksum", tests.test_tampered_checksum)
    tests.run_test("Wrong Secret Key", tests.test_wrong_secret_key)
    tests.run_test("Message Truncation", tests.test_message_truncation)
    tests.run_test("Replayed Message", tests.test_replayed_message)
    tests.run_test("Modified Length Field", tests.test_modified_message_length)
    tests.run_test("HMAC Verification", tests.test_hmac_verification_process)
    tests.run_test("Message Injection", tests.test_message_injection)
    tests.run_test("Bit Flip Attack", tests.test_bit_flip_attack)

    # Print summary
    tests.print_summary()

    return 0 if tests.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
