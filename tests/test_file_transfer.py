"""
Test Suite: Secure File Transfer & Integrity Verification
Tests end-to-end file preparation, checksum generation, and tampering detection
"""

import sys
import os
import tempfile
import base64

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except (AttributeError, Exception):
        pass

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from common.protocol import (
    ProtocolMessage, MessageType, StatusCode,
    create_file_send, create_file_receive, create_file_ack
)
from common.crypto_utils import generate_file_checksum, verify_file_checksum


class FileTransferTests:
    """Test file transfer security and integrity verification"""

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
                print("✅ PASSED")
                self.passed += 1
            else:
                print("❌ FAILED")
                self.failed += 1
        except Exception as e:
            print(f"❌ FAILED with exception: {e}")
            self.failed += 1

    def test_file_checksum_generation(self):
        """Test 1: SHA-256 checksum generation matches content"""
        print("Testing: SHA-256 file checksum calculation")

        test_content = b"This is confidential test file content for ECCP transfer."
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(test_content)
            temp_path = tf.name

        try:
            checksum = generate_file_checksum(temp_path)
            print(f"  Calculated Checksum: {checksum}")
            valid = verify_file_checksum(temp_path, checksum)
            print(f"  Checksum Verified: {valid}")
            return valid is True
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_file_tampering_detection(self):
        """Test 2: Checksum detects tampered file content"""
        print("Testing: Detection of altered file content")

        original_content = b"Contract details: Payment amount is $100."
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(original_content)
            temp_path = tf.name

        try:
            original_checksum = generate_file_checksum(temp_path)
            print(f"  Original Checksum: {original_checksum}")

            # Tamper with file
            tampered_content = b"Contract details: Payment amount is $9999999."
            with open(temp_path, 'wb') as tf:
                tf.write(tampered_content)

            valid = verify_file_checksum(temp_path, original_checksum)
            print(f"  Tampered file matches original checksum: {valid}")
            return valid is False
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_file_message_wire_packing(self):
        """Test 3: File message wire format packing and unpacking"""
        print("Testing: Packing and unpacking FILE_SEND_DATA message")

        secret_key = b"shared_secret_key"
        file_bytes = b"Hello, encrypted attachment world!"
        file_b64 = base64.b64encode(file_bytes).decode('utf-8')
        checksum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        msg = create_file_send(
            recipient="bob",
            filename="sample.txt",
            file_data_base64=file_b64,
            checksum=checksum,
            session_token="token_abc_123",
            file_size=len(file_bytes)
        )

        packed = msg.pack(secret_key)
        print(f"  Packed wire size: {len(packed)} bytes")

        unpacked, valid = ProtocolMessage.unpack(packed, secret_key)
        print(f"  Unpacked message type: {unpacked.msg_type}")
        print(f"  HMAC valid: {valid}")
        print(f"  Recipient: {unpacked.data.get('recipient')}")
        print(f"  Filename: {unpacked.data.get('filename')}")

        return valid and unpacked.msg_type == MessageType.FILE_SEND_DATA

    def test_file_payload_integrity(self):
        """Test 4: Tampering with base64 payload fails HMAC verification"""
        print("Testing: Detection of altered file payload bytes")

        secret_key = b"shared_secret_key"
        file_bytes = b"Secret data"
        file_b64 = base64.b64encode(file_bytes).decode('utf-8')

        msg = create_file_send(
            recipient="bob",
            filename="data.bin",
            file_data_base64=file_b64,
            checksum="dummy_checksum",
            session_token="tok123"
        )

        packed = bytearray(msg.pack(secret_key))
        # Tamper with byte in data section
        packed[-5] = (packed[-5] + 1) % 256

        try:
            _, valid = ProtocolMessage.unpack(bytes(packed), secret_key)
            print(f"  Tampered payload HMAC valid: {valid}")
            return valid is False
        except Exception as e:
            print(f"  Tampering caught with exception: {e}")
            return True

    def print_summary(self):
        """Print summary results"""
        print("\n" + "=" * 60)
        print("FILE TRANSFER TEST SUMMARY")
        print("=" * 60)
        print(f"Total tests:  {self.total}")
        print(f"Passed:       {self.passed} ✅")
        print(f"Failed:       {self.failed} ❌")
        print(f"Success rate: {(self.passed/self.total)*100:.1f}%")
        print("=" * 60)


def main():
    """Main entry point"""
    print("=" * 60)
    print("SECURE FILE TRANSFER & INTEGRITY TESTS")
    print("Encrypted Client-Server Communication Framework")
    print("=" * 60)

    tests = FileTransferTests()
    tests.run_test("Checksum Generation", tests.test_file_checksum_generation)
    tests.run_test("Tampering Detection", tests.test_file_tampering_detection)
    tests.run_test("Wire Message Packing", tests.test_file_message_wire_packing)
    tests.run_test("Payload Integrity Check", tests.test_file_payload_integrity)

    tests.print_summary()
    return 0 if tests.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
