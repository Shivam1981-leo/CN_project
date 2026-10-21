"""
End-to-End Integration Test for ECCP Framework
Validates complete TLS connection, authentication, messaging, and file transfer
"""

import sys
import os
import time
import threading

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except (AttributeError, Exception):
        pass

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from server.server import SecureServer
from client.client import SecureClient


def run_integration_test():
    print("=" * 70)
    print("  ECCP END-TO-END INTEGRATION TEST")
    print("=" * 70)

    test_port = 5010
    server = SecureServer(host='localhost', port=test_port)
    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    time.sleep(1.0)

    try:
        # Step 1: Connect Alice
        print("\n[1/5] Connecting and Authenticating Alice...")
        alice = SecureClient(host='localhost', port=test_port)
        if not alice.connect():
            print("❌ Alice connection failed")
            return False
        alice.register("alice_test", "alice_pass123")
        if not alice.login("alice_test", "alice_pass123"):
            print("❌ Alice login failed")
            return False
        print("✅ Alice authenticated successfully (Session token created)")

        # Step 2: Connect Bob
        print("\n[2/5] Connecting and Authenticating Bob...")
        bob = SecureClient(host='localhost', port=test_port)
        if not bob.connect():
            print("❌ Bob connection failed")
            return False
        bob.register("bob_test", "bob_pass456")
        if not bob.login("bob_test", "bob_pass456"):
            print("❌ Bob login failed")
            return False
        print("✅ Bob authenticated successfully (Session token created)")

        # Step 3: Online User Discovery
        print("\n[3/5] Testing Online User Discovery...")
        time.sleep(0.5)
        users = alice.list_users()
        print(f"  Online users seen by Alice: {users}")
        if "bob_test" not in users:
            print("❌ Bob not detected in online user list")
            return False
        print("✅ Active user presence verified")

        # Step 4: Real-time Message Exchange
        print("\n[4/5] Testing Encrypted Message Routing...")
        msg_received = []
        bob.on_message_callback = lambda s, c: msg_received.append((s, c))

        msg_content = "Hello Bob! This is an end-to-end encrypted ECCP message."
        if not alice.send_message("bob_test", msg_content):
            print("❌ Message send failed")
            return False

        time.sleep(1.0)
        if not msg_received or msg_received[0] != ("alice_test", msg_content):
            print(f"❌ Bob did not receive message: {msg_received}")
            return False
        print(f"✅ Bob received message: '{msg_received[0][1]}' from {msg_received[0][0]}")

        # Step 5: Secure File Transfer
        print("\n[5/5] Testing Secure File Transfer & Verification...")
        test_file = "integration_test_doc.txt"
        file_content = "ECCP Secret Document: Computer Networks Mini-Project (Topic 19)"
        with open(test_file, "w", encoding="utf-8") as f:
            f.write(file_content)

        files_received = []
        bob.on_file_callback = lambda s, fn, valid, p: files_received.append((s, fn, valid, p))

        if not alice.send_file("bob_test", test_file):
            print("❌ File transfer failed")
            return False

        time.sleep(1.0)
        if not files_received or not files_received[0][2]:
            print(f"❌ File not received or failed integrity verification: {files_received}")
            return False

        print(f"✅ Bob received file '{files_received[0][1]}' (Checksum Validated: {files_received[0][2]})")

        # Clean up
        if os.path.exists(test_file):
            os.remove(test_file)

        alice.logout()
        bob.logout()
        server.stop()

        print("\n" + "=" * 70)
        print("🎉 ALL END-TO-END INTEGRATION TESTS PASSED SUCCESSFULLY!")
        print("=" * 70)
        return True

    except Exception as e:
        print(f"❌ Exception in integration test: {e}")
        try:
            server.stop()
        except Exception:
            pass
        return False


if __name__ == "__main__":
    success = run_integration_test()
    sys.exit(0 if success else 1)
