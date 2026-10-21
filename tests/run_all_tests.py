"""
Test Suite Runner
Runs all test suites for the ECCP project
"""

import sys
import os
import subprocess
from datetime import datetime


if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except (AttributeError, Exception):
        pass


def print_header(title):
    """Print formatted header"""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70 + "\n")


def run_test_suite(test_file, description):
    """Run a single test suite"""
    print_header(description)

    try:
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'
        result = subprocess.run(
            [sys.executable, test_file],
            capture_output=False,
            text=True,
            env=env
        )
        return result.returncode == 0
    except Exception as e:
        print(f"❌ Error running test: {e}")
        return False


def main():
    """Run all test suites"""
    print("\n" + "=" * 70)
    print("  ECCP TEST SUITE RUNNER")
    print("  Encrypted Client-Server Communication Framework")
    print("=" * 70)
    print(f"\n  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Python: {sys.version.split()[0]}")
    print()

    # Get test directory
    test_dir = os.path.dirname(os.path.abspath(__file__))

    # Define test suites
    test_suites = [
        ("test_authentication.py", "Authentication Failure Tests"),
        ("test_tampering.py", "Message Integrity & Tampering Tests"),
        ("test_connection.py", "Connection & Network Failure Tests"),
        ("test_file_transfer.py", "Secure File Transfer & Integrity Tests"),
        ("test_integration.py", "End-to-End TLS & Protocol Integration Tests"),
    ]

    results = []

    # Run each test suite
    for test_file, description in test_suites:
        test_path = os.path.join(test_dir, test_file)

        if not os.path.exists(test_path):
            print(f"⚠️  Test file not found: {test_file}")
            results.append((description, False))
            continue

        success = run_test_suite(test_path, description)
        results.append((description, success))

    # Print overall summary
    print_header("OVERALL TEST SUMMARY")

    total = len(results)
    passed = sum(1 for _, success in results if success)
    failed = total - passed

    for description, success in results:
        status = "✅ PASSED" if success else "❌ FAILED"
        print(f"  {status:12} - {description}")

    print("\n" + "-" * 70)
    print(f"  Total test suites:  {total}")
    print(f"  Passed:             {passed} ✅")
    print(f"  Failed:             {failed} ❌")
    print(f"  Success rate:       {(passed/total)*100:.1f}%")
    print("=" * 70 + "\n")

    if failed == 0:
        print("🎉 All test suites passed!")
        return 0
    else:
        print(f"⚠️  {failed} test suite(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
