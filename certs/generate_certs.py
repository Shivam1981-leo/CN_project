#!/usr/bin/env python3
"""
Cross-Platform Certificate Generator for ECCP
Generates CA and Server TLS certificates using Python's cryptography library.
Works on Windows, Linux, and macOS without requiring OpenSSL CLI.
"""

import os
import sys
import datetime
import ipaddress
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError:
    print("Error: 'cryptography' library is not installed.")
    print("Please run: pip install cryptography")
    sys.exit(1)


if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass


def generate_certificates(output_dir: str = "."):
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    print("==========================================")
    print("  Generating TLS 1.3 Certificates (Python)")
    print("==========================================")
    print(f"Target Directory: {out_path.resolve()}\n")

    # 1. Generate CA Private Key
    print("[1/4] Generating CA Private Key...")
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    ca_key_path = out_path / "ca.key"
    with open(ca_key_path, "wb") as f:
        f.write(
            ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    print(f"  [OK] Saved: {ca_key_path}")

    # 2. Generate CA Certificate
    print("[2/4] Generating Self-Signed CA Certificate...")
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Maharashtra"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Pune"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CN Mini Project CA"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Computer Networks"),
        x509.NameAttribute(NameOID.COMMON_NAME, "CN Mini Project Root CA"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    ca_cert_path = out_path / "ca.crt"
    with open(ca_cert_path, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    print(f"  [OK] Saved: {ca_cert_path}")

    # 3. Generate Server Private Key
    print("[3/4] Generating Server Private Key...")
    server_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    server_key_path = out_path / "server.key"
    with open(server_key_path, "wb") as f:
        f.write(
            server_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    print(f"  [OK] Saved: {server_key_path}")

    # 4. Generate Server Certificate signed by CA with Subject Alternative Names (SAN)
    print("[4/4] Signing Server Certificate with CA...")
    server_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Maharashtra"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Pune"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CN Mini Project"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Computer Networks"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    san = x509.SubjectAlternativeName([
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ])

    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(san, critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    server_cert_path = out_path / "server.crt"
    with open(server_cert_path, "wb") as f:
        f.write(server_cert.public_bytes(serialization.Encoding.PEM))
    print(f"  [OK] Saved: {server_cert_path}")

    print("\n==========================================")
    print("  Certificates Generated Successfully! [OK]")
    print("==========================================")
    print(f"  CA Certificate:     {ca_cert_path}")
    print(f"  CA Private Key:     {ca_key_path}")
    print(f"  Server Certificate: {server_cert_path}")
    print(f"  Server Private Key: {server_key_path}")
    print("==========================================\n")


if __name__ == "__main__":
    target_dir = sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).parent)
    generate_certificates(target_dir)
