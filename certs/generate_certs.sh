#!/bin/bash

# Certificate Generation Script for Encrypted Client-Server Communication
# Generates self-signed certificates for TLS/SSL

set -e  # Exit on error

# Prevent Git Bash / MSYS from converting OpenSSL -subj paths (e.g. /C=IN) to Windows paths
export MSYS_NO_PATHCONV=1

echo "=========================================="
echo "  Certificate Generation for ECCP"
echo "=========================================="
echo

# Configuration
CERT_DIR="."
DAYS_VALID=365
KEY_SIZE=2048
COUNTRY="IN"
STATE="Maharashtra"
CITY="Pune"
ORG="CN Mini Project"
ORG_UNIT="Computer Networks"
COMMON_NAME="localhost"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Configuration:${NC}"
echo "  Country: $COUNTRY"
echo "  State: $STATE"
echo "  City: $CITY"
echo "  Organization: $ORG"
echo "  Common Name: $COMMON_NAME"
echo "  Validity: $DAYS_VALID days"
echo

# Check if OpenSSL is installed
if ! command -v openssl &> /dev/null; then
    echo "Error: OpenSSL is not installed"
    echo "Please install OpenSSL and try again"
    exit 1
fi

echo -e "${GREEN}✓${NC} OpenSSL found: $(openssl version)"
echo

# Create certificate directory if it doesn't exist
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

# 1. Generate CA private key
echo "Step 1: Generating Certificate Authority (CA) private key..."
openssl genrsa -out ca.key $KEY_SIZE 2>/dev/null
chmod 600 ca.key
echo -e "${GREEN}✓${NC} CA private key generated: ca.key"
echo

# 2. Generate CA certificate
echo "Step 2: Generating CA certificate..."
openssl req -new -x509 -days $DAYS_VALID -key ca.key -out ca.crt \
    -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG CA/OU=$ORG_UNIT/CN=$ORG CA"
chmod 644 ca.crt
echo -e "${GREEN}✓${NC} CA certificate generated: ca.crt"
echo

# 3. Generate server private key
echo "Step 3: Generating server private key..."
openssl genrsa -out server.key $KEY_SIZE 2>/dev/null
chmod 600 server.key
echo -e "${GREEN}✓${NC} Server private key generated: server.key"
echo

# 4. Generate server certificate signing request (CSR)
echo "Step 4: Generating server certificate signing request..."
openssl req -new -key server.key -out server.csr \
    -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/OU=$ORG_UNIT/CN=$COMMON_NAME"
echo -e "${GREEN}✓${NC} Server CSR generated: server.csr"
echo

# 5. Create extensions file for SAN (Subject Alternative Name)
echo "Step 5: Creating certificate extensions..."
cat > server_ext.cnf << EOF
subjectAltName = @alt_names
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = localhost
DNS.2 = 127.0.0.1
IP.1 = 127.0.0.1
EOF
echo -e "${GREEN}✓${NC} Extensions file created: server_ext.cnf"
echo

# 6. Sign server certificate with CA
echo "Step 6: Signing server certificate with CA..."
openssl x509 -req -days $DAYS_VALID \
    -in server.csr \
    -CA ca.crt \
    -CAkey ca.key \
    -CAcreateserial \
    -out server.crt \
    -extfile server_ext.cnf
chmod 644 server.crt
echo -e "${GREEN}✓${NC} Server certificate generated: server.crt"
echo

# 7. Verify the certificate
echo "Step 7: Verifying certificate..."
openssl verify -CAfile ca.crt server.crt
echo

# Clean up
rm -f server.csr server_ext.cnf ca.srl

# Summary
echo "=========================================="
echo "  Certificate Generation Complete!"
echo "=========================================="
echo
echo "Generated files:"
echo "  ca.key          - CA private key"
echo "  ca.crt          - CA certificate"
echo "  server.key      - Server private key"
echo "  server.crt      - Server certificate"
echo
echo "Certificate details:"
openssl x509 -in server.crt -noout -subject -dates -issuer
echo
echo -e "${GREEN}✓${NC} All certificates generated successfully!"
echo
echo "You can now start the server with these certificates."
echo
