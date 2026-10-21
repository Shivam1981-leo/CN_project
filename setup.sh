#!/bin/bash

# Automated Setup Script for Encrypted Client-Server Communication Framework
# This script sets up the entire project environment

set -e  # Exit on error

# Prevent Git Bash / MSYS on Windows from mangling OpenSSL -subj paths
export MSYS_NO_PATHCONV=1

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo
echo "=========================================="
echo "  ECCP Setup Script"
echo "  Encrypted Client-Server Communication"
echo "=========================================="
echo

# Function to print status messages
print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Check Python installation
print_status "Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is not installed"
    echo "Please install Python 3.8 or higher"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
print_success "Python $PYTHON_VERSION found"

# Check pip
print_status "Checking pip installation..."
if ! command -v pip3 &> /dev/null; then
    print_error "pip3 is not installed"
    echo "Please install pip3"
    exit 1
fi
print_success "pip3 found"

# Check OpenSSL
print_status "Checking OpenSSL installation..."
if ! command -v openssl &> /dev/null; then
    print_error "OpenSSL is not installed"
    echo "Please install OpenSSL"
    exit 1
fi
OPENSSL_VERSION=$(openssl version)
print_success "$OPENSSL_VERSION found"

echo

# Create directory structure
print_status "Creating directory structure..."
mkdir -p logs data config received_files pcaps
print_success "Directories created"

# Install Python dependencies
print_status "Installing Python dependencies..."
echo
pip3 install -r requirements.txt --break-system-packages 2>/dev/null || pip3 install -r requirements.txt
echo
print_success "Dependencies installed"

# Generate SSL certificates
print_status "Generating SSL/TLS certificates..."
cd certs
if [ -f "server.crt" ] && [ -f "server.key" ]; then
    print_warning "Certificates already exist. Skipping generation."
    read -p "Do you want to regenerate certificates? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -f ca.key ca.crt server.key server.crt
        bash generate_certs.sh
        print_success "Certificates regenerated"
    fi
else
    bash generate_certs.sh
    print_success "Certificates generated"
fi
cd "$PROJECT_ROOT"

# Create configuration files
print_status "Creating configuration files..."

# Server config
cat > config/server_config.json << 'EOF'
{
  "host": "localhost",
  "port": 5000,
  "cert_file": "certs/server.crt",
  "key_file": "certs/server.key",
  "max_clients": 50,
  "session_timeout": 3600,
  "log_level": "INFO"
}
EOF
print_success "Server configuration created"

# Client config
cat > config/client_config.json << 'EOF'
{
  "host": "localhost",
  "port": 5000,
  "ca_cert": "certs/server.crt",
  "connect_timeout": 30,
  "log_level": "INFO"
}
EOF
print_success "Client configuration created"

# Create .gitignore
print_status "Creating .gitignore..."
cat > .gitignore << 'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
venv/
ENV/
*.egg-info/
dist/
build/

# Logs
logs/*.log
*.log

# Database
data/*.db
*.db

# Certificates (keep in production, ignore in dev)
# Uncomment if you don't want to commit certs
# certs/*.key
# certs/*.crt
# certs/*.pem

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db

# Test outputs
test_output/
*.pcap
EOF
print_success ".gitignore created"

# Initialize database
print_status "Initializing database..."
python3 << 'PYEOF'
import sys
import os
sys.path.insert(0, 'src')
from server.user_db import UserDatabase

db = UserDatabase('data/users.db')
print("✓ Database initialized")
PYEOF
print_success "Database initialized"

# Run tests
print_status "Running protocol tests..."
python3 src/common/protocol.py > /dev/null 2>&1 && print_success "Protocol test passed" || print_warning "Protocol test had issues"

print_status "Running crypto tests..."
python3 src/common/crypto_utils.py > /dev/null 2>&1 && print_success "Crypto test passed" || print_warning "Crypto test had issues"

echo
echo "=========================================="
echo "  Setup Complete!"
echo "=========================================="
echo
echo "Next steps:"
echo
echo "1. Start the server:"
echo "   ${GREEN}python3 src/server/server.py${NC}"
echo
echo "2. In another terminal, start the client:"
echo "   ${GREEN}python3 src/client/client.py${NC}"
echo
echo "3. Run the interactive Packet Flow Simulator:"
echo "   ${GREEN}./simulate.sh${NC} (or ${GREEN}python3 src/tools/run_simulator.py${NC})"
echo
echo "4. Trace Wireshark packets in terminal:"
echo "   ${GREEN}python3 src/tools/packet_tracer.py --scenario all${NC}"
echo
echo "For Wireshark verification:"
echo "   ${YELLOW}wireshark pcaps/3_encrypted_chat.pcap${NC}"
echo "   Filter: ${YELLOW}tcp.port == 5000${NC}"
echo
echo "Documentation:"
echo "   • Protocol spec: docs/PROTOCOL_SPEC.md"
echo "   • Wireshark guide: docs/WIRESHARK_GUIDE.md"
echo "   • Lab report template: docs/LAB_REPORT_TEMPLATE.md"
echo
print_success "All done! Happy secure chatting! 🔒"
echo
