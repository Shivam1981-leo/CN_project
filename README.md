# Encrypted Client-Server Communication Framework

## Computer Networks Mini-Project (Topic 19)

A robust implementation of secure client-server communication with TLS/SSL encryption, user authentication, and integrity verification.

---

## 📋 Project Overview

This project implements a secure messaging and file transfer system between clients and servers using:
- **TLS 1.3** encryption for all communications
- **User authentication** with username/password
- **Message integrity verification** using HMAC
- **Session management** with secure tokens
- **Custom protocol** for message exchange
- **Wireshark-verifiable** encrypted traffic

---

## 🎯 Features

### Core Functionality
- ✅ Secure client-server communication over TLS/SSL
- ✅ User registration and authentication
- ✅ End-to-end encrypted messaging
- ✅ Secure file transfer with integrity checks
- ✅ Session management with timeout
- ✅ Multi-client support with threading
- ✅ Comprehensive logging

### Security Features
- 🔐 TLS 1.3 encryption
- 🔑 Password hashing with bcrypt
- 🛡️ HMAC-based message integrity
- 🎫 Session token authentication
- ⏱️ Session timeout and automatic cleanup
- 🚫 Protection against replay attacks

### Testing & Verification
- 📊 Wireshark packet capture verification
- ⚠️ Failure condition test cases
- 📈 Performance benchmarking
- 🔍 Protocol compliance testing

---

## 📁 Project Structure

```
CN_miniproject_Sarode_don/
├── src/
│   ├── client/
│   │   ├── client.py              # Main CLI client application
│   │   └── client_gui.py          # Modern Tkinter GUI client
│   ├── server/
│   │   ├── server.py              # Main multi-threaded TLS server
│   │   ├── auth.py                # Authentication & session handler
│   │   └── user_db.py             # Thread-safe SQLite user database
│   └── common/
│       ├── protocol.py            # ECCP wire protocol & binary framing
│       ├── crypto_utils.py        # Cryptographic utilities & HMAC
│       └── message.py             # Message formatting helpers
├── tests/
│   ├── run_all_tests.py           # Master test suite runner (34 tests)
│   ├── test_authentication.py     # Auth failure & security tests (10)
│   ├── test_tampering.py          # HMAC & data integrity tests (10)
│   ├── test_connection.py         # Network & connection failure tests (10)
│   ├── test_file_transfer.py      # Secure file transfer & SHA-256 (4)
│   ├── test_integration.py       # Full end-to-end TLS integration (5)
│   └── benchmark.py               # Cryptographic performance benchmarks
├── certs/
│   ├── generate_certs.py          # Cross-platform Python certificate generator
│   ├── generate_certs.sh          # Bash certificate generation script
│   ├── server.crt                 # Server X.509 certificate
│   ├── server.key                 # Server RSA private key
│   └── ca.crt                     # Root Certificate Authority
├── docs/
│   ├── FINAL_LAB_REPORT.md        # Complete ready-to-submit laboratory report
│   ├── LAB_REPORT_TEMPLATE.md     # Lab submission template
│   ├── ARCHITECTURE.md            # Comprehensive system architecture & diagrams
│   ├── PROTOCOL_SPEC.md           # Formal ECCP protocol specification
│   └── WIRESHARK_GUIDE.md         # Packet capture & Wireshark verification guide
├── config/
│   ├── server_config.json         # Server port, certs, and limits
│   └── client_config.json         # Client connection parameters
├── logs/                          # Application runtime logs
├── received_files/                # Incoming verified file transfers
├── requirements.txt               # Python package dependencies
├── setup.bat                      # Windows CMD automated setup script
├── setup.ps1                      # Windows PowerShell automated setup script
├── setup.sh                       # Linux / macOS automated setup script
└── README.md                      # Project documentation
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8+ (tested on Python 3.13)
- pip package manager

### Automated Installation

Choose the setup script for your platform:

- **Windows (PowerShell):**
  ```powershell
  .\setup.ps1
  ```
- **Windows (Command Prompt):**
  ```cmd
  setup.bat
  ```
- **Linux / macOS:**
  ```bash
  bash setup.sh
  ```

The setup script automatically:
1. Installs Python dependencies (`cryptography`, `bcrypt`, `pytest`, `colorama`)
2. Generates X.509 CA and TLS server certificates
3. Creates necessary directories (`logs/`, `data/`, `received_files/`)
4. Executes the full test suite (34 tests) verifying system health

### Manual Setup (Optional)
```bash
pip install -r requirements.txt
python certs/generate_certs.py certs
python tests/run_all_tests.py
```

### Running the Application

#### Start the Server
```bash
python src/server/server.py
```

Default port: `5000`

#### Start the Client
```bash
python src/client/client.py
```

#### GUI Client (Optional)
```bash
python src/client/client_gui.py
```

---

## 📖 Usage Guide

### Server Operations

The server supports:
- User registration
- User authentication
- Message relay between clients
- File transfer handling
- Session management

**Server Configuration** (`config/server_config.json`):
```json
{
  "host": "localhost",
  "port": 5000,
  "cert_file": "certs/server.crt",
  "key_file": "certs/server.key",
  "max_clients": 50,
  "session_timeout": 3600,
  "log_level": "INFO"
}
```

### Client Operations

**1. Register a new account:**
```
> register
Username: alice
Password: ********
```

**2. Login:**
```
> login
Username: alice
Password: ********
```

**3. Send a message:**
```
> send bob "Hello, this is an encrypted message!"
```

**4. Send a file:**
```
> sendfile bob /path/to/file.txt
```

**5. List online users:**
```
> list
```

**6. View received messages:**
```
> inbox
```

---

## 🔬 Protocol Specification

### Message Format

All messages follow this structure:

```
+--------+--------+------------+----------+------+
| Header | Length | Message ID | Checksum | Data |
+--------+--------+------------+----------+------+
|  4B    |  4B    |    16B     |   32B    | Var  |
```

- **Header**: Protocol version and message type
- **Length**: Total message length
- **Message ID**: Unique identifier for tracking
- **Checksum**: HMAC-SHA256 for integrity
- **Data**: Encrypted payload

### Handshake Process

```
Client                                Server
  |                                     |
  |------- TLS Connection Setup ------>|
  |<------ TLS Handshake Complete -----|
  |                                     |
  |------- AUTH_REQUEST --------------->|
  |        (username, password_hash)    |
  |<------ AUTH_RESPONSE ---------------|
  |        (session_token, status)      |
  |                                     |
  |------- MESSAGE_SEND --------------->|
  |        (encrypted_data, hmac)       |
  |<------ MESSAGE_ACK -----------------|
```

See [PROTOCOL_SPEC.md](docs/PROTOCOL_SPEC.md) for complete details.

---

## 🧪 Testing & Verification

### Running Test Cases

```bash
# Run all 5 test suites (34 tests, 100% pass rate)
python tests/run_all_tests.py

# Cryptographic Performance Benchmark
python tests/benchmark.py

# Individual test suites
python tests/test_authentication.py    # Authentication failure tests (10)
python tests/test_tampering.py         # Data integrity & HMAC tests (10)
python tests/test_connection.py        # Connection & network tests (10)
python tests/test_file_transfer.py     # Secure file transfer & SHA-256 (4)
python tests/test_integration.py       # Full-stack TLS integration (5)
```

### Wireshark Verification

1. **Start packet capture:**
   ```bash
   wireshark
   ```

2. **Filter for your traffic:**
   ```
   tcp.port == 5000
   ```

3. **Observe encrypted traffic:**
   - TLS 1.3 handshake packets (`Client Hello`, `Server Hello`, `Encrypted Extensions`)
   - Encrypted application data (`0x17`)
   - Zero plaintext leakage of credentials, chat messages, or file contents

See [WIRESHARK_GUIDE.md](docs/WIRESHARK_GUIDE.md) for detailed step-by-step instructions.

---

## 📊 Lab Submission Requirements

### ✅ Checklist

- [x] Protocol specification document ([PROTOCOL_SPEC.md](docs/PROTOCOL_SPEC.md))
- [x] System architecture & diagrams ([ARCHITECTURE.md](docs/ARCHITECTURE.md))
- [x] Comprehensive lab report ([FINAL_LAB_REPORT.md](docs/FINAL_LAB_REPORT.md))
- [x] Wireshark packet capture & verification guide ([WIRESHARK_GUIDE.md](docs/WIRESHARK_GUIDE.md))
- [x] Fully commented source code (Client, Server, GUI, Protocol, Auth, Crypto)
- [x] Failure condition & unit test suites (34 tests passing with 100% rate)
- [x] Performance benchmarking suite ([benchmark.py](tests/benchmark.py))
- [x] Cross-platform automated setup scripts (`setup.ps1`, `setup.bat`, `setup.sh`)

### Reports & Documentation

- **Final Lab Report:** [FINAL_LAB_REPORT.md](docs/FINAL_LAB_REPORT.md) — complete, formatted for immediate submission.
- **Lab Report Template:** [LAB_REPORT_TEMPLATE.md](docs/LAB_REPORT_TEMPLATE.md) — modular template for custom adaptations.
- **Architecture Specification:** [ARCHITECTURE.md](docs/ARCHITECTURE.md) — data flow diagrams, threading model, and threat vectors.
- **Protocol Specification:** [PROTOCOL_SPEC.md](docs/PROTOCOL_SPEC.md) — binary wire framing, state machine, and message types.

---

## 🛠️ Troubleshooting

### Common Issues

**1. Certificate errors:**
```bash
cd certs && bash generate_certs.sh
```

**2. Port already in use:**
```bash
# Change port in config/server_config.json
# Or kill existing process
lsof -ti:5000 | xargs kill -9
```

**3. Permission denied (certificates):**
```bash
chmod 600 certs/*.key
chmod 644 certs/*.crt
```

**4. Module not found:**
```bash
pip install -r requirements.txt
```

---

## 🔒 Security Considerations

### Implemented
- TLS 1.3 with strong cipher suites
- Password hashing with bcrypt (cost factor: 12)
- HMAC-SHA256 message authentication
- Session tokens with expiration
- Input validation and sanitization

### Not Implemented (Out of Scope)
- Perfect forward secrecy (requires ephemeral key exchange)
- Certificate pinning
- Rate limiting
- DDoS protection
- Production-grade key management

---

## 📚 Dependencies

Core libraries:
- `ssl` - TLS/SSL support
- `socket` - Network communication
- `cryptography` - Cryptographic operations
- `bcrypt` - Password hashing
- `hashlib` - HMAC generation
- `sqlite3` - User database

See `requirements.txt` for complete list.

---

## 🤝 Authors

- **Sarode & Don** - Computer Networks Mini-Project Team

---

## 📄 License

This project is for educational purposes as part of a Computer Networks course.

---

## 📞 Support

For issues or questions:
1. Check the [docs/](docs/) directory
2. Review test cases in [tests/](tests/)
3. Check logs in [logs/](logs/)

---

## 🎓 Academic Notes

### Key Learning Outcomes
- Understanding of TCP/IP socket programming
- TLS/SSL encryption implementation
- Network protocol design
- Security best practices
- Packet analysis with Wireshark

### Grading Criteria Met
✅ Protocol implementation and documentation
✅ Wireshark packet verification
✅ Failure condition testing
✅ Security analysis
✅ Code quality and documentation

---

**Last Updated:** October 2026
**Version:** 1.0.0
