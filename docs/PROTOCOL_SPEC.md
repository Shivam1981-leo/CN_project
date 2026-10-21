# Protocol Specification
## Encrypted Client-Server Communication Protocol (ECCP)

**Version:** 1.0  
**Date:** October 2026  
**Authors:** Sarode & Don

---

## Table of Contents

1. [Overview](#overview)
2. [Protocol Architecture](#protocol-architecture)
3. [Message Format](#message-format)
4. [Message Types](#message-types)
5. [Handshake Process](#handshake-process)
6. [Security Mechanisms](#security-mechanisms)
7. [Error Handling](#error-handling)
8. [Implementation Details](#implementation-details)

---

## Overview

The Encrypted Client-Server Communication Protocol (ECCP) is a secure messaging protocol designed for authenticated, encrypted communication between clients and a central server. The protocol operates over TLS 1.2/1.3 and implements additional application-layer security features.

### Design Goals

- **Confidentiality**: All communications encrypted end-to-end
- **Integrity**: Message tampering detection via HMAC
- **Authentication**: User identity verification
- **Session Management**: Secure token-based sessions
- **Reliability**: Guaranteed message delivery with offline storage

### Protocol Stack

```
+------------------------+
|   Application Layer    |  (ECCP Messages)
+------------------------+
|   Presentation Layer   |  (JSON Serialization)
+------------------------+
|   Session Layer        |  (Token-based Sessions)
+------------------------+
|   Transport Layer      |  (TLS 1.2/1.3)
+------------------------+
|   Network Layer        |  (TCP/IP)
+------------------------+
```

---

## Protocol Architecture

### Components

1. **Client Application**
   - Initiates connections
   - Sends/receives messages
   - Manages user interface

2. **Server Application**
   - Accepts connections
   - Routes messages
   - Manages user database
   - Handles offline message storage

3. **Security Layer**
   - TLS encryption
   - HMAC integrity checks
   - Password hashing (bcrypt)
   - Session token management

### Communication Flow

```
┌─────────┐                              ┌─────────┐
│ Client  │                              │ Server  │
│    A    │                              │         │
└────┬────┘                              └────┬────┘
     │                                        │
     │  1. TLS Handshake                     │
     │ ─────────────────────────────────────>│
     │                                        │
     │  2. Server Certificate                │
     │ <─────────────────────────────────────│
     │                                        │
     │  3. AUTH_REQUEST                      │
     │    (username, password_hash)          │
     │ ─────────────────────────────────────>│
     │                                        │
     │  4. AUTH_RESPONSE                     │
     │    (session_token, status)            │
     │ <─────────────────────────────────────│
     │                                        │
     │  5. MESSAGE_SEND                      │
     │    (recipient, content, token)        │
     │ ─────────────────────────────────────>│
     │                                        │
     │  6. MESSAGE_ACK (success)             │
     │ <─────────────────────────────────────│
     │                                        │
```

---

## Message Format

All ECCP messages follow a fixed binary format:

### Wire Format Structure

```
+--------+--------+------------+----------+------+
| Header | Length | Message ID | Checksum | Data |
+--------+--------+------------+----------+------+
|  4B    |  4B    |    16B     |   32B    | Var  |
```

### Field Descriptions

#### 1. Header (4 bytes)
- **Bytes 0-2**: Protocol Version (`ECCP` = 0x45434350)
- **Byte 3**: Message Type (see Message Types section)

#### 2. Length (4 bytes)
- **Type**: Unsigned 32-bit integer (big-endian)
- **Value**: Total message length (excluding length field itself)
- **Range**: 4 to 10,485,760 (10 MB)

#### 3. Message ID (16 bytes)
- **Type**: UUID (RFC 4122)
- **Purpose**: Unique message identification for tracking and deduplication

#### 4. Checksum (32 bytes)
- **Type**: HMAC-SHA256
- **Input**: Header + Length + Message ID + Data
- **Key**: Shared secret between client and server
- **Purpose**: Message integrity verification

#### 5. Data (Variable)
- **Encoding**: UTF-8 JSON
- **Structure**: Key-value pairs specific to message type
- **Max Size**: 10 MB

### Example: Auth Request Message

```
Hex dump of wire format:

45 43 43 50                              // Header: "ECCP"
01                                       // Type: AUTH_REQUEST
00 00 00 A4                              // Length: 164 bytes
3F 6D 2B 1E 9A 8C 4D 21                 // Message ID (UUID)
B3 7F C8 5E 11 02 6A 94
9C 8A 3E 7D 2F 6B 1A 5C                 // HMAC-SHA256 (32 bytes)
4D 9E 2A 7F 8B 3C 1D 6E
0F 5A 9B 4C 7E 2D 8F 1A
3B 6C 9D 5E 0A 4F 7C 2E
7B 22 75 73 65 72 6E 61 6D 65 22 3A     // Data (JSON)
22 61 6C 69 63 65 22 2C 22 70 61 73
73 77 6F 72 64 5F 68 61 73 68 22 3A
...
```

Decoded data:
```json
{
  "username": "alice",
  "password_hash": "JDJiJDEyJC4uLg==",
  "timestamp": 1697025162
}
```

---

## Message Types

### Authentication Messages

#### AUTH_REQUEST (0x01)
**Direction**: Client → Server  
**Purpose**: Authenticate user credentials

**Data Fields**:
```json
{
  "username": "string (max 32 chars)",
  "password_hash": "string (bcrypt hash, base64)",
  "timestamp": "integer (unix timestamp)"
}
```

**Response**: AUTH_RESPONSE

---

#### AUTH_RESPONSE (0x02)
**Direction**: Server → Client  
**Purpose**: Return authentication result

**Data Fields**:
```json
{
  "status": "integer (StatusCode)",
  "session_token": "string (hex, 64 chars)" // Only on success
}
```

**Status Codes**:
- `0x00`: SUCCESS
- `0x01`: AUTH_FAILED

---

#### REGISTER_REQUEST (0x03)
**Direction**: Client → Server  
**Purpose**: Register new user account

**Data Fields**:
```json
{
  "username": "string (max 32 chars, alphanumeric)",
  "password_hash": "string (bcrypt hash, base64)"
}
```

**Response**: REGISTER_RESPONSE

---

#### REGISTER_RESPONSE (0x04)
**Direction**: Server → Client  
**Purpose**: Return registration result

**Data Fields**:
```json
{
  "status": "integer (StatusCode)"
}
```

**Status Codes**:
- `0x00`: SUCCESS
- `0x02`: USER_EXISTS
- `0x06`: SERVER_ERROR

---

#### LOGOUT (0x05)
**Direction**: Client → Server  
**Purpose**: Terminate session

**Data Fields**:
```json
{
  "session_token": "string"
}
```

**Response**: None (connection closes)

---

### Messaging

#### MESSAGE_SEND (0x10)
**Direction**: Client → Server  
**Purpose**: Send message to another user

**Data Fields**:
```json
{
  "recipient": "string (username)",
  "content": "string (message content)",
  "session_token": "string",
  "timestamp": "integer"
}
```

**Response**: MESSAGE_ACK

---

#### MESSAGE_RECEIVE (0x11)
**Direction**: Server → Client  
**Purpose**: Deliver incoming message

**Data Fields**:
```json
{
  "sender": "string (username)",
  "content": "string (message content)"
}
```

**Response**: None (one-way notification)

---

#### MESSAGE_ACK (0x12)
**Direction**: Server → Client  
**Purpose**: Acknowledge message receipt

**Data Fields**:
```json
{
  "status": "integer (StatusCode)",
  "original_message_id": "string (hex)" // Optional
}
```

**Status Codes**:
- `0x00`: SUCCESS
- `0x03`: USER_NOT_FOUND
- `0x04`: INVALID_SESSION
- `0x05`: MESSAGE_TOO_LARGE

---

### Status Messages

#### PING (0x30)
**Direction**: Client → Server  
**Purpose**: Keep-alive / connection test

**Data Fields**: `{}`

**Response**: PONG

---

#### PONG (0x31)
**Direction**: Server → Client  
**Purpose**: Response to PING

**Data Fields**:
```json
{
  "timestamp": "string (ISO 8601)"
}
```

---

#### USER_LIST_REQUEST (0x32)
**Direction**: Client → Server  
**Purpose**: Request list of online users

**Data Fields**:
```json
{
  "session_token": "string"
}
```

**Response**: USER_LIST_RESPONSE

---

#### USER_LIST_RESPONSE (0x33)
**Direction**: Server → Client  
**Purpose**: Return online users

**Data Fields**:
```json
{
  "users": ["string", "string", ...]
}
```

---

#### ERROR (0xFF)
**Direction**: Server → Client  
**Purpose**: Report error condition

**Data Fields**:
```json
{
  "error_code": "integer (StatusCode)",
  "error_message": "string"
}
```

---

## Handshake Process

### Complete Authentication Flow

```
Phase 1: Transport Security
─────────────────────────────────────────
Client                                Server
  │                                     │
  │  ClientHello (TLS 1.3)             │
  │ ──────────────────────────────────>│
  │                                     │
  │  ServerHello + Certificate          │
  │  + ServerKeyExchange                │
  │ <──────────────────────────────────│
  │                                     │
  │  ClientKeyExchange                  │
  │  ChangeCipherSpec                   │
  │  Finished                           │
  │ ──────────────────────────────────>│
  │                                     │
  │  ChangeCipherSpec                   │
  │  Finished                           │
  │ <──────────────────────────────────│
  │                                     │
  │  [TLS tunnel established]           │
  │                                     │

Phase 2: Application Authentication
─────────────────────────────────────────
  │                                     │
  │  AUTH_REQUEST                       │
  │  {username, password_hash}          │
  │ ──────────────────────────────────>│
  │                                     │
  │     [Server validates credentials]  │
  │     [Creates session token]         │
  │                                     │
  │  AUTH_RESPONSE                      │
  │  {status: SUCCESS,                  │
  │   session_token: "abc123..."}       │
  │ <──────────────────────────────────│
  │                                     │
  │     [Server delivers offline msgs]  │
  │                                     │
  │  MESSAGE_RECEIVE (if any pending)   │
  │ <──────────────────────────────────│
  │                                     │
  │  [Client ready for messaging]       │
  │                                     │
```

---

## Security Mechanisms

### 1. Transport Layer Security (TLS)

**Protocol**: TLS 1.2/1.3  
**Cipher Suites** (in order of preference):
- `TLS_AES_256_GCM_SHA384`
- `TLS_CHACHA20_POLY1305_SHA256`
- `TLS_AES_128_GCM_SHA256`

**Certificate Validation**:
- Server presents X.509 certificate
- Client verifies certificate chain (in production)
- Self-signed certificates allowed (development only)

### 2. Password Security

**Hashing Algorithm**: bcrypt  
**Cost Factor**: 12 (2^12 = 4096 iterations)  
**Salt**: Random, 16 bytes per password  
**Output**: 60-byte hash, base64-encoded

**Example**:
```
Input:    "SecurePassword123!"
Salt:     (random 16 bytes)
Hash:     $2b$12$xyz.../ABC...
Encoded:  "JDJiJDEyJHh5ei4uLi9BQkMuLi4="
```

### 3. Message Integrity (HMAC)

**Algorithm**: HMAC-SHA256  
**Key**: Shared secret (32 bytes)  
**Input**: Header + Length + Message ID + Data  
**Output**: 32-byte digest

**Verification**:
```python
calculated_hmac = HMAC-SHA256(key, message_data)
if calculated_hmac == received_hmac:
    # Message is authentic and unmodified
else:
    # Reject message - potential tampering
```

### 4. Session Management

**Token Generation**:
```python
token_data = username + timestamp + random(16 bytes)
session_token = SHA256(token_data).hexdigest()
# Result: 64-character hex string
```

**Session Properties**:
- **Lifetime**: 3600 seconds (1 hour)
- **Storage**: Server-side in-memory
- **Validation**: On every request
- **Revocation**: On logout or expiry

### 5. Replay Attack Prevention

**Mechanism**: Timestamp in authentication messages

```json
{
  "username": "alice",
  "password_hash": "...",
  "timestamp": 1697025162  // Current unix timestamp
}
```

Server rejects requests with:
- Timestamp > 60 seconds in the past
- Timestamp in the future

---

## Error Handling

### Status Codes

| Code | Name | Description |
|------|------|-------------|
| 0x00 | SUCCESS | Operation completed successfully |
| 0x01 | AUTH_FAILED | Authentication failed |
| 0x02 | USER_EXISTS | Username already registered |
| 0x03 | USER_NOT_FOUND | Recipient does not exist |
| 0x04 | INVALID_SESSION | Session token invalid or expired |
| 0x05 | MESSAGE_TOO_LARGE | Message exceeds 10MB limit |
| 0x06 | SERVER_ERROR | Internal server error |
| 0x07 | CHECKSUM_MISMATCH | HMAC verification failed |
| 0x08 | PROTOCOL_ERROR | Invalid message format |

### Error Response Format

When an error occurs, server sends ERROR message:

```json
{
  "error_code": 0x07,
  "error_message": "Message integrity check failed"
}
```

### Client Error Handling

```python
if message.msg_type == MessageType.ERROR:
    error_code = StatusCode(message.data['error_code'])
    error_message = message.data['error_message']
    
    if error_code == StatusCode.INVALID_SESSION:
        # Re-authenticate
        client.login()
    elif error_code == StatusCode.CHECKSUM_MISMATCH:
        # Log potential attack
        logger.warning("Integrity check failed")
    # ... handle other errors
```

---

## Implementation Details

### Connection Lifecycle

```
1. INIT       → Client creates socket
2. CONNECT    → TCP connection established
3. TLS_SETUP  → TLS handshake completes
4. AUTH       → User authentication
5. READY      → Ready for messaging
6. ACTIVE     → Sending/receiving messages
7. LOGOUT     → User disconnects
8. CLOSED     → Socket closed
```

### Message Size Limits

| Component | Maximum Size |
|-----------|--------------|
| Username | 32 bytes |
| Password | 128 bytes |
| Message content | 10 MB |
| Total message | 10 MB |

### Timeouts

| Operation | Timeout |
|-----------|---------|
| TCP connect | 30 seconds |
| TLS handshake | 30 seconds |
| Authentication | 10 seconds |
| Message send | 60 seconds |
| Session lifetime | 3600 seconds |

### Threading Model

**Server**:
- Main thread: Accept connections
- Per-client threads: Handle individual clients
- Cleanup thread: Remove expired sessions

**Client**:
- Main thread: User interface
- Receiver thread: Incoming messages

---

## Protocol Extensions (Future)

Potential enhancements for future versions:

1. **File Transfer Protocol**
   - Chunked file transmission
   - Resume capability
   - Compression

2. **Group Messaging**
   - Multi-recipient messages
   - Group management

3. **End-to-End Encryption**
   - Per-message encryption keys
   - Forward secrecy

4. **Presence Information**
   - Online/offline/away status
   - Last seen timestamps

---

## References

- RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
- RFC 2104: HMAC: Keyed-Hashing for Message Authentication
- RFC 4122: A Universally Unique IDentifier (UUID) URN Namespace

---

**Document Version**: 1.0  
**Last Updated**: October 11, 2026  
**Status**: Final
