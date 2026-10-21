# Wireshark Verification Guide
## Packet Capture and Analysis for ECCP

**Project:** Encrypted Client-Server Communication Framework  
**Purpose:** Lab submission requirement - Network traffic verification  
**Date:** October 2026

---

## Table of Contents

1. [Introduction](#introduction)
2. [Prerequisites](#prerequisites)
3. [Capturing Traffic](#capturing-traffic)
4. [Traffic Analysis](#traffic-analysis)
5. [Verification Checklist](#verification-checklist)
6. [Screenshot Guide](#screenshot-guide)
7. [Troubleshooting](#troubleshooting)

---

## Introduction

This guide demonstrates how to use Wireshark to verify that the Encrypted Client-Server Communication Protocol (ECCP) properly encrypts all application data, making it unreadable to network eavesdroppers.

### What You'll Verify

✅ TLS handshake completes successfully  
✅ All application data is encrypted  
✅ No plaintext usernames, passwords, or messages visible  
✅ Protocol uses TLS 1.2 or 1.3  
✅ Strong cipher suites are negotiated (TLS_AES_256_GCM_SHA384)  
✅ HMAC-SHA256 message integrity detects active wire tampering  

---

## 🌟 Interactive Packet Flow Simulator & Tracer

This project includes a **real-time visual packet flow simulator** and an **authentic Wireshark PCAP generator**:

### 1. Launching the Interactive Web Simulator
To launch the interactive visual simulation with animated node-to-node packets and embedded Wireshark trace:
```bash
# Windows
simulate.bat
# OR
python src/tools/run_simulator.py

# Linux / macOS
./simulate.sh
# OR
python3 src/tools/run_simulator.py
```
This automatically opens `http://127.0.0.1:8080` in your web browser with:
- **4-Node Animated Topology**: Alice ➔ Wire Tap / Sniffer ➔ ECCP Server ➔ Bob
- **5 Selectable Scenarios**:
  1. TLS 1.3 Handshake & Key Exchange
  2. Secure Authentication (bcrypt over TLS + Session Token)
  3. End-to-End Encrypted Chat with HMAC
  4. Secure File Transfer (12 Chunks + SHA-256 verification)
  5. Active MITM Tampering Attack & Defense
- **Interactive Wireshark Table**: Click any packet to inspect OSI layers, Hex Dump, and Plaintext vs Ciphertext wire comparison.
- **One-Click PCAP Download**: Direct download button to open the capture in Wireshark!

### 2. Built-in Terminal Packet Tracer
If you don't have Wireshark installed, you can trace packets directly in your terminal:
```bash
# Trace all 5 scenarios with colored Wireshark-like output
python src/tools/packet_tracer.py --scenario all

# Deep inspect a specific packet (e.g. Frame #4 Client Hello)
python src/tools/packet_tracer.py --scenario 1 --inspect 4
```

### 3. Pre-Generated Authentic PCAP Files
The project provides genuine standard Libpcap 2.4 `.pcap` files in the `pcaps/` directory that can be opened directly in Wireshark:
```bash
wireshark pcaps/1_tls13_handshake.pcap
wireshark pcaps/2_user_auth_session.pcap
wireshark pcaps/3_encrypted_chat.pcap
wireshark pcaps/4_secure_file_transfer.pcap
wireshark pcaps/5_mitm_tampering_attack.pcap
```
To regenerate all PCAP files at any time:
```bash
python src/tools/packet_tracer.py --generate-all
```

---

## Prerequisites

### Install Wireshark

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install wireshark
sudo usermod -a -G wireshark $USER
# Log out and back in for group changes to take effect
```

**macOS:**
```bash
brew install wireshark
```

**Windows:**
Download from [https://www.wireshark.org/download.html](https://www.wireshark.org/download.html)

### Run with Proper Permissions

**Linux:**
```bash
sudo wireshark
# OR configure to run without sudo:
sudo dpkg-reconfigure wireshark-common
# Select "Yes" to allow non-superusers to capture packets
```

### Start the Server

Before capturing, start the server:
```bash
cd CN_miniproject_Sarode_don
python3 src/server/server.py
```

---

## Capturing Traffic

### Step 1: Start Wireshark

1. Launch Wireshark with administrator/sudo privileges
2. Select the appropriate network interface:
   - **Loopback/lo** (for localhost testing)
   - **eth0/wlan0** (for network testing)

![Select Interface](screenshots/wireshark_interface.png)

### Step 2: Apply Capture Filter

Before starting capture, apply a filter to reduce noise:

**Capture Filter:**
```
tcp port 5000
```

Enter this in the capture filter field and click the blue shark fin icon to start.

### Step 3: Generate Traffic

In a new terminal, start the client and perform operations:

```bash
python3 src/client/client.py
```

**Actions to perform:**
1. Register a new user
2. Login with credentials
3. Send a message to another user
4. List online users
5. Logout

Keep Wireshark running throughout these operations.

### Step 4: Stop Capture

After completing the test actions:
1. Click the red square (Stop) button in Wireshark
2. Save the capture: `File → Save As → eccp_capture.pcapng`

---

## Traffic Analysis

### Apply Display Filters

Use these filters to analyze specific traffic:

#### View All ECCP Traffic
```
tcp.port == 5000
```

#### View TLS Handshake Only
```
ssl.handshake.type
```
or
```
tls.handshake.type
```

#### View Encrypted Application Data
```
ssl.app_data || tls.app_data
```

#### View Specific Connection
```
tcp.stream eq 0
```
(Change 0 to the stream number of interest)

### Traffic Flow Overview

You should see the following sequence:

```
1. TCP Three-Way Handshake
   ├─ SYN      (Client → Server)
   ├─ SYN-ACK  (Server → Client)
   └─ ACK      (Client → Server)

2. TLS Handshake
   ├─ Client Hello
   ├─ Server Hello
   ├─ Certificate
   ├─ Server Key Exchange
   ├─ Server Hello Done
   ├─ Client Key Exchange
   ├─ Change Cipher Spec (Client)
   ├─ Encrypted Handshake Message (Client)
   ├─ Change Cipher Spec (Server)
   └─ Encrypted Handshake Message (Server)

3. Application Data (All Encrypted)
   ├─ Application Data (Client → Server) [AUTH_REQUEST]
   ├─ Application Data (Server → Client) [AUTH_RESPONSE]
   ├─ Application Data (Client → Server) [MESSAGE_SEND]
   └─ Application Data (Server → Client) [MESSAGE_ACK]

4. Connection Teardown
   ├─ Encrypted Alert (Close Notify)
   └─ TCP FIN/ACK
```

### Detailed Packet Analysis

#### 1. TCP Handshake

Select the first SYN packet and expand:
- `Transmission Control Protocol`
- Note the source and destination ports

![TCP Handshake](screenshots/tcp_handshake.png)

#### 2. TLS Client Hello

Find and select the "Client Hello" packet:

**Key Information to Note:**
```
Transport Layer Security
  └─ TLSv1.3 Record Layer: Handshake Protocol: Client Hello
     ├─ Content Type: Handshake (22)
     ├─ Version: TLS 1.2 (0x0303)
     ├─ Length: ...
     └─ Handshake Protocol: Client Hello
        ├─ Handshake Type: Client Hello (1)
        ├─ Cipher Suites (offered):
        │  ├─ TLS_AES_256_GCM_SHA384
        │  ├─ TLS_CHACHA20_POLY1305_SHA256
        │  └─ TLS_AES_128_GCM_SHA256
        └─ Extensions:
           ├─ server_name: localhost
           └─ supported_versions: TLS 1.3
```

**Screenshot Requirements:**
- Capture showing cipher suites offered
- Version numbers clearly visible

#### 3. TLS Server Hello

Select the "Server Hello" packet:

**Key Information:**
```
Transport Layer Security
  └─ TLSv1.3 Record Layer: Handshake Protocol: Server Hello
     ├─ Content Type: Handshake (22)
     └─ Handshake Protocol: Server Hello
        ├─ Handshake Type: Server Hello (2)
        ├─ Cipher Suite: TLS_AES_256_GCM_SHA384 (0x1301)
        └─ Extensions:
           └─ supported_versions: TLS 1.3
```

**Verification:**
✅ Server selected a strong cipher suite  
✅ TLS 1.3 was negotiated (or TLS 1.2 minimum)

#### 4. Server Certificate

Select the "Certificate" packet:

**Key Information:**
```
Transport Layer Security
  └─ TLSv1.3 Record Layer: Handshake Protocol: Certificate
     └─ Handshake Protocol: Certificate
        └─ Certificates
           └─ Certificate: ... (X.509 certificate data)
              ├─ Subject: CN=localhost, O=CN Mini Project...
              ├─ Issuer: CN=CN Mini Project CA...
              └─ Validity Period
```

**Verification:**
✅ Certificate matches your server  
✅ Certificate is properly formatted

#### 5. Encrypted Application Data

Select any "Application Data" packet after the handshake:

**Key Observations:**
```
Transport Layer Security
  └─ TLSv1.3 Record Layer: Application Data Protocol
     ├─ Content Type: Application Data (23)
     ├─ Version: TLS 1.2 (0x0303)
     ├─ Length: XXX
     └─ Encrypted Application Data: [opaque data]
```

**Critical Verification:**
❌ **NO plaintext visible** in the packet data  
❌ **NO usernames visible**  
❌ **NO passwords visible**  
❌ **NO message content visible**  
✅ **Only encrypted binary data**

**Right-click packet → Follow → TCP Stream:**
- Should show encrypted binary data
- No readable text for application messages

![Encrypted Data](screenshots/encrypted_data.png)

---

## Verification Checklist

Use this checklist for your lab report:

### ✅ TLS Layer Verification

- [ ] TCP three-way handshake completes successfully
- [ ] TLS Client Hello packet present
- [ ] TLS Server Hello packet present
- [ ] Server certificate transmitted
- [ ] TLS version is 1.2 or higher
- [ ] Strong cipher suite negotiated (AES-256-GCM or ChaCha20-Poly1305)
- [ ] No TLS alerts or errors

### ✅ Encryption Verification

- [ ] All application data packets show "Encrypted Application Data"
- [ ] No plaintext usernames visible
- [ ] No plaintext passwords visible
- [ ] No plaintext message content visible
- [ ] TCP stream shows only binary encrypted data
- [ ] Packet hex dump shows no readable strings

### ✅ Protocol Verification

- [ ] Client sends data after TLS handshake (AUTH_REQUEST)
- [ ] Server responds with data (AUTH_RESPONSE)
- [ ] Bidirectional encrypted communication established
- [ ] Connection properly closed with TLS alert

---

## Screenshot Guide

### Required Screenshots for Lab Report

#### Screenshot 1: Wireshark Overview
**Capture:** Main Wireshark window showing captured packets  
**Filter:** `tcp.port == 5000`  
**Highlight:** TLS handshake and encrypted application data packets

**What to show:**
- Packet list with clear sequence numbers
- Time column visible
- Source/destination visible
- Protocol column showing TLS

**Annotations:**
- Label TLS handshake section
- Label encrypted application data section

---

#### Screenshot 2: TLS Handshake Details
**Select:** Client Hello or Server Hello packet  
**Expand:** Transport Layer Security section

**What to show:**
- TLS version (1.2 or 1.3)
- Cipher suites
- Extensions (if applicable)

**Annotations:**
- Highlight TLS version
- Highlight selected cipher suite

---

#### Screenshot 3: Encrypted Application Data
**Select:** Any Application Data packet  
**Expand:** Transport Layer Security → Application Data

**What to show:**
- Content Type: Application Data (23)
- Length of encrypted data
- Encrypted Application Data field (opaque)

**Annotations:**
- Circle "Encrypted Application Data"
- Note: "No plaintext visible"

---

#### Screenshot 4: TCP Stream (Hex/ASCII View)
**Action:** Right-click packet → Follow → TCP Stream  
**View Mode:** Hex Dump

**What to show:**
- Encrypted binary data
- No readable text strings
- Random-looking hex values

**Annotations:**
- "All application data encrypted"
- "No sensitive information visible"

---

#### Screenshot 5: Server Certificate
**Select:** Certificate packet  
**Expand:** Certificate details

**What to show:**
- Subject name (CN=localhost)
- Issuer information
- Validity period

---

### How to Take Screenshots

**Wireshark Built-in:**
```
File → Export Packet Dissections → As Plain Text
```

**Or use system screenshot tools:**
- **Linux:** `gnome-screenshot` or `scrot`
- **macOS:** `Cmd + Shift + 4`
- **Windows:** `Win + Shift + S`

### Screenshot Annotations

Use an image editor to add annotations:
- **Arrows** pointing to important fields
- **Circles** highlighting key information
- **Text labels** explaining what is shown
- **Color coding** for different packet types

---

## Troubleshooting

### Issue: No Packets Captured

**Causes:**
- Wrong network interface selected
- Server not running
- Client not connected

**Solutions:**
```bash
# Verify server is running
netstat -tuln | grep 5000

# On Windows:
netstat -an | findstr 5000

# Verify correct interface
ip addr show  # Linux
ifconfig      # macOS
ipconfig      # Windows
```

---

### Issue: Cannot See TLS Handshake

**Cause:** Capture started after connection established

**Solution:**
1. Stop current capture
2. Restart client
3. Start new capture BEFORE client connects
4. Then run client

---

### Issue: Packets Show as TCP, Not TLS

**Cause:** Wireshark doesn't recognize port 5000 as TLS

**Solution:**
1. Right-click any packet
2. Select `Decode As...`
3. Add new entry:
   - Field: `TCP port`
   - Value: `5000`
   - Current: `(none)`
   - Set to: `SSL` or `TLS`
4. Click OK

![Decode As](screenshots/decode_as.png)

---

### Issue: Want to Decrypt TLS Traffic

**Important:** This should NOT be possible with proper TLS!

If you need to decrypt for debugging:
1. Use SSLKEYLOGFILE environment variable
2. Configure server to log session keys
3. Load keys into Wireshark

**For lab report:** Demonstrate that traffic CANNOT be decrypted without keys!

---

## Advanced Analysis

### Statistics

View protocol hierarchy:
```
Statistics → Protocol Hierarchy
```

Shows percentage of TLS traffic.

### I/O Graph

Create a graph of traffic over time:
```
Statistics → I/O Graph
```

**Filters to plot:**
- `tcp.port == 5000` (total traffic)
- `ssl.handshake.type` (handshakes)
- `ssl.app_data` (encrypted data)

### Conversations

View all TCP conversations:
```
Statistics → Conversations → TCP tab
```

Shows:
- Client/server addresses
- Packets exchanged
- Bytes transferred

---

## Lab Report Integration

### Section: Network Traffic Analysis

**Include:**

1. **Introduction**
   - Purpose of packet capture
   - Tools used (Wireshark version)
   - Network setup (localhost, etc.)

2. **Methodology**
   - Capture filter used
   - Actions performed during capture
   - Duration of capture

3. **Results**
   - Screenshot 1: Overview
   - Screenshot 2: TLS handshake
   - Screenshot 3: Encrypted data
   - Screenshot 4: TCP stream
   - Screenshot 5: Certificate

4. **Analysis**
   - TLS version used: ___
   - Cipher suite: ___
   - Certificate valid: Yes/No
   - Encryption verified: Yes/No

5. **Conclusions**
   - All traffic properly encrypted ✅
   - No plaintext visible ✅
   - Strong security protocols used ✅

---

## Export Capture for Submission

### Save Capture File

```
File → Save As
Filename: eccp_capture.pcapng
Format: Pcapng
```

### Export Packet Details

```
File → Export Packet Dissections → As Plain Text
Packet Range: Selected packet only
Packet Details: All expanded
Include: All

Filename: packet_details.txt
```

### Create Summary Report

```
Statistics → Capture File Properties
Click "Save"
Filename: capture_summary.txt
```

---

## Example Capture Analysis

### Sample Output

```
Capture File: eccp_capture.pcapng
Duration: 15.342 seconds
Packets: 127
Average packets/sec: 8.3

Protocol Hierarchy:
  Ethernet: 100%
    IP: 100%
      TCP: 100%
        TLS: 98.4%
          Application Data: 85.2%

TLS Versions:
  TLS 1.3: 100%

Cipher Suites:
  TLS_AES_256_GCM_SHA384: 100%

Verification:
  ✅ All application data encrypted
  ✅ No plaintext credentials visible
  ✅ Strong cipher suite used
  ✅ TLS 1.3 negotiated successfully
```

---

## References

- Wireshark User Guide: https://www.wireshark.org/docs/
- TLS 1.3 RFC 8446
- Display Filter Reference: https://www.wireshark.org/docs/dfref/

---

## Tips for Lab Demonstration

1. **Practice beforehand** - Capture multiple times until comfortable
2. **Annotate screenshots** clearly with arrows and labels
3. **Explain each packet** type in your report
4. **Compare encrypted vs unencrypted** - Show what attackers would see
5. **Highlight security features** - Point out strong cipher suites
6. **Document everything** - Timestamp, filter used, actions taken

---

**Last Updated:** October 11, 2026  
**Version:** 1.0
