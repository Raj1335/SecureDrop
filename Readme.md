# SecureDrop - Secure Peer-to-Peer File Transfer

**Version 1.0** - Enterprise-grade cryptographic protocol for local file sharing.

## Security Features

- **SPAKE2 PAKE**: Password-authenticated key exchange (offline brute-force resistant)
- **X25519 Ephemeral DH**: Forward secrecy (past sessions safe even if code compromised)
- **ChaCha20-Poly1305 AEAD**: Authenticated encryption (detects tampering)
- **SAS Verification**: Human-verifiable fingerprint (MITM detection)
- **Zero Internet Usage**: All transfers over local network only

## Threat Model

**Protects against:**
- Passive eavesdropping (traffic capture)
- Active MITM attacks (connection hijacking)
- Offline brute-force (recorded traffic analysis)
- Replay attacks (reused messages)
- Tampering (modified chunks)

**Does not protect against:**
- Compromised devices (malware)
- Denial-of-service flooding
- Physical device access

## Installation
```bash
# Install dependencies
pip install -r requirements.txt

# Verify installation
python -c "import spake2, cryptography; print('Ready')"
```

## Usage

### Receiver (starts first):
```bash
python receiver.py
# Displays 6-digit code and SAS for verification
```

### Sender:
```bash
python sender.py <receiver_ip> <6-digit-code> <file_path>

# Example:
python sender.py 192.168.1.5 123456 document.pdf
```

### SAS Verification:

Both sides will display a Short Authentication String (SAS). **Compare manually**:
- Words must match exactly
- Or compare hex/decimal representation
- If mismatch: **ABORT** (possible MITM attack)

## Protocol Overview

1. **HELLO exchange** - Nonces exchanged
2. **SPAKE2** - Password-authenticated key derivation
3. **X25519 DH** - Ephemeral key exchange
4. **HKDF** - Session key derivation
5. **SAS display** - Manual confirmation
6. **Key confirmation** - HMAC verification
7. **AEAD transfer** - Encrypted file chunks
8. **Integrity check** - SHA-256 verification

## Architecture
```
core/
├── protocol.py    # Message framing (19 message types)
├── pake.py        # SPAKE2 wrapper
├── crypto.py      # X25519, HKDF, ChaCha20-Poly1305
└── sas.py         # Short Authentication String
```

## Security Parameters

- **PAKE**: SPAKE2 on Curve25519
- **DH**: X25519 (ephemeral)
- **KDF**: HKDF-SHA256
- **AEAD**: ChaCha20-Poly1305 (256-bit key)
- **SAS**: 40 bits (6 words) or 64 bits (8 digits)
- **Nonces**: 12-byte counter (per-message unique)

## License

Open Source - Educational/Research Use

## Credits

Implements cryptographic protocols per industry standards:
- SPAKE2: [RFC 9382](https://www.rfc-editor.org/rfc/rfc9382)
- X25519: [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748)
- ChaCha20-Poly1305: [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439)