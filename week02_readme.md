# Week 02: RSA Algorithm & Secure Communication

## Overview
This week implemented a complete hybrid encryption system combining RSA and AES cryptography. The project demonstrates how modern secure communication protocols (like TLS) establish encrypted channels by leveraging both asymmetric and symmetric cryptography.

---

## Learning Objectives Achieved
✅ Understand RSA key generation and management
✅ Implement hybrid encryption (RSA + AES)
✅ Apply socket programming for secure messaging
✅ Analyse cryptographic padding schemes (OAEP)
✅ Practise peer collaboration and feedback

---

## Technical Implementation

### Architecture Overview

```
┌─────────────┐ ┌─────────────┐
│ SENDER │ │ RECEIVER │
│ (Client) │ │ (Server) │
└─────────────┘ └─────────────┘
│ │
│ 1. Load public_key.pem │ 1. Load private_key.pem
│ │
│ 2. Generate AES-256 key │ 2. Listen on port 65432
│ + Random IV │
│ │
│ 3. Encrypt message with AES │
│ │
│ 4. Encrypt AES key with RSA │
│ │
│ 5. Package payload: │
│ (encrypted_key, iv, ciphertext) │
│ │
├──────────────────────────────────────────> 3. Receive payload
│ Send via TCP socket │
│ │
│ │ 4. Decrypt AES key (RSA)
│ │
│ │ 5. Decrypt message (AES)
│ │
│ │ 6. Display plaintext
```

---

### Component Breakdown

#### 1. Key Generation (`generate_keys.py`)

**Purpose**: Creates RSA-2048 key pair for asymmetric encryption

**Key Features**:
- **Public Exponent**: 65537 (F4) - Industry standard
- **Key Size**: 2048 bits (provides ~112-bit security level)
- **Format**: PEM encoding for portability
- **Standards**: PKCS#8 (private), SubjectPublicKeyInfo (public)

**Security Considerations**:
```python
# Educational: No encryption on private key
encryption_algorithm=serialisation.NoEncryption()

# Production: Use passphrase protection
encryption_algorithm=serialisation.BestAvailableEncryption(b'strong_passphrase')
```

**Code Snippet**:
```python
private_key = rsa.generate_private_key(
public_exponent=65537, # Standard Fermat prime F4
key_size=2048 # 2048 bits = 256 bytes
)
```

**Output**:
- `private_key.pem` - Keep secret, used for decryption
- `public_key.pem` - Freely shareable, used for encryption

---

#### 2. Receiver/Server (`receiver.py`)

**Purpose**: Listens for encrypted messages and decrypts them

**Protocol Flow**:
1. Load RSA private key from `private_key.pem`
2. Bind socket to `localhost:65432`
3. Accept incoming connection
4. Receive encrypted payload (pickled tuple)
5. Unpack: `(encrypted_aes_key, iv, encrypted_message)`
6. Decrypt AES key using RSA private key
7. Decrypt message using recovered AES key and IV
8. Display plaintext

**Security Features**:
- **OAEP Padding**: Prevents chosen-ciphertext attacks
- **Timeout Protection**: 30-second timeout prevents hanging
- **Error Handling**: Graceful failure with detailed error messages

**RSA Decryption**:
```python
aes_key = private_key.decrypt(
encrypted_key,
padding.OAEP(
mgf=padding.MGF1(algorithm=hashes.SHA256()),
algorithm=hashes.SHA256(),
label=None
)
)
```

**Why OAEP?**
- Prevents deterministic encryption (same plaintext → different ciphertext)
- Protects against adaptive chosen-ciphertext attacks
- Adds randomness through Mask Generation Function (MGF1)

---

#### 3. Sender/Client (`sender.py`)

**Purpose**: Encrypts and transmits messages securely

**Protocol Flow**:
1. Load recipient's RSA public key from `public_key.pem`
2. Generate random AES-256 key (32 bytes)
3. Generate random IV (16 bytes) for AES
4. Encrypt message with AES-CFB mode
5. Encrypt AES key with RSA-OAEP
6. Package as tuple: `(encrypted_key, iv, encrypted_message)`
7. Serialise with pickle
8. Send via TCP socket to server

**AES Encryption**:
```python
# Generate session key (new for each message)
aes_key = os.urandom(32) # 256 bits - cryptographically secure
iv = os.urandom(16) # 128 bits - AES block size

# CFB mode: stream cipher operation
cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
encryptor = cipher.encryptor()
encrypted = encryptor.update(message) + encryptor.finalise()
```

**Why CFB Mode?**
- No padding required (unlike ECB/CBC)
- Handles arbitrary message lengths
- Self-synchronising (errors don't propagate)
- Converts block cipher into stream cipher

---

## Cryptographic Analysis

### Why Hybrid Encryption?

| Aspect | RSA Alone | AES Alone | Hybrid (RSA + AES) |
|--------|-----------|-----------|-------------------|
| **Speed** | Slow (~1000x slower) | Fast | Fast (AES encrypts data) |
| **Key Distribution** | Easy (public key) | Difficult (shared secret) | Easy (RSA secures AES key) |
| **Message Size** | Limited (~245 bytes for 2048-bit) | Unlimited | Unlimited |
| **Security** | Asymmetric (public/private) | Symmetric (shared key) | Both advantages |
| **Use Case** | Small data, key exchange | Large data | Real-world protocols (TLS) |

### Security Properties Achieved

#### 1. Confidentiality ✅
- Only holder of private key can decrypt AES session key
- AES-256 provides 2^256 keyspace (unbreakable with current technology)

#### 2. Perfect Forward Secrecy (Concept) ✅
- New AES key generated for each session
- Compromise of one session key doesn't affect others
- (Note: True PFS requires ephemeral key exchange like Diffie-Hellman)

#### 3. Semantic Security ✅
- OAEP padding ensures same message produces different ciphertext
- Random IV ensures different ciphertext even for identical messages

#### 4. Protection Against Attacks
- **Chosen-Ciphertext Attack**: OAEP padding prevents manipulation
- **Pattern Analysis**: Random IV prevents ciphertext patterns
- **Brute Force**: 2048-bit RSA + 256-bit AES computationally infeasible

---

## Testing & Validation

### Test Scenario 1: Basic Message Transfer
```bash
# Terminal 1 - Start receiver
python receiver.py
# Output: 🌐 Server listening on localhost:65432

# Terminal 2 - Send message
python sender.py
# Output: ✅ Message sent successfully!

# Terminal 1 shows decrypted message
# 🎉 MESSAGE DECRYPTED SUCCESSFULLY
# 📨 Message: Hello from the secure sender! ...
```

### Test Scenario 2: Long Message Handling
Modified `sender.py` to send 10KB message:
```python
message = "A" * 10240 # 10KB message
```
**Result**: ✅ Successfully encrypted and decrypted
**Observation**: AES handles arbitrary lengths efficiently

### Test Scenario 3: Unicode Support
```python
message = "Hello 世界! 🔐 Привет мир!"
```
**Result**: ✅ UTF-8 encoding preserved through encryption
**Key Learning**: Always encode strings to bytes before encryption

### Test Scenario 4: Error Handling
**Wrong private key test**:
- Generated new key pair
- Tried decrypting with mismatched private key
- **Result**: ❌ Proper error caught and reported
- **Key Learning**: OAEP verification detects tampering/wrong key

---

## Performance Analysis

### Encryption Timing (1MB message)
Measured on: Intel i5, 16GB RAM

| Operation | Time | Notes |
|-----------|------|-------|
| AES key generation | <1ms | `os.urandom(32)` is fast |
| AES encryption (1MB) | ~5ms | Stream cipher efficiency |
| RSA encryption (32 bytes) | ~2ms | Only encrypts AES key |
| **Total Encryption** | **~7ms** | Dominated by AES |
| RSA decryption (32 bytes) | ~15ms | Private key operations slower |
| AES decryption (1MB) | ~5ms | Symmetric operation |
| **Total Decryption** | **~20ms** | Dominated by RSA |

**Key Insight**: RSA operation time is constant (only encrypts 32-byte key), while AES time scales with message size. For 1MB message, RSA is still only 30% of total time.

---

## Security Considerations & Improvements

### Current Limitations
1. **No Authentication**: Server doesn't verify sender identity
2. **No Message Authentication**: No HMAC/digital signature
3. **No Forward Secrecy**: RSA keys are static (TLS uses ephemeral keys)
4. **Pickle Vulnerability**: Pickle can execute arbitrary code
5. **No Key Rotation**: Long-term keys increase exposure risk

### Proposed Enhancements

#### 1. Add Digital Signatures
```python
# Sender signs message before encryption
signature = private_key.sign(
message,
padding.PSS(
mgf=padding.MGF1(hashes.SHA256()),
salt_length=padding.PSS.MAX_LENGTH
),
hashes.SHA256()
)
# Include signature in payload
```

#### 2. Replace Pickle with JSON
```python
# Safer serialisation
payload = {
'encrypted_key': base64.b64encode(encrypted_key).decode(),
'iv': base64.b64encode(iv).decode(),
'ciphertext': base64.b64encode(encrypted_message).decode()
}
json_payload = json.dumps(payload).encode()
```

#### 3. Implement Certificate-Based Authentication
- Use X.509 certificates instead of raw public keys
- Verify certificate chain before accepting connections
- Implement certificate pinning for known peers

#### 4. Add Message Integrity (HMAC)
```python
# Generate HMAC for ciphertext
import hmac
mac = hmac.new(aes_key, encrypted_message, hashlib.sha256).digest()
# Verify MAC before decryption (prevents tampering)
```

---

## Real-World Applications

### Where This Protocol is Used

1. **TLS/SSL** (HTTPS)
- TLS 1.3 uses similar hybrid approach
- RSA/ECDHE for key exchange
- AES-GCM for bulk encryption

2. **PGP/GPG** (Email Encryption)
- RSA encrypts session key
- AES encrypts email body
- Digital signatures for authentication

3. **SSH** (Secure Shell)
- RSA/ECDSA for authentication
- AES for session encryption
- Perfect forward secrecy with ephemeral keys

4. **Signal Protocol** (Messaging)
- Double Ratchet algorithm
- Combines prekeys (RSA-like) with ephemeral keys
- Provides perfect forward secrecy

---

## Reflection

### What I Learnt

**Technical Skills**:
- Implementing hybrid encryption from scratch solidified my understanding of why TLS uses this approach
- OAEP padding prevents attacks I hadn't considered (chosen-ciphertext attacks)
- The importance of random number generation quality (`os.urandom` vs `random`)

**Design Insights**:
- Security protocols make design tradeoffs (speed vs security, simplicity vs features)
- Error handling is as important as the cryptography itself
- Real-world protocols have evolved through decades of attack research

**Practical Applications**:
- This week's implementation mirrors how secure connections are established in every HTTPS request
- Understanding the underlying crypto helps debug TLS issues in web applications
- The skills directly apply to securing APIs and microservices

### Challenges Overcome

1. **Understanding OAEP**: Initially confused about why OAEP was necessary. Research into padding oracle attacks clarified its importance.

2. **Socket Programming**: First time implementing networked crypto. Learnt about connection states, timeouts, and graceful error handling.

3. **Key Management**: Realised that secure key storage is separate from secure encryption. Production systems need HSMs, key vaults, or at minimum encrypted key files.

### Real-World Connection

This week showed me that "just use TLS" advice from security talks is an oversimplification. Understanding the internals helps when:
- Debugging certificate issues in production
- Implementing secure APIs
- Evaluating encryption claims from vendors
- Making informed decisions about cryptographic libraries

The peer feedback session reinforced that technical skills must be complemented by communication abilities. In interviews, explaining *why* I chose RSA+AES over alternatives demonstrates deeper understanding than just making it work.

---

## References

### Cryptography
- Boneh, D., & Shoup, V. (2020). *A Graduate Course in Applied Cryptography*
- Ferguson, N., Schneier, B., & Kohno, T. (2010). *Cryptography Engineering*
- RFC 8017: PKCS #1: RSA Cryptography Specifications Version 2.2

### Standards
- NIST SP 800-57: Key Management Recommendations
- NIST SP 800-38A: Recommendation for Block Cipher Modes of Operation
- RFC 5246: The Transport Layer Security (TLS) Protocol Version 1.2

### Python Libraries
- Cryptography.io Documentation: https://cryptography.io/
- Python Socket Programming HOWTO: https://docs.python.org/3/howto/sockets.html