"""
Week 04: Authenticated Secure Sender with Digital Signatures
Networks and Systems Security Portfolio

New Features:
- Digital signatures for sender authentication (RSA-PSS)
- JSON serialisation (eliminates pickle RCE vulnerability)
- Timestamp and sequence numbers (replay protection)
- Base64 encoding for safe transmission
- Version field for protocol evolution

Security Properties:
- Confidentiality: AES-256-CFB
- Integrity: HMAC-SHA256
- Authentication: RSA-PSS digital signatures
- Non-repudiation: Signature proves sender identity
"""

import socket
import os
import hmac
import hashlib
import json
import base64
from datetime import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AuthenticatedSecureSender:
    """Sender with digital signature authentication."""
    
    def __init__(self, sender_private_key_path="alice_private_key.pem",
                 recipient_public_key_path="bob_public_key.pem",
                 sender_id="alice@example.com"):
        """
        Initialise authenticated sender.
        
        Args:
            sender_private_key_path: Sender's private key for signing
            recipient_public_key_path: Recipient's public key for encryption
            sender_id: Sender identifier for authentication
        """
        self.sender_private_key = self._load_private_key(sender_private_key_path)
        self.recipient_public_key = self._load_public_key(recipient_public_key_path)
        self.sender_id = sender_id
        self.sequence_number = 0
        
        logger.info(f"✅ Sender initialised: {sender_id}")
    
    def _load_private_key(self, key_path):
        """Load sender's private key for signing."""
        try:
            with open(key_path, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None
                )
            logger.info(f"🔐 Private signing key loaded")
            return private_key
        except FileNotFoundError:
            logger.error(f"❌ Private key not found: {key_path}")
            raise
    
    def _load_public_key(self, key_path):
        """Load recipient's public key for encryption."""
        try:
            with open(key_path, "rb") as f:
                public_key = serialization.load_pem_public_key(f.read())
            logger.info(f"🔐 Recipient public key loaded")
            return public_key
        except FileNotFoundError:
            logger.error(f"❌ Public key not found: {key_path}")
            raise
    
    def sign_message(self, message):
        """
        Create digital signature for message authentication.
        
        Uses RSA-PSS (Probabilistic Signature Scheme):
        - Provides security proof against existential forgery
        - Includes randomness (salt) making signatures non-deterministic
        - More secure than older PKCS#1 v1.5 padding
        
        Args:
            message: Message to sign (bytes)
            
        Returns:
            bytes: Digital signature
        """
        logger.info("✍️  Generating digital signature...")
        
        signature = self.sender_private_key.sign(
            message,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        logger.info(f"✅ Signature generated ({len(signature)} bytes)")
        return signature
    
    def encrypt_and_authenticate(self, message):
        """
        Encrypt message with authentication and integrity.
        
        Protocol: Sign-then-encrypt
        1. Sign plaintext message (authentication)
        2. Encrypt message with AES (confidentiality)
        3. Generate HMAC of ciphertext (integrity)
        4. Encrypt AES key with RSA (key exchange)
        
        Args:
            message: Plaintext message (string or bytes)
            
        Returns:
            dict: Complete authenticated and encrypted payload
        """
        # Ensure message is bytes
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        logger.info(f"📝 Processing message ({len(message)} bytes)")
        
        # Step 1: Sign the plaintext message
        signature = self.sign_message(message)
        
        # Step 2: Generate encryption keys
        aes_key = os.urandom(32)  # AES-256
        iv = os.urandom(16)
        logger.debug("🔐 Generated AES-256 key and IV")
        
        # Step 3: Encrypt message with AES
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(message) + encryptor.finalize()
        logger.debug(f"🔐 Message encrypted")
        
        # Step 4: Generate HMAC for integrity
        mac = hmac.new(aes_key, encrypted_message, hashlib.sha256).digest()
        logger.debug("✅ HMAC generated")
        
        # Step 5: Encrypt AES key with recipient's public key
        encrypted_key = self.recipient_public_key.encrypt(
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        logger.debug(f"🔐 AES key encrypted with RSA")
        
        # Step 6: Increment sequence number for replay protection
        self.sequence_number += 1
        
        # Step 7: Build JSON payload (safe serialisation)
        payload = {
            'version': '2.0',
            'sender_id': self.sender_id,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'sequence': self.sequence_number,
            'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'ciphertext': base64.b64encode(encrypted_message).decode('utf-8'),
            'mac': base64.b64encode(mac).decode('utf-8'),
            'signature': base64.b64encode(signature).decode('utf-8')
        }
        
        logger.info(f"📦 Payload constructed (JSON, {len(json.dumps(payload))} bytes)")
        return payload
    
    def send_message(self, message, host='localhost', port=65433, timeout=30):
        """
        Send authenticated encrypted message.
        
        Args:
            message: Plaintext message
            host: Server hostname
            port: Server port
            timeout: Socket timeout
            
        Returns:
            bool: True if successful
        """
        try:
            # Encrypt and authenticate
            payload = self.encrypt_and_authenticate(message)
            
            # Serialise to JSON
            json_payload = json.dumps(payload).encode('utf-8')
            
            logger.info(f"🌐 Connecting to {host}:{port}...")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                
                try:
                    sock.connect((host, port))
                    logger.info("✅ Connected")
                except ConnectionRefusedError:
                    logger.error("❌ Connection refused. Is receiver running?")
                    return False
                
                # Send payload
                logger.info("📤 Sending authenticated message...")
                sock.sendall(json_payload)
                sock.shutdown(socket.SHUT_WR)
                
                # Wait for ACK
                logger.info("⏳ Waiting for acknowledgement...")
                ack = sock.recv(4)
                
                if ack == b"ACK":
                    logger.info("✅ Message acknowledged")
                    return True
                elif ack == b"NACK":
                    logger.error("❌ Message rejected by receiver")
                    return False
                else:
                    logger.warning(f"⚠️  Unexpected response: {ack}")
                    return False
                    
        except Exception as e:
            logger.error(f"❌ Send failed: {e}")
            import traceback
            traceback.print_exc()
            return False


def main():
    """Main execution function."""
    print("""
    ╔════════════════════════════════════════════════════════╗
    ║     AUTHENTICATED SECURE SENDER                        ║
    ║     Week 04: Digital Signatures & JSON Serialisation   ║
    ╚════════════════════════════════════════════════════════╝
    """)
    
    print("🔐 Security Enhancements:")
    print("   • RSA-PSS digital signatures (authentication)")
    print("   • JSON serialisation (no RCE vulnerability)")
    print("   • Timestamp + sequence numbers (replay protection)")
    print("   • Sign-then-encrypt protocol")
    print("   • Base64 encoding for safe transport\n")
    
    # Sample confidential message
    message = """
    CLASSIFIED - INTERNAL USE ONLY
    ================================
    
    From: alice@example.com
    To: bob@example.com
    Subject: Security Protocol Update
    
    This message demonstrates enhanced security protocol:
    
    1. Digital Signature: Proves sender authenticity
    2. Non-repudiation: Sender cannot deny sending
    3. Integrity: HMAC detects tampering
    4. Confidentiality: AES-256 encryption
    5. Replay Protection: Timestamp + sequence validation
    
    Authentication Status: VERIFIED
    Encryption Status: ACTIVE
    Protocol Version: 2.0
    
    End of secure transmission.
    """
    
    try:
        # Note: This assumes you have alice_private_key.pem and bob_public_key.pem
        # For testing, you can use the same keys from Week 02-03
        # Just rename: private_key.pem -> alice_private_key.pem
        #             public_key.pem -> bob_public_key.pem
        
        sender = AuthenticatedSecureSender(
            sender_private_key_path="private_key.pem",  # Use existing key for demo
            recipient_public_key_path="public_key.pem",
            sender_id="alice@example.com"
        )
        
        print("="*60)
        print("📨 SENDING AUTHENTICATED MESSAGE")
        print("="*60 + "\n")
        
        success = sender.send_message(message.strip())
        
        print("\n" + "="*60)
        if success:
            print("🎉 AUTHENTICATED MESSAGE SENT")
            print("="*60)
            print("\n✅ Protocol features applied:")
            print("   • Authentication: RSA-PSS signature")
            print("   • Confidentiality: AES-256-CFB")
            print("   • Integrity: HMAC-SHA256")
            print("   • Replay Protection: Timestamp + sequence")
            print("   • Safe Serialisation: JSON (no code execution)")
        else:
            print("❌ MESSAGE DELIVERY FAILED")
            print("="*60)
        
    except FileNotFoundError as e:
        print(f"\n❌ Key file not found: {e}")
        print("   Run generate_keys.py to create keys")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()