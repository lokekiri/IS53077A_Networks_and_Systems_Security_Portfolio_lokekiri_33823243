"""
Week 04: Authenticated Secure Receiver with Signature Verification
Networks and Systems Security Portfolio

New Features:
- Digital signature verification (sender authentication)
- JSON deserialisation (safe, no RCE)
- Timestamp validation (replay protection)
- Sequence number checking (order verification)
- Comprehensive security logging
"""

import socket
import json
import base64
import hmac
import hashlib
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AuthenticatedSecureReceiver:
    """Receiver with signature verification and replay protection."""
    
    def __init__(self, receiver_private_key_path="bob_private_key.pem",
                 sender_public_key_path="alice_public_key.pem"):
        """
        Initialise authenticated receiver.
        
        Args:
            receiver_private_key_path: Receiver's private key for decryption
            sender_public_key_path: Sender's public key for signature verification
        """
        self.receiver_private_key = self._load_private_key(receiver_private_key_path)
        self.sender_public_key = self._load_public_key(sender_public_key_path)
        self.last_sequence = {}  # Track sequence numbers per sender
        
        logger.info("✅ Receiver initialised")
    
    def _load_private_key(self, key_path):
        """Load receiver's private key."""
        try:
            with open(key_path, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None
                )
            logger.info("🔐 Private decryption key loaded")
            return private_key
        except FileNotFoundError:
            logger.error(f"❌ Private key not found: {key_path}")
            raise
    
    def _load_public_key(self, key_path):
        """Load sender's public key for verification."""
        try:
            with open(key_path, "rb") as f:
                public_key = serialization.load_pem_public_key(f.read())
            logger.info("🔐 Sender's public key loaded")
            return public_key
        except FileNotFoundError:
            logger.error(f"❌ Public key not found: {key_path}")
            raise
    
    def verify_signature(self, message, signature):
        """
        Verify digital signature to authenticate sender.
        
        Args:
            message: Original plaintext message (bytes)
            signature: Digital signature to verify (bytes)
            
        Returns:
            bool: True if signature valid
            
        Raises:
            InvalidSignature: If signature verification fails
        """
        logger.info("🔍 Verifying digital signature...")
        
        try:
            self.sender_public_key.verify(
                signature,
                message,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            logger.info("✅ Signature verified - sender authenticated")
            return True
            
        except InvalidSignature:
            logger.error("❌ Invalid signature - possible impersonation attack")
            raise
    
    def validate_timestamp(self, timestamp_str, max_age_seconds=300):
        """
        Validate message timestamp for replay protection.
        
        Args:
            timestamp_str: ISO format timestamp
            max_age_seconds: Maximum acceptable message age (default 5 minutes)
            
        Returns:
            bool: True if timestamp valid
        """
        try:
            message_time = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            current_time = datetime.utcnow()
            
            # Calculate time difference
            time_diff = abs((current_time - message_time).total_seconds())
            
            if time_diff > max_age_seconds:
                logger.error(f"❌ Message too old ({time_diff:.0f} seconds)")
                return False
            
            logger.info(f"✅ Timestamp valid (age: {time_diff:.0f} seconds)")
            return True
            
        except ValueError as e:
            logger.error(f"❌ Invalid timestamp format: {e}")
            return False
    
    def validate_sequence(self, sender_id, sequence):
        """
        Validate sequence number for replay/reorder protection.
        
        Args:
            sender_id: Sender identifier
            sequence: Message sequence number
            
        Returns:
            bool: True if sequence valid
        """
        last_seq = self.last_sequence.get(sender_id, 0)
        
        if sequence <= last_seq:
            logger.error(f"❌ Invalid sequence: {sequence} (expected > {last_seq})")
            return False
        
        self.last_sequence[sender_id] = sequence
        logger.info(f"✅ Sequence valid: {sequence}")
        return True
    
    def decrypt_and_verify(self, payload):
        """
        Complete verification and decryption workflow.
        
        Verification order:
        1. Validate timestamp (replay protection)
        2. Validate sequence (order protection)
        3. Decrypt AES key with RSA
        4. Verify HMAC (integrity)
        5. Decrypt message
        6. Verify signature (authentication)
        
        Args:
            payload: JSON payload with encrypted message
            
        Returns:
            str: Decrypted and verified message
        """
        try:
            # Step 1: Validate timestamp
            if not self.validate_timestamp(payload['timestamp']):
                raise ValueError("Timestamp validation failed")
            
            # Step 2: Validate sequence number
            if not self.validate_sequence(payload['sender_id'], payload['sequence']):
                raise ValueError("Sequence validation failed")
            
            # Decode Base64 fields
            encrypted_key = base64.b64decode(payload['encrypted_key'])
            iv = base64.b64decode(payload['iv'])
            ciphertext = base64.b64decode(payload['ciphertext'])
            received_mac = base64.b64decode(payload['mac'])
            signature = base64.b64decode(payload['signature'])
            
            logger.info("📦 Payload decoded")
            
            # Step 3: Decrypt AES key with RSA
            aes_key = self.receiver_private_key.decrypt(
                encrypted_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            logger.info("🔓 AES key decrypted")
            
            # Step 4: Verify HMAC (must occur before decryption)
            computed_mac = hmac.new(aes_key, ciphertext, hashlib.sha256).digest()
            if not hmac.compare_digest(received_mac, computed_mac):
                raise ValueError("HMAC verification failed")
            logger.info("✅ HMAC verified")
            
            # Step 5: Decrypt message
            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            logger.info("🔓 Message decrypted")
            
            # Step 6: Verify signature on plaintext
            self.verify_signature(plaintext, signature)
            
            return plaintext.decode('utf-8')
            
        except InvalidSignature:
            raise ValueError("Signature verification failed - sender not authenticated")
        except Exception as e:
            logger.error(f"❌ Verification error: {e}")
            raise
    
    def start_server(self, host='localhost', port=65433, timeout=60):
        """
        Start server to receive authenticated messages.
        
        Args:
            host: Hostname to bind
            port: Port to listen on
            timeout: Connection timeout
        """
        logger.info("🚀 Starting authenticated message server...")
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            try:
                server_socket.bind((host, port))
                server_socket.listen(1)
                logger.info(f"🌐 Server listening on {host}:{port}")
                logger.info("⏳ Waiting for authenticated connection...")
                
            except OSError as e:
                logger.error(f"❌ Bind failed: {e}")
                return
            
            # Accept connection
            try:
                conn, addr = server_socket.accept()
                logger.info(f"✅ Connection from {addr[0]}:{addr[1]}")
            except KeyboardInterrupt:
                logger.info("\n⚠️  Server interrupted")
                return
            
            with conn:
                conn.settimeout(timeout)
                
                # Receive JSON payload
                logger.info("📥 Receiving payload...")
                data = b""
                
                try:
                    while True:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                except socket.timeout:
                    logger.error("❌ Receive timeout")
                    conn.sendall(b"NACK")
                    return
                
                if not data:
                    logger.error("❌ No data received")
                    conn.sendall(b"NACK")
                    return
                
                logger.info(f"✅ Received {len(data)} bytes")
                
                # Parse JSON
                try:
                    payload = json.loads(data.decode('utf-8'))
                    logger.info(f"📦 JSON parsed (protocol v{payload.get('version', 'unknown')})")
                    
                    # Validate required fields
                    required_fields = ['encrypted_key', 'iv', 'ciphertext', 'mac', 
                                     'signature', 'timestamp', 'sequence', 'sender_id']
                    
                    for field in required_fields:
                        if field not in payload:
                            raise ValueError(f"Missing required field: {field}")
                    
                except json.JSONDecodeError as e:
                    logger.error(f"❌ Invalid JSON: {e}")
                    conn.sendall(b"NACK")
                    return
                except ValueError as e:
                    logger.error(f"❌ Invalid payload: {e}")
                    conn.sendall(b"NACK")
                    return
                
                # Decrypt and verify
                try:
                    message = self.decrypt_and_verify(payload)
                    
                    # Display result
                    print("\n" + "="*70)
                    print("🎉 AUTHENTICATED MESSAGE RECEIVED")
                    print("="*70)
                    print(f"From: {payload['sender_id']}")
                    print(f"Timestamp: {payload['timestamp']}")
                    print(f"Sequence: {payload['sequence']}")
                    print(f"Protocol: v{payload['version']}")
                    print("="*70)
                    print(message)
                    print("="*70)
                    print("\n✅ Security Checks Passed:")
                    print("   • Signature verified (sender authenticated)")
                    print("   • HMAC verified (integrity confirmed)")
                    print("   • Timestamp validated (not replayed)")
                    print("   • Sequence validated (correct order)")
                    print("="*70 + "\n")
                    
                    # Send ACK
                    conn.sendall(b"ACK")
                    logger.info("✅ ACK sent")
                    
                except ValueError as e:
                    logger.error(f"❌ Verification failed: {e}")
                    print("\n" + "="*70)
                    print("⚠️  MESSAGE REJECTED")
                    print("="*70)
                    print(f"Reason: {e}")
                    print("="*70 + "\n")
                    conn.sendall(b"NACK")


def main():
    """Main execution function."""
    print("""
    ╔════════════════════════════════════════════════════════╗
    ║     AUTHENTICATED SECURE RECEIVER                      ║
    ║     Week 04: Signature Verification & Replay Protection║
    ╚════════════════════════════════════════════════════════╝
    """)
    
    print("🔐 Security Features:")
    print("   • Digital signature verification (RSA-PSS)")
    print("   • Timestamp validation (replay protection)")
    print("   • Sequence number validation (order protection)")
    print("   • HMAC verification (integrity)")
    print("   • JSON deserialisation (safe, no RCE)\n")
    
    try:
        # Note: For testing, use the same keys from Week 02-03
        receiver = AuthenticatedSecureReceiver(
            receiver_private_key_path="private_key.pem",
            sender_public_key_path="public_key.pem"
        )
        
        receiver.start_server()
        
    except FileNotFoundError as e:
        print(f"\n❌ Key file not found: {e}")
        print("   Run generate_keys.py to create keys")
    except KeyboardInterrupt:
        print("\n\n⚠️  Server stopped by user")
    except Exception as e:
        print(f"\n❌ Server error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
