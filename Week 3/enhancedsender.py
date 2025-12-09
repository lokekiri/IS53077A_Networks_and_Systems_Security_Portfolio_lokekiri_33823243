"""
Week 03: Enhanced Secure Message Sender with HMAC
Networks and Systems Security Portfolio

Enhancements over Week 02:
- HMAC-SHA256 for message authentication
- Comprehensive error handling
- Chunked data transfer for reliability
- ACK/NACK confirmation protocol
- Enhanced logging

Security Features:
- Confidentiality: AES-256-CFB
- Key Exchange: RSA-2048 with OAEP
- Integrity: HMAC-SHA256
- Reliability: Chunked transfer with confirmation
"""

import socket
import os
import hmac
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import pickle
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class EnhancedSecureSender:
    """Enhanced sender with HMAC authentication and error handling."""
    
    def __init__(self, public_key_path="public_key.pem"):
        """
        Initialise sender with recipient's public key.
        
        Args:
            public_key_path: Path to recipient's public key
        """
        self.public_key = self._load_public_key(public_key_path)
        logger.info(f"✅ Sender initialised with key: {public_key_path}")
    
    def _load_public_key(self, key_path):
        """
        Load RSA public key from file with error handling.
        
        Args:
            key_path: Path to public key file
            
        Returns:
            RSA public key object
            
        Raises:
            FileNotFoundError: If key file doesn't exist
            ValueError: If key file is corrupted
        """
        try:
            with open(key_path, "rb") as f:
                public_key = serialization.load_pem_public_key(f.read())
            logger.info(f"🔐 Public key loaded ({public_key.key_size}-bit RSA)")
            return public_key
        except FileNotFoundError:
            logger.error(f"❌ Public key not found: {key_path}")
            raise
        except Exception as e:
            logger.error(f"❌ Error loading public key: {e}")
            raise ValueError(f"Invalid public key file: {e}")
    
    def encrypt_with_hmac(self, message):
        """
        Encrypt message and generate HMAC for integrity verification.
        
        Args:
            message: Plaintext message (bytes or string)
            
        Returns:
            tuple: (encrypted_key, iv, encrypted_message, mac)
        """
        # Ensure message is bytes
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        logger.info(f"📝 Encrypting message ({len(message)} bytes)")
        
        # Step 1: Generate random AES key and IV
        aes_key = os.urandom(32)  # AES-256
        iv = os.urandom(16)
        logger.debug("🔐 Generated AES-256 session key and IV")
        
        # Step 2: Encrypt message with AES
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(message) + encryptor.finalize()
        logger.debug(f"🔐 Message encrypted ({len(encrypted_message)} bytes)")
        
        # Step 3: Generate HMAC for integrity
        mac = hmac.new(aes_key, encrypted_message, hashlib.sha256).digest()
        logger.debug("✅ HMAC generated (32 bytes)")
        
        # Step 4: Encrypt AES key with RSA
        try:
            encrypted_key = self.public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            logger.debug(f"🔐 AES key encrypted with RSA ({len(encrypted_key)} bytes)")
        except Exception as e:
            logger.error(f"❌ RSA encryption failed: {e}")
            raise
        
        return encrypted_key, iv, encrypted_message, mac
    
    def send_message(self, message, host='localhost', port=65432, timeout=30):
        """
        Encrypt and send message with confirmation protocol.
        
        Args:
            message: Plaintext message to send
            host: Server hostname
            port: Server port
            timeout: Socket timeout in seconds
            
        Returns:
            bool: True if message sent and acknowledged
        """
        try:
            # Encrypt message
            encrypted_key, iv, encrypted_message, mac = self.encrypt_with_hmac(message)
            
            # Package payload
            payload = (encrypted_key, iv, encrypted_message, mac)
            serialised_payload = pickle.dumps(payload)
            
            logger.info(f"📦 Payload packaged ({len(serialised_payload)} bytes)")
            logger.info(f"   - Encrypted key: {len(encrypted_key)} bytes")
            logger.info(f"   - IV: {len(iv)} bytes")
            logger.info(f"   - Ciphertext: {len(encrypted_message)} bytes")
            logger.info(f"   - HMAC: {len(mac)} bytes")
            
            # Connect to server
            logger.info(f"🌐 Connecting to {host}:{port}...")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                
                try:
                    sock.connect((host, port))
                    logger.info("✅ Connected to server")
                except ConnectionRefusedError:
                    logger.error("❌ Connection refused. Is the receiver running?")
                    return False
                except socket.timeout:
                    logger.error("❌ Connection timeout")
                    return False
                
                # Send data in chunks for reliability
                total_sent = 0
                chunk_size = 4096
                
                logger.info("📤 Sending encrypted payload...")
                while total_sent < len(serialised_payload):
                    chunk_end = min(total_sent + chunk_size, len(serialised_payload))
                    chunk = serialised_payload[total_sent:chunk_end]
                    
                    try:
                        sent = sock.send(chunk)
                        if sent == 0:
                            logger.error("❌ Socket connection broken")
                            return False
                        total_sent += sent
                        
                        # Progress indicator
                        progress = (total_sent / len(serialised_payload)) * 100
                        logger.debug(f"Progress: {progress:.1f}% ({total_sent}/{len(serialised_payload)} bytes)")
                    
                    except socket.timeout:
                        logger.error("❌ Send timeout")
                        return False
                
                logger.info(f"✅ Payload sent ({total_sent} bytes)")
                
                # Shutdown write side to signal completion
                sock.shutdown(socket.SHUT_WR)
                
                # Wait for acknowledgement
                logger.info("⏳ Waiting for acknowledgement...")
                try:
                    ack = sock.recv(4)
                    if ack == b"ACK":
                        logger.info("✅ Message acknowledged by receiver")
                        return True
                    elif ack == b"NACK":
                        logger.error("❌ Receiver rejected message (verification failed)")
                        return False
                    else:
                        logger.warning(f"⚠️  Unexpected response: {ack}")
                        return False
                except socket.timeout:
                    logger.warning("⚠️  No acknowledgement received (timeout)")
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
    ║     ENHANCED SECURE MESSAGE SENDER                     ║
    ║     Week 03: HMAC Authentication & Error Handling      ║
    ╚════════════════════════════════════════════════════════╝
    """)
    
    # Example message
    message = """
    CONFIDENTIAL SECURITY REPORT
    ============================
    
    Subject: Quarterly Security Assessment
    Date: 2024-12-09
    Classification: INTERNAL USE ONLY
    
    Summary:
    This encrypted message demonstrates enhanced security features:
    - AES-256-CFB encryption for confidentiality
    - HMAC-SHA256 for integrity verification
    - RSA-2048 for secure key exchange
    - Chunked transmission for reliability
    - ACK/NACK confirmation protocol
    
    All security controls functioning as expected.
    
    End of transmission.
    """
    
    try:
        # Initialise sender
        sender = EnhancedSecureSender()
        
        # Send message
        print("\n" + "="*60)
        print("📨 SENDING SECURE MESSAGE")
        print("="*60)
        
        success = sender.send_message(message.strip())
        
        print("\n" + "="*60)
        if success:
            print("🎉 MESSAGE SENT SUCCESSFULLY")
            print("="*60)
            print("\n✅ Security features applied:")
            print("   • Confidentiality: AES-256-CFB encryption")
            print("   • Integrity: HMAC-SHA256 authentication")
            print("   • Authentication: RSA-2048 key exchange")
            print("   • Reliability: Chunked transfer with ACK")
        else:
            print("❌ MESSAGE DELIVERY FAILED")
            print("="*60)
            print("\n⚠️  Check that receiver is running and try again")
        
    except FileNotFoundError:
        print("\n❌ Error: public_key.pem not found")
        print("   Run generate_keys.py first to create key pair")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()