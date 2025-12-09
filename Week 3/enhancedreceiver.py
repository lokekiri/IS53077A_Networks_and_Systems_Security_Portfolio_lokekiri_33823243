"""
Week 03: Enhanced Secure Message Receiver with HMAC Verification
Networks and Systems Security Portfolio

Enhancements over Week 02:
- HMAC verification before decryption (prevent oracle attacks)
- Comprehensive error handling and logging
- ACK/NACK response protocol
- Timing-safe MAC comparison
- Connection state management
"""

import socket
import pickle
import hmac
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class EnhancedSecureReceiver:
    """Enhanced receiver with HMAC verification and error handling."""
    
    def __init__(self, private_key_path="private_key.pem"):
        """
        Initialise receiver with private key.
        
        Args:
            private_key_path: Path to RSA private key
        """
        self.private_key = self._load_private_key(private_key_path)
        logger.info(f"✅ Receiver initialised with key: {private_key_path}")
    
    def _load_private_key(self, key_path):
        """
        Load RSA private key from file with error handling.
        
        Args:
            key_path: Path to private key file
            
        Returns:
            RSA private key object
            
        Raises:
            FileNotFoundError: If key file doesn't exist
            ValueError: If key file is corrupted
        """
        try:
            with open(key_path, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None
                )
            logger.info(f"🔐 Private key loaded ({private_key.key_size}-bit RSA)")
            return private_key
        except FileNotFoundError:
            logger.error(f"❌ Private key not found: {key_path}")
            raise
        except Exception as e:
            logger.error(f"❌ Error loading private key: {e}")
            raise ValueError(f"Invalid private key file: {e}")
    
    def verify_and_decrypt(self, encrypted_payload):
        """
        Verify HMAC and decrypt message.
        CRITICAL: HMAC verification MUST occur before decryption.
        
        Args:
            encrypted_payload: Tuple of (encrypted_key, iv, ciphertext, mac)
            
        Returns:
            bytes: Decrypted plaintext message
            
        Raises:
            ValueError: If HMAC verification fails
            Exception: If decryption fails
        """
        try:
            encrypted_key, iv, encrypted_message, received_mac = encrypted_payload
            
            logger.info("🔍 Verifying message integrity...")
            
            # Step 1: Decrypt AES key using RSA private key
            try:
                aes_key = self.private_key.decrypt(
                    encrypted_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                logger.debug("✅ AES key decrypted")
            except ValueError as e:
                logger.error("❌ RSA decryption failed: Wrong private key or corrupted data")
                raise ValueError("RSA decryption failed") from e
            
            # Step 2: Verify HMAC BEFORE decrypting message
            # This prevents oracle attacks where attackers learn info from decryption errors
            computed_mac = hmac.new(aes_key, encrypted_message, hashlib.sha256).digest()
            
            # Use constant-time comparison to prevent timing attacks
            if not hmac.compare_digest(received_mac, computed_mac):
                logger.error("❌ HMAC verification failed - message tampered or corrupted")
                raise ValueError("Message authentication failed")
            
            logger.info("✅ HMAC verified - message authentic")
            
            # Step 3: Decrypt message with AES (only after HMAC verification)
            logger.info("🔓 Decrypting message...")
            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(encrypted_message) + decryptor.finalize()
            
            logger.info(f"✅ Message decrypted ({len(plaintext)} bytes)")
            return plaintext
            
        except ValueError as e:
            # Authentication or decryption failure
            logger.error(f"❌ Verification/decryption error: {e}")
            raise
        except Exception as e:
            logger.error(f"❌ Unexpected error during decryption: {e}")
            raise
    
    def start_server(self, host='localhost', port=65432, timeout=60):
        """
        Start server and wait for encrypted messages.
        
        Args:
            host: Hostname to bind to
            port: Port to listen on
            timeout: Connection timeout in seconds
        """
        logger.info("🚀 Starting secure message server...")
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            # Allow address reuse
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            try:
                server_socket.bind((host, port))
                server_socket.listen(1)
                logger.info(f"🌐 Server listening on {host}:{port}")
                logger.info("⏳ Waiting for secure connection...")
                
            except OSError as e:
                logger.error(f"❌ Failed to bind to {host}:{port}: {e}")
                return
            
            # Accept connection
            try:
                conn, addr = server_socket.accept()
                logger.info(f"✅ Connection established with {addr[0]}:{addr[1]}")
            except KeyboardInterrupt:
                logger.info("\n⚠️  Server interrupted by user")
                return
            
            with conn:
                conn.settimeout(timeout)
                
                # Receive data
                logger.info("📥 Receiving encrypted payload...")
                data = b""
                
                try:
                    while True:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                        logger.debug(f"Received {len(chunk)} bytes (total: {len(data)})")
                        
                except socket.timeout:
                    logger.error("❌ Receive timeout")
                    conn.sendall(b"NACK")
                    return
                except Exception as e:
                    logger.error(f"❌ Receive error: {e}")
                    conn.sendall(b"NACK")
                    return
                
                if not data:
                    logger.error("❌ No data received")
                    conn.sendall(b"NACK")
                    return
                
                logger.info(f"✅ Received {len(data)} bytes")
                
                # Deserialise payload
                logger.info("📦 Unpacking encrypted payload...")
                try:
                    encrypted_payload = pickle.loads(data)
                    
                    # Validate payload structure
                    if not isinstance(encrypted_payload, tuple) or len(encrypted_payload) != 4:
                        logger.error("❌ Invalid payload structure")
                        conn.sendall(b"NACK")
                        return
                    
                    logger.info("✅ Payload unpacked successfully")
                    
                except pickle.UnpicklingError:
                    logger.error("❌ Corrupted or tampered payload")
                    conn.sendall(b"NACK")
                    return
                except Exception as e:
                    logger.error(f"❌ Deserialisation error: {e}")
                    conn.sendall(b"NACK")
                    return
                
                # Verify and decrypt
                try:
                    plaintext = self.verify_and_decrypt(encrypted_payload)
                    
                    # Display result
                    print("\n" + "="*70)
                    print("🎉 MESSAGE RECEIVED AND VERIFIED")
                    print("="*70)
                    print(plaintext.decode('utf-8'))
                    print("="*70 + "\n")
                    
                    # Send acknowledgement
                    logger.info("📤 Sending acknowledgement...")
                    conn.sendall(b"ACK")
                    logger.info("✅ ACK sent")
                    
                except ValueError as e:
                    # Authentication failed
                    logger.error(f"❌ Message verification failed: {e}")
                    print("\n" + "="*70)
                    print("⚠️  MESSAGE REJECTED")
                    print("="*70)
                    print("Reason: HMAC verification failed")
                    print("Possible causes:")
                    print("  • Message was tampered with during transmission")
                    print("  • Wrong decryption key used")
                    print("  • Data corruption")
                    print("="*70 + "\n")
                    
                    conn.sendall(b"NACK")
                    return
                    
                except Exception as e:
                    logger.error(f"❌ Decryption error: {e}")
                    conn.sendall(b"NACK")
                    return


def main():
    """Main execution function."""
    print("""
    ╔════════════════════════════════════════════════════════╗
    ║     ENHANCED SECURE MESSAGE RECEIVER                   ║
    ║     Week 03: HMAC Verification & Error Handling        ║
    ╚════════════════════════════════════════════════════════╝
    """)
    
    print("🔐 Security Features:")
    print("   • HMAC-SHA256 message authentication")
    print("   • Timing-safe MAC comparison")
    print("   • Verify-before-decrypt (prevents oracle attacks)")
    print("   • Comprehensive error handling")
    print("   • ACK/NACK confirmation protocol\n")
    
    try:
        # Initialise receiver
        receiver = EnhancedSecureReceiver()
        
        # Start server
        receiver.start_server()
        
    except FileNotFoundError:
        print("\n❌ Error: private_key.pem not found")
        print("   Run generate_keys.py first to create key pair")
    except KeyboardInterrupt:
        print("\n\n⚠️  Server stopped by user")
    except Exception as e:
        print(f"\n❌ Server error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()