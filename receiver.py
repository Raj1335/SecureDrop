"""
SecureDrop Receiver - SPAKE2 + X25519 + ChaCha20-Poly1305
Protocol Version 1.0
SECURITY FIXES:
- Path traversal protection
- Rate limiting for brute-force prevention
- DoS protection via payload size validation
"""

import socket
import os
import struct
import hashlib
from pathlib import Path
import time
import sys

# Import protocol modules
sys.path.append(os.path.dirname(__file__))
from core.protocol import (
    ProtocolMessage, MessageType, RoleID, ErrorCode,
    generate_nonce, check_version_compatible,
    PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
    MAX_PAKE_PAYLOAD, MAX_FILENAME_LENGTH, MAX_CHUNK_SIZE
)
from core.pake import SPAKE2Exchange, generate_6digit_code
from core.crypto import (
    EphemeralDH, SessionKeyDerivation, AEADCipher,
    create_associated_data
)
from core.sas import SASGenerator

class SecureReceiver:
    def __init__(self, port=5000, save_dir="received_files"):
        self.port = port
        self.save_dir = Path(save_dir)
        self.save_dir.mkdir(exist_ok=True)
        
        # Generate pairing code
        self.pairing_code = generate_6digit_code()
        print(f"[*] Generated pairing code: {self.pairing_code}")
        
        # Protocol state
        self.client_nonce = None
        self.server_nonce = None
        self.session_keys = None
        self.aead_cipher = None
        self.sas = None
        
        # Rate limiting - NOW ACTUALLY USED
        self.failed_attempts = {}  # IP -> (count, last_attempt_time)
        self.max_attempts = 3
        self.ban_duration = 300  # 5 minutes
    
    def get_local_ip(self):
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    
    def is_ip_banned(self, ip):
        """Check if IP is currently banned due to failed attempts"""
        if ip not in self.failed_attempts:
            return False
        
        count, last_attempt = self.failed_attempts[ip]
        
        # Check if ban has expired
        if time.time() - last_attempt > self.ban_duration:
            del self.failed_attempts[ip]
            return False
        
        return count >= self.max_attempts
    
    def record_failed_attempt(self, ip):
        """Record a failed handshake attempt for rate limiting"""
        current_time = time.time()
        
        if ip in self.failed_attempts:
            count, last_attempt = self.failed_attempts[ip]
            # Reset count if last attempt was more than ban_duration ago
            if current_time - last_attempt > self.ban_duration:
                count = 0
            self.failed_attempts[ip] = (count + 1, current_time)
        else:
            self.failed_attempts[ip] = (1, current_time)
        
        count = self.failed_attempts[ip][0]
        if count >= self.max_attempts:
            remaining_ban = self.ban_duration - (current_time - self.failed_attempts[ip][1])
            print(f"⚠️  IP {ip} banned for {remaining_ban:.0f} more seconds")
    
    def sanitize_filename(self, filename):
        """
        SECURITY FIX: Sanitize filename to prevent path traversal attacks.
        
        Args:
            filename: Untrusted filename from network
            
        Returns:
            Safe filename (just the base name)
            
        Raises:
            ValueError if filename is invalid
        """
        if not filename or len(filename) > MAX_FILENAME_LENGTH:
            raise ValueError(f"Invalid filename length: {len(filename)}")
        
        # Extract just the base filename (removes any path components)
        safe_name = os.path.basename(filename)
        
        # Additional validation: ensure no path separators remain
        if '/' in safe_name or '\\' in safe_name or '..' in safe_name:
            raise ValueError(f"Invalid filename contains path separators: {filename}")
        
        # Ensure filename is not empty after sanitization
        if not safe_name or safe_name in ('.', '..'):
            raise ValueError(f"Invalid filename after sanitization: {filename}")
        
        return safe_name
    
    def recv_exact(self, sock, n):
        """Receive exactly n bytes from socket"""
        data = b''
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("Connection closed prematurely")
            data += chunk
        return data
    
    def handshake(self, conn, client_ip):
        """
        Perform full cryptographic handshake with rate limiting.
        Returns True if successful, False otherwise.
        
        Args:
            conn: Socket connection
            client_ip: Client IP address for rate limiting
        """
        try:
            # SECURITY FIX: Check if IP is banned before proceeding
            if self.is_ip_banned(client_ip):
                print(f"✗ Connection rejected - IP {client_ip} is temporarily banned")
                error_msg = ProtocolMessage.pack_error(
                    PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                    ErrorCode.RATE_LIMIT
                )
                conn.send(error_msg)
                return False
            
            # Step 1: Receive HELLO
            print("[1/7] Receiving HELLO...")
            hello_data = self.recv_exact(conn, 19)
            major, minor, self.client_nonce = ProtocolMessage.unpack_hello(hello_data)
            
            if not check_version_compatible(major, minor):
                print(f"✗ Incompatible version: {major}.{minor}")
                error_msg = ProtocolMessage.pack_error(
                    PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                    ErrorCode.PROTOCOL_MISMATCH
                )
                conn.send(error_msg)
                self.record_failed_attempt(client_ip)
                return False
            
            print(f"✓ Version compatible: {major}.{minor}")
            
            # Step 2: Send HELLO_ACK
            print("[2/7] Sending HELLO_ACK...")
            self.server_nonce = generate_nonce()
            hello_ack = ProtocolMessage.pack_hello_ack(
                PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                self.server_nonce
            )
            conn.send(hello_ack)
            
            # Step 3: SPAKE2 Exchange
            print("[3/7] Performing SPAKE2 PAKE...")
            spake = SPAKE2Exchange(self.pairing_code, side="B")

            # Receive PAKE_INIT - SECURITY FIX: Validate payload size BEFORE reading
            pake_init_header = self.recv_exact(conn, 5)
            msg_type, pake_major, pake_minor, payload_len = struct.unpack('!BBBH', pake_init_header)
            
            if msg_type != MessageType.PAKE_INIT:
                print(f"✗ Expected PAKE_INIT, got {msg_type}")
                self.record_failed_attempt(client_ip)
                return False
            
            # SECURITY FIX: Validate payload size against maximum
            if payload_len > MAX_PAKE_PAYLOAD:
                print(f"✗ PAKE payload too large: {payload_len} (max: {MAX_PAKE_PAYLOAD})")
                error_msg = ProtocolMessage.pack_error(
                    PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                    ErrorCode.PROTOCOL_MISMATCH
                )
                conn.send(error_msg)
                self.record_failed_attempt(client_ip)
                return False

            pake_payload = self.recv_exact(conn, payload_len)

            # Send PAKE_REPLY
            pake_server_msg = spake.start()
            pake_reply = ProtocolMessage.pack_pake_reply(
                PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                pake_server_msg
            )
            conn.send(pake_reply)

            # Derive K_pake - this will fail if wrong pairing code
            try:
                k_pake = spake.finish(pake_payload)
                print(f"✓ SPAKE2 complete (K_pake derived)")
            except Exception as e:
                print(f"✗ SPAKE2 failed - likely wrong pairing code: {e}")
                error_msg = ProtocolMessage.pack_error(
                    PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                    ErrorCode.PAKE_FAIL
                )
                conn.send(error_msg)
                self.record_failed_attempt(client_ip)
                return False
            
            # Step 4: Ephemeral DH Exchange
            print("[4/7] Performing X25519 DH...")
            dh = EphemeralDH()
            
            # Receive sender's DH public key
            dh_client_data = self.recv_exact(conn, 36)
            _, _, role_id, client_pubkey = ProtocolMessage.unpack_dh_pub(dh_client_data)
            
            # Send our DH public key
            dh_server_msg = ProtocolMessage.pack_dh_pub(
                PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                RoleID.RECEIVER,
                dh.get_public_bytes()
            )
            conn.send(dh_server_msg)
            
            # Derive DH shared secret
            dh_secret = dh.derive_shared_secret(client_pubkey)
            print(f"✓ X25519 complete (DH secret derived)")
            
            # Step 5: Session Key Derivation
            print("[5/7] Deriving session keys (HKDF)...")
            self.session_keys = SessionKeyDerivation.derive_session_keys(
                k_pake, dh_secret,
                self.client_nonce, self.server_nonce,
                RoleID.RECEIVER
            )
            print(f"✓ Session keys derived")
            
            # Step 6: Generate and Display SAS
            print("[6/7] Generating SAS...")
            self.sas = SASGenerator.generate_sas(
                self.session_keys['session_key'],
                self.client_nonce,
                self.server_nonce
            )
            
            print("\n" + "="*60)
            print(SASGenerator.format_sas_display(self.sas))
            print("="*60)
            
            # SAS Verification
            print("\n🔍 SAS VERIFICATION REQUIRED!")
            print("Compare the SAS above with the sender's display.")
            print("Do they match exactly? (yes/no): ")
            user_input = input().strip().lower()
            
            if user_input not in ['yes', 'y']:
                print("❌ Transfer ABORTED - SAS mismatch!")
                error_msg = ProtocolMessage.pack_error(
                    PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                    ErrorCode.PAKE_FAIL
                )
                conn.send(error_msg)
                self.record_failed_attempt(client_ip)
                return False
            
            print("✅ SAS verified - proceeding with transfer")
            
            # Step 7: Key Confirmation
            print("[7/7] Key confirmation...")
            
            # Receive client KCONFIRM
            kconfirm_data = self.recv_exact(conn, 19)
            _, _, client_mac = ProtocolMessage.unpack_kconfirm(kconfirm_data)
            
            # Verify client MAC
            expected_client_mac = SessionKeyDerivation.compute_kconfirm_mac(
                self.session_keys['k_confirm'],
                self.client_nonce, self.server_nonce,
                is_client=True
            )
            
            import hmac
            if not hmac.compare_digest(client_mac, expected_client_mac):
                print("✗ Key confirmation failed!")
                error_msg = ProtocolMessage.pack_error(
                    PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                    ErrorCode.KCONFIRM_FAIL
                )
                conn.send(error_msg)
                self.record_failed_attempt(client_ip)
                return False
            
            # Send server KCONFIRM_ACK
            server_mac = SessionKeyDerivation.compute_kconfirm_mac(
                self.session_keys['k_confirm'],
                self.client_nonce, self.server_nonce,
                is_client=False
            )
            kconfirm_ack = ProtocolMessage.pack_kconfirm_ack(
                PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                server_mac
            )
            conn.send(kconfirm_ack)
            
            print("✓ Key confirmation SUCCESS")
            print("✓ Secure channel established\n")
            
            # Initialize AEAD cipher
            self.aead_cipher = AEADCipher(self.session_keys['aead_key'])
            
            # Clear failed attempts on successful handshake
            if client_ip in self.failed_attempts:
                del self.failed_attempts[client_ip]
            
            return True
            
        except Exception as e:
            print(f"✗ Handshake failed: {e}")
            self.record_failed_attempt(client_ip)
            import traceback
            traceback.print_exc()
            return False
    
    def receive_file(self, conn):
        """Receive encrypted file over AEAD channel"""
        try:
            # Receive FILE_META using ProtocolMessage method
            print("\n[*] Receiving file metadata...")
            
            # Read FILE_META header first
            meta_header = self.recv_exact(conn, 5)
            msg_type, major, minor, filename_len = struct.unpack('!BBBH', meta_header)
            
            if msg_type != MessageType.FILE_META:
                print(f"✗ Expected FILE_META, got {msg_type}")
                return False
            
            # SECURITY FIX: Validate filename length before reading
            if filename_len > MAX_FILENAME_LENGTH:
                print(f"✗ Filename too long: {filename_len} (max: {MAX_FILENAME_LENGTH})")
                return False
            
            # Read the rest of FILE_META
            filename_bytes = self.recv_exact(conn, filename_len)
            file_size_bytes = self.recv_exact(conn, 8)
            
            filename_raw = filename_bytes.decode('utf-8')
            file_size = struct.unpack('!Q', file_size_bytes)[0]
            
            # SECURITY FIX: Sanitize filename to prevent path traversal
            try:
                filename = self.sanitize_filename(filename_raw)
                if filename != filename_raw:
                    print(f"⚠️  Filename sanitized: '{filename_raw}' -> '{filename}'")
            except ValueError as e:
                print(f"✗ Invalid filename rejected: {e}")
                return False
            
            print(f"✓ File: {filename}")
            print(f"✓ Size: {file_size / (1024*1024):.2f} MB")
            
            # Receive encrypted chunks
            save_path = self.save_dir / filename
            received = 0
            sequence = 0
            file_hasher = hashlib.sha256()
            chunk_count = 0
            
            print(f"\n📥 Receiving... 0%", end='', flush=True)
            start_time = time.time()
            
            with open(save_path, 'wb') as f:
                while received < file_size:
                    sequence += 1
                    chunk_count += 1
                    
                    # Receive FILE_CHUNK header
                    try:
                        chunk_header = self.recv_exact(conn, 13)
                    except ConnectionError:
                        # Check if we received the entire file
                        if received >= file_size:
                            break
                        else:
                            raise
                    
                    msg_type, major, minor, seq, ct_len = struct.unpack('!BBBQH', chunk_header)
                    
                    if msg_type != MessageType.FILE_CHUNK:
                        print(f"✗ Expected FILE_CHUNK, got {msg_type}")
                        return False
                    
                    # SECURITY FIX: Validate chunk size against protocol maximum
                    if ct_len > MAX_CHUNK_SIZE or ct_len == 0:
                        print(f"✗ Invalid chunk size: {ct_len} (max: {MAX_CHUNK_SIZE})")
                        return False
                    
                    # Receive ciphertext
                    ciphertext = self.recv_exact(conn, ct_len)
                    
                    # Decrypt with AEAD
                    nonce = self.aead_cipher.make_nonce(sequence)
                    ad = create_associated_data(
                        MessageType.FILE_CHUNK,
                        PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                        sequence, filename
                    )
                    
                    try:
                        plaintext = self.aead_cipher.decrypt(nonce, ciphertext, ad)
                        f.write(plaintext)
                        file_hasher.update(plaintext)
                        received += len(plaintext)
                        
                        progress = (received / file_size) * 100
                        elapsed = time.time() - start_time
                        speed = (received / (1024*1024)) / elapsed if elapsed > 0 else 0
                        print(f"\r📥 Receiving... {progress:.1f}% | Speed: {speed:.2f} MB/s | Chunks: {chunk_count}", end='', flush=True)
                        
                    except Exception as e:
                        print(f"\n✗ AEAD decrypt failed for chunk {sequence}: {e}")
                        # SECURITY FIX: Clean up partial file on decryption failure
                        if save_path.exists():
                            os.remove(save_path)
                            print(f"✓ Cleaned up partial file")
                        return False
            
            print(f"\n\n✓ File received ({chunk_count} chunks)")
            
            # Receive FILE_END
            file_end_data = self.recv_exact(conn, 43)
            _, _, final_seq, sender_hash = ProtocolMessage.unpack_file_end(file_end_data)
            
            # Verify file integrity (use constant-time comparison)
            calculated_hash = file_hasher.digest()
            
            print("\n" + "="*60)
            import hmac
            if hmac.compare_digest(calculated_hash, sender_hash):
                print("✅ Transfer SUCCESSFUL")
                print(f"✅ File saved: {save_path.absolute()}")
                print(f"✅ Total chunks: {chunk_count}")
                
                # Send success
                result_msg = ProtocolMessage.pack_transfer_result(
                    PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                    True
                )
                conn.send(result_msg)
            else:
                print("❌ FAILED - Hash mismatch")
                print(f"Expected: {sender_hash.hex()}")
                print(f"Got: {calculated_hash.hex()}")
                if save_path.exists():
                    os.remove(save_path)
                    print(f"✓ Cleaned up corrupted file")
                
                # Send failure
                result_msg = ProtocolMessage.pack_transfer_result(
                    PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                    False
                )
                conn.send(result_msg)
            print("="*60 + "\n")
            
            return hmac.compare_digest(calculated_hash, sender_hash)
            
        except Exception as e:
            print(f"\n✗ File transfer failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def start(self):
        """Start receiver and listen for connections"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', self.port))
        server.listen(1)
        server.settimeout(300)  # 5 minute timeout
        
        local_ip = self.get_local_ip()
        
        print("\n" + "="*60)
        print("SecureDrop Receiver v1.0 [SPAKE2 + X25519 + ChaCha20]")
        print("="*60)
        print(f"\n🔐 PAIRING CODE: {self.pairing_code}")
        print(f"\n📱 Sender command:")
        print(f"   python sender.py {local_ip} {self.pairing_code} <file>\n")
        print(f"📂 Save location: {self.save_dir.absolute()}")
        print(f"🌐 Listening on: {local_ip}:{self.port}")
        print(f"\n⏳ Waiting for connection...\n")
        
        conn = None
        try:
            conn, addr = server.accept()
            conn.settimeout(300)  # 5 minute timeout
            client_ip = addr[0]
            print(f"✓ Connection from: {client_ip}\n")
            
            # Perform handshake with IP for rate limiting
            if not self.handshake(conn, client_ip):
                print("✗ Handshake failed")
                if conn:
                    conn.close()
                return
            
            # Receive file
            success = self.receive_file(conn)
            
            if success:
                print("🎉 Transfer completed successfully!")
            else:
                print("💥 Transfer failed")
            
        except socket.timeout:
            print("\n✗ Connection timeout - no connection received")
        except KeyboardInterrupt:
            print("\n\n⚠️  Cancelled by user")
        except Exception as e:
            print(f"\n✗ Error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            if conn:
                conn.close()
            server.close()
            
            # Clean up sensitive data
            if self.session_keys:
                for key_name, key_value in self.session_keys.items():
                    if isinstance(key_value, (bytes, bytearray)):
                        # Best effort to clear sensitive data
                        try:
                            # Convert to bytearray and zero it
                            if isinstance(key_value, bytes):
                                key_value = bytearray(key_value)
                            for i in range(len(key_value)):
                                key_value[i] = 0
                        except:
                            pass  # Can't do much in Python

if __name__ == "__main__":
    import sys
    
    port = 5000
    if len(sys.argv) > 1 and sys.argv[1] == "--port":
        port = int(sys.argv[2])
    
    receiver = SecureReceiver(port=port)
    receiver.start()