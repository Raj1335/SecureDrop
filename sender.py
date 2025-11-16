"""
SecureDrop Sender - SPAKE2 + X25519 + ChaCha20-Poly1305
Protocol Version 1.0
SECURITY FIXES:
- Added recv_exact() helper to prevent incomplete recv() operations
- Socket timeout protection against slow-read attacks
- Proper payload size validation
"""

import socket
import os
import hashlib
import struct 
from pathlib import Path
import time
import sys

from core.protocol import (
    ProtocolMessage, MessageType, RoleID, ErrorCode,
    generate_nonce, check_version_compatible,
    PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
    MAX_PAKE_PAYLOAD
)
from core.pake import SPAKE2Exchange
from core.crypto import (
    EphemeralDH, SessionKeyDerivation, AEADCipher,
    create_associated_data
)
from core.sas import SASGenerator

class SecureSender:
    def __init__(self, receiver_ip, pairing_code, receiver_port=5000):
        self.receiver_ip = receiver_ip
        self.receiver_port = receiver_port
        self.pairing_code = pairing_code
        
        # Protocol state
        self.client_nonce = None
        self.server_nonce = None
        self.session_keys = None
        self.aead_cipher = None
        self.sas = None
    
    def recv_exact(self, sock, n):
        """
        SECURITY FIX: Receive exactly n bytes from socket.
        Prevents issues with TCP messages split across packets.
        
        Args:
            sock: Socket to receive from
            n: Exact number of bytes to receive
            
        Returns:
            Exactly n bytes
            
        Raises:
            ConnectionError if connection closes before receiving n bytes
        """
        data = b''
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("Connection closed prematurely")
            data += chunk
        return data
    
    def handshake(self, sock):
        """
        Perform full cryptographic handshake.
        Returns True if successful, False otherwise.
        """
        try:
            # Step 1: Send HELLO
            print("[1/7] Sending HELLO...")
            self.client_nonce = generate_nonce()
            hello_msg = ProtocolMessage.pack_hello(
                PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                self.client_nonce
            )
            sock.send(hello_msg)
            
            # Step 2: Receive HELLO_ACK - FIXED: Use recv_exact
            print("[2/7] Receiving HELLO_ACK...")
            hello_ack_data = self.recv_exact(sock, 19)
            major, minor, self.server_nonce = ProtocolMessage.unpack_hello_ack(hello_ack_data)
            
            if not check_version_compatible(major, minor):
                print(f"✗ Incompatible version: {major}.{minor}")
                return False
            
            print(f"✓ Version compatible: {major}.{minor}")
            
            # Step 3: SPAKE2 Exchange
            print("[3/7] Performing SPAKE2 PAKE...")
            spake = SPAKE2Exchange(self.pairing_code, side="A")
            
            # Send PAKE_INIT
            pake_client_msg = spake.start()
            pake_init = ProtocolMessage.pack_pake_init(
                PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                pake_client_msg
            )
            sock.send(pake_init)
            
            # Receive PAKE_REPLY - FIXED: Read header first, validate size, then read payload
            print("[3/7] Receiving PAKE_REPLY...")
            pake_reply_header = self.recv_exact(sock, 5)
            msg_type, pake_major, pake_minor, payload_len = struct.unpack('!BBBH', pake_reply_header)
            
            if msg_type != MessageType.PAKE_REPLY:
                print(f"✗ Expected PAKE_REPLY, got {msg_type}")
                return False
            
            # SECURITY FIX: Validate payload size before reading
            if payload_len > MAX_PAKE_PAYLOAD:
                print(f"✗ PAKE payload too large: {payload_len} (max: {MAX_PAKE_PAYLOAD})")
                return False
            
            pake_server_msg = self.recv_exact(sock, payload_len)
            
            # Derive K_pake
            try:
                k_pake = spake.finish(pake_server_msg)
                print(f"✓ SPAKE2 complete (K_pake derived)")
            except Exception as e:
                print(f"✗ SPAKE2 failed - likely wrong pairing code: {e}")
                return False
            
            # Step 4: Ephemeral DH Exchange
            print("[4/7] Performing X25519 DH...")
            dh = EphemeralDH()
            
            # Send our DH public key
            dh_client_msg = ProtocolMessage.pack_dh_pub(
                PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                RoleID.SENDER,
                dh.get_public_bytes()
            )
            sock.send(dh_client_msg)
            
            # Receive server's DH public key - FIXED: Use recv_exact
            dh_server_data = self.recv_exact(sock, 36)
            _, _, role_id, server_pubkey = ProtocolMessage.unpack_dh_pub(dh_server_data)
            
            # Derive DH shared secret
            dh_secret = dh.derive_shared_secret(server_pubkey)
            print(f"✓ X25519 complete (DH secret derived)")
            
            # Step 5: Session Key Derivation
            print("[5/7] Deriving session keys (HKDF)...")
            self.session_keys = SessionKeyDerivation.derive_session_keys(
                k_pake, dh_secret,
                self.client_nonce, self.server_nonce,
                RoleID.SENDER
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
            print("\n⚠️   VERIFY THIS MATCHES RECEIVER'S DISPLAY!")
            print("   Press ENTER after verification...")
            input()
            
            # Step 7: Key Confirmation
            print("[7/7] Key confirmation...")
            
            # Send client KCONFIRM
            client_mac = SessionKeyDerivation.compute_kconfirm_mac(
                self.session_keys['k_confirm'],
                self.client_nonce, self.server_nonce,
                is_client=True
            )
            kconfirm = ProtocolMessage.pack_kconfirm(
                PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                client_mac
            )
            sock.send(kconfirm)
            
            # Receive server KCONFIRM_ACK - FIXED: Use recv_exact
            kconfirm_ack_data = self.recv_exact(sock, 19)
            _, _, server_mac = ProtocolMessage.unpack_kconfirm_ack(kconfirm_ack_data)
            
            # Verify server MAC
            expected_server_mac = SessionKeyDerivation.compute_kconfirm_mac(
                self.session_keys['k_confirm'],
                self.client_nonce, self.server_nonce,
                is_client=False
            )
            
            import hmac
            if not hmac.compare_digest(server_mac, expected_server_mac):
                print("✗ Key confirmation failed!")
                return False
            
            print("✓ Key confirmation SUCCESS")
            print("✓ Secure channel established\n")
            
            # Initialize AEAD cipher
            self.aead_cipher = AEADCipher(self.session_keys['aead_key'])
            
            return True
            
        except Exception as e:
            print(f"✗ Handshake failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def send_file(self, file_path):
        """Send file over encrypted AEAD channel"""
        file_path = Path(file_path)
        
        if not file_path.exists():
            print(f"✗ Error: File not found - {file_path}")
            return False
        
        file_size = file_path.stat().st_size
        filename = file_path.name
        
        print(f"\n{'='*60}")
        print(f"SecureDrop Sender v1.0 [SPAKE2 + X25519 + ChaCha20]")
        print(f"{'='*60}")
        print(f"📄 File: {filename}")
        print(f"📦 Size: {file_size / (1024*1024):.2f} MB")
        print(f"🌐 Receiver: {self.receiver_ip}:{self.receiver_port}")
        print(f"\n🔗 Connecting...", end='', flush=True)
        
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # SECURITY FIX: Set socket timeout to prevent hanging indefinitely
            sock.settimeout(300)  # 5 minute timeout for handshake and transfers
            
            sock.connect((self.receiver_ip, self.receiver_port))
            print(" ✓ Connected\n")
            
            # Perform handshake
            if not self.handshake(sock):
                print("✗ Handshake failed")
                sock.close()
                return False
            
            # Send FILE_META
            print("\n[*] Sending file metadata...")
            file_meta = ProtocolMessage.pack_file_meta(
                PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                filename, file_size
            )
            sock.send(file_meta)
            
            # Send encrypted chunks
            sent = 0
            sequence = 1
            chunk_size = 32 * 1024  # 32KB chunks
            file_hasher = hashlib.sha256()
            start_time = time.time()
            
            print(f"\n📤 Sending... 0%", end='', flush=True)
            
            with open(file_path, 'rb') as f:
                while sent < file_size:
                    plaintext = f.read(chunk_size)
                    if not plaintext:
                        break
                    
                    file_hasher.update(plaintext)
                    
                    # Encrypt with AEAD
                    nonce = self.aead_cipher.make_nonce(sequence)
                    ad = create_associated_data(
                        MessageType.FILE_CHUNK,
                        PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                        sequence, filename
                    )
                    
                    _, ciphertext = self.aead_cipher.encrypt(plaintext, ad, sequence)
                    
                    # Send FILE_CHUNK
                    chunk_msg = ProtocolMessage.pack_file_chunk(
                        PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                        sequence, ciphertext
                    )
                    sock.sendall(chunk_msg)
                    
                    sent += len(plaintext)
                    sequence += 1
                    
                    progress = (sent / file_size) * 100
                    elapsed = time.time() - start_time
                    if elapsed > 0:
                        speed = (sent / elapsed) / (1024*1024)
                        print(f"\r📤 Sending... {progress:.1f}% | Speed: {speed:.2f} MB/s", end='', flush=True)
            
            file_hash = file_hasher.digest()
            
            # Send FILE_END
            file_end = ProtocolMessage.pack_file_end(
                PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                sequence - 1, file_hash
            )
            sock.send(file_end)
            
            # Receive TRANSFER_RESULT - FIXED: Use recv_exact
            result_data = self.recv_exact(sock, 4)
            _, _, success = ProtocolMessage.unpack_transfer_result(result_data)
            
            elapsed = time.time() - start_time
            avg_speed = (file_size / elapsed) / (1024*1024) if elapsed > 0 else 0
            
            print(f"\n\n{'='*60}")
            if success:
                print("✅ Transfer SUCCESSFUL")
                print(f"✓ Time: {elapsed:.2f} seconds")
                print(f"✓ Average speed: {avg_speed:.2f} MB/s")
            else:
                print("❌ Transfer FAILED - Receiver reported error")
            print(f"{'='*60}\n")
            
            return success
            
        except socket.timeout:
            print(f"\n✗ Error: Connection timeout")
            print("  The receiver may be unresponsive or the network is too slow")
            return False
        except ConnectionRefusedError:
            print(f"\n✗ Error: Could not connect to {self.receiver_ip}:{self.receiver_port}")
            print("  Make sure receiver is running and IP address is correct")
            return False
        except KeyboardInterrupt:
            print("\n\n⚠️  Transfer cancelled by user")
            return False
        except Exception as e:
            print(f"\n✗ Error: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            if sock:
                sock.close()

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("\nUsage: python sender.py <receiver_ip> <pairing_code> <file_path>")
        print("Example: python sender.py 192.168.1.5 123456 document.pdf")
        sys.exit(1)
    
    receiver_ip = sys.argv[1]
    pairing_code = sys.argv[2]
    file_path = sys.argv[3]
    
    sender = SecureSender(receiver_ip, pairing_code)
    sender.send_file(file_path)