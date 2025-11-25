"""
SecureDrop Sender - SPAKE2 + X25519 + ChaCha20-Poly1305
Protocol Version 1.0
UPDATED: Multi-file transfer support
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
        """Receive exactly n bytes from socket"""
        data = b''
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError(f"Connection closed after {len(data)}/{n} bytes")
            data += chunk
        return data
    
    def handshake(self, sock):
        """Perform full cryptographic handshake"""
        try:
            # Step 1: Send HELLO
            print("[1/7] Sending HELLO...")
            self.client_nonce = generate_nonce()
            hello_msg = ProtocolMessage.pack_hello(
                PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                self.client_nonce
            )
            sock.send(hello_msg)
            
            # Step 2: Receive HELLO_ACK
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
            
            # Receive PAKE_REPLY
            pake_reply_header = self.recv_exact(sock, 5)
            msg_type, pake_major, pake_minor, payload_len = struct.unpack('!BBBH', pake_reply_header)
            
            if msg_type != MessageType.PAKE_REPLY:
                print(f"✗ Expected PAKE_REPLY, got {msg_type}")
                return False
            
            if payload_len > MAX_PAKE_PAYLOAD:
                print(f"✗ PAKE payload too large: {payload_len}")
                return False
            
            pake_server_msg = self.recv_exact(sock, payload_len)
            
            # Derive K_pake
            try:
                k_pake = spake.finish(pake_server_msg)
                print(f"✓ SPAKE2 complete (K_pake derived)")
            except Exception as e:
                print(f"✗ SPAKE2 failed - wrong pairing code: {e}")
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
            
            # Receive server's DH public key
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
            
            # Receive server KCONFIRM_ACK
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
    
    def send_files(self, file_paths):
        """Send multiple files over single secure connection"""
        # Validate all files first
        validated_files = []
        total_size = 0
        
        for path in file_paths:
            fpath = Path(path)
            if not fpath.exists():
                print(f"✗ Error: File not found - {fpath}")
                return False
            if fpath.is_dir():
                print(f"✗ Error: Directories not supported - {fpath}")
                return False
            
            size = fpath.stat().st_size
            validated_files.append((fpath, size))
            total_size += size
        
        print(f"\n{'='*60}")
        print(f"SecureDrop Sender v1.0 [Multi-File Transfer]")
        print(f"{'='*60}")
        print(f"📦 Files: {len(validated_files)}")
        print(f"📊 Total size: {total_size / (1024*1024):.2f} MB")
        print(f"🌐 Receiver: {self.receiver_ip}:{self.receiver_port}")
        print(f"\n🔗 Connecting...", end='', flush=True)
        
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(300)
            sock.connect((self.receiver_ip, self.receiver_port))
            print(" ✓ Connected\n")
            
            # Perform handshake once
            if not self.handshake(sock):
                print("✗ Handshake failed")
                sock.close()
                return False
            
            # Send file list
            print("\n[*] Sending file list...")
            file_entries = [(f.name, s) for f, s in validated_files]
            file_list_msg = ProtocolMessage.pack_file_list(
                PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                file_entries
            )
            sock.send(file_list_msg)
            
            # Wait for FILE_LIST_ACK
            ack_data = self.recv_exact(sock, 4)
            _, _, status = ProtocolMessage.unpack_file_list_ack(ack_data)
            if status != 0x01:
                print("✗ Receiver rejected file list")
                return False
            print("✓ File list accepted\n")
            
            # Send each file
            overall_start = time.time()
            for idx, (file_path, file_size) in enumerate(validated_files):
                print(f"\n{'─'*60}")
                print(f"[{idx+1}/{len(validated_files)}] {file_path.name}")
                print(f"{'─'*60}")
                
                if not self._send_single_file(sock, file_path, file_size):
                    print(f"✗ Failed to send {file_path.name}")
                    return False
                
                # Wait for NEXT_FILE signal (except after last file)
                if idx < len(validated_files) - 1:
                    next_msg = self.recv_exact(sock, 7)
                    _, _, next_idx = ProtocolMessage.unpack_next_file(next_msg)
                    if next_idx != idx + 1:
                        print(f"✗ Protocol error: expected file {idx+1}, got {next_idx}")
                        return False
            
            # Receive final transfer result
            result_data = self.recv_exact(sock, 4)
            _, _, success = ProtocolMessage.unpack_transfer_result(result_data)
            
            overall_elapsed = time.time() - overall_start
            overall_speed = (total_size / overall_elapsed) / (1024*1024) if overall_elapsed > 0 else 0
            
            print(f"\n{'='*60}")
            if success:
                print("✅ ALL FILES TRANSFERRED SUCCESSFULLY")
                print(f"✓ Total files: {len(validated_files)}")
                print(f"✓ Total size: {total_size / (1024*1024):.2f} MB")
                print(f"✓ Total time: {overall_elapsed:.2f} seconds")
                print(f"✓ Average speed: {overall_speed:.2f} MB/s")
            else:
                print("❌ TRANSFER FAILED - Receiver reported error")
            print(f"{'='*60}\n")
            
            return success
            
        except socket.timeout:
            print(f"\n✗ Error: Connection timeout")
            return False
        except ConnectionRefusedError:
            print(f"\n✗ Error: Could not connect to {self.receiver_ip}:{self.receiver_port}")
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
    
    def _send_single_file(self, sock, file_path, file_size):
        """Send single file over existing connection"""
        filename = file_path.name
        
        # Send FILE_META
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
        
        print(f"📤 Sending... 0%", end='', flush=True)
        
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
                    print(f"\r📤 Sending... {progress:.1f}% | {speed:.2f} MB/s", end='', flush=True)
        
        file_hash = file_hasher.digest()
        
        # Send FILE_END
        file_end = ProtocolMessage.pack_file_end(
            PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
            sequence - 1, file_hash
        )
        sock.send(file_end)
        
        elapsed = time.time() - start_time
        avg_speed = (file_size / elapsed) / (1024*1024) if elapsed > 0 else 0
        print(f"\r✓ Sent in {elapsed:.2f}s @ {avg_speed:.2f} MB/s" + " "*20)
        
        return True

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("\n╔════════════════════════════════════════════════════════════╗")
        print("║           SecureDrop - Multi-File Transfer                 ║")
        print("╚════════════════════════════════════════════════════════════╝")
        print("\nUsage: python sender.py <receiver_ip> <pairing_code> <file1> [file2] [file3] ...")
        print("\nExamples:")
        print("  Single file:   python sender.py 192.168.1.5 123456 document.pdf")
        print("  Multiple files: python sender.py 192.168.1.5 123456 doc.pdf image.jpg data.zip")
        sys.exit(1)
    
    receiver_ip = sys.argv[1]
    pairing_code = sys.argv[2]
    file_paths = sys.argv[3:]
    
    sender = SecureSender(receiver_ip, pairing_code)
    success = sender.send_files(file_paths)
    sys.exit(0 if success else 1)