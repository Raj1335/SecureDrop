"""
SecureDrop Sender - SPAKE2 + X25519 + ChaCha20-Poly1305
Protocol Version 1.0 - Minimalist Output Mode
"""

import socket
import os
import hashlib
import struct 
from pathlib import Path
import time
import sys

from .core.protocol import (
    ProtocolMessage, MessageType, RoleID, ErrorCode,
    generate_nonce, check_version_compatible,
    PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
    MAX_PAKE_PAYLOAD
)
from .core.pake import SPAKE2Exchange
from .core.crypto import (
    EphemeralDH, SessionKeyDerivation, AEADCipher,
    create_associated_data
)
from .core.sas import SASGenerator

class SecureSender:
    def __init__(self, receiver_ip, pairing_code, receiver_port=5000, verbose=False):
        self.receiver_ip = receiver_ip
        self.receiver_port = receiver_port
        self.pairing_code = pairing_code
        self.verbose = verbose
        
        self.client_nonce = None
        self.server_nonce = None
        self.session_keys = None
        self.aead_cipher = None
        self.sas = None
    
    def log(self, message):
        """Print only in verbose mode"""
        if self.verbose:
            print(message)
    
    def recv_exact(self, sock, n):
        data = b''
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError(f"Connection closed")
            data += chunk
        return data
    
    def handshake(self, sock):
        try:
            self.log("Sending HELLO...")
            self.client_nonce = generate_nonce()
            hello_msg = ProtocolMessage.pack_hello(
                PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                self.client_nonce
            )
            sock.send(hello_msg)
            
            self.log("Receiving HELLO_ACK...")
            hello_ack_data = self.recv_exact(sock, 19)
            major, minor, self.server_nonce = ProtocolMessage.unpack_hello_ack(hello_ack_data)
            
            if not check_version_compatible(major, minor):
                print(f"✗ Incompatible version: {major}.{minor}")
                return False
            
            self.log(f"Version: {major}.{minor}")
            
            self.log("SPAKE2 exchange...")
            spake = SPAKE2Exchange(self.pairing_code, side="A")
            
            pake_client_msg = spake.start()
            pake_init = ProtocolMessage.pack_pake_init(
                PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                pake_client_msg
            )
            sock.send(pake_init)
            
            pake_reply_header = self.recv_exact(sock, 5)
            msg_type, pake_major, pake_minor, payload_len = struct.unpack('!BBBH', pake_reply_header)
            
            if msg_type != MessageType.PAKE_REPLY or payload_len > MAX_PAKE_PAYLOAD:
                print("✗ PAKE failed")
                return False
            
            pake_server_msg = self.recv_exact(sock, payload_len)
            
            try:
                k_pake = spake.finish(pake_server_msg)
                self.log("SPAKE2 complete")
            except Exception as e:
                print("✗ Wrong pairing code")
                return False
            
            self.log("X25519 exchange...")
            dh = EphemeralDH()
            
            dh_client_msg = ProtocolMessage.pack_dh_pub(
                PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                RoleID.SENDER,
                dh.get_public_bytes()
            )
            sock.send(dh_client_msg)
            
            dh_server_data = self.recv_exact(sock, 36)
            _, _, role_id, server_pubkey = ProtocolMessage.unpack_dh_pub(dh_server_data)
            
            dh_secret = dh.derive_shared_secret(server_pubkey)
            self.log("X25519 complete")
            
            self.log("Deriving session keys...")
            self.session_keys = SessionKeyDerivation.derive_session_keys(
                k_pake, dh_secret,
                self.client_nonce, self.server_nonce,
                RoleID.SENDER
            )
            self.log("Keys derived")
            
            self.log("Generating SAS...")
            self.sas = SASGenerator.generate_sas(
                self.session_keys['session_key'],
                self.client_nonce,
                self.server_nonce
            )
            
            print(f"\n🔐 SAS: {' '.join(self.sas['words'][:3])}")
            if self.verbose:
                print(f"    Hex: {self.sas['hex'][:16]}...")
            print("⚠️  Verify with receiver, press ENTER to continue...")
            input()
            
            self.log("Key confirmation...")
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
            
            kconfirm_ack_data = self.recv_exact(sock, 19)
            _, _, server_mac = ProtocolMessage.unpack_kconfirm_ack(kconfirm_ack_data)
            
            expected_server_mac = SessionKeyDerivation.compute_kconfirm_mac(
                self.session_keys['k_confirm'],
                self.client_nonce, self.server_nonce,
                is_client=False
            )
            
            import hmac
            if not hmac.compare_digest(server_mac, expected_server_mac):
                print("✗ Key confirmation failed")
                return False
            
            print("✓ Secure channel established\n")
            
            self.aead_cipher = AEADCipher(self.session_keys['aead_key'])
            
            return True
            
        except Exception as e:
            print(f"✗ Handshake failed: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()
            return False
    
    def send_files(self, file_paths, console=None):
        validated_files = []
        total_size = 0
        
        for path in file_paths:
            fpath = Path(path)
            if not fpath.exists():
                print(f"✗ File not found: {fpath}")
                return False
            if fpath.is_dir():
                print(f"✗ Directories not supported: {fpath}")
                return False
            
            size = fpath.stat().st_size
            validated_files.append((fpath, size))
            total_size += size
        
        print(f"\n{'='*50}")
        print(f"SecureDrop Sender v1.0")
        print(f"{'='*50}")
        print(f"📦 Files: {len(validated_files)}")
        print(f"📊 Total: {total_size / (1024*1024):.1f} MB")
        print(f"🌐 Receiver: {self.receiver_ip}:{self.receiver_port}")
        if self.verbose:
            print(f"📊 Verbose mode enabled")
        print(f"\n🔗 Connecting...", end='', flush=True)
        
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(300)
            sock.connect((self.receiver_ip, self.receiver_port))
            print(" ✓\n")
            
            if not self.handshake(sock):
                sock.close()
                return False
            
            self.log("Sending file list...")
            file_entries = [(f.name, s) for f, s in validated_files]
            file_list_msg = ProtocolMessage.pack_file_list(
                PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                file_entries
            )
            sock.send(file_list_msg)
            
            ack_data = self.recv_exact(sock, 4)
            _, _, status = ProtocolMessage.unpack_file_list_ack(ack_data)
            if status != 0x01:
                print("✗ Receiver rejected file list")
                return False
            
            overall_start = time.time()
            for idx, (file_path, file_size) in enumerate(validated_files):
                print(f"\n[{idx+1}/{len(validated_files)}] {file_path.name}")
                
                if not self._send_single_file(sock, file_path, file_size):
                    print(f"✗ Failed")
                    return False
                
                if idx < len(validated_files) - 1:
                    next_msg = self.recv_exact(sock, 7)
                    _, _, next_idx = ProtocolMessage.unpack_next_file(next_msg)
                    if next_idx != idx + 1:
                        print(f"✗ Protocol error")
                        return False
            
            result_data = self.recv_exact(sock, 4)
            _, _, success = ProtocolMessage.unpack_transfer_result(result_data)
            
            overall_elapsed = time.time() - overall_start
            overall_speed = (total_size / overall_elapsed) / (1024*1024) if overall_elapsed > 0 else 0
            
            if success:
                print(f"\n✅ Transfer complete ({overall_speed:.1f} MB/s)")
            else:
                print("\n✗ Transfer failed")
            
            return success
            
        except socket.timeout:
            print(f"\n✗ Connection timeout")
            return False
        except ConnectionRefusedError:
            print(f"\n✗ Could not connect to {self.receiver_ip}:{self.receiver_port}")
            return False
        except KeyboardInterrupt:
            print("\n\n⚠️  Cancelled")
            return False
        except Exception as e:
            print(f"\n✗ Error: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()
            return False
        finally:
            if sock:
                sock.close()
    
    def _send_single_file(self, sock, file_path, file_size):
        filename = file_path.name
        
        file_meta = ProtocolMessage.pack_file_meta(
            PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
            filename, file_size
        )
        sock.send(file_meta)
        
        sent = 0
        sequence = 1
        chunk_size = 32 * 1024
        file_hasher = hashlib.sha256()
        start_time = time.time()
        
        print(f"   Sending... 0%", end='', flush=True)
        
        with open(file_path, 'rb') as f:
            while sent < file_size:
                plaintext = f.read(chunk_size)
                if not plaintext:
                    break
                
                file_hasher.update(plaintext)
                
                nonce = self.aead_cipher.make_nonce(sequence)
                ad = create_associated_data(
                    MessageType.FILE_CHUNK,
                    PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                    sequence, filename
                )
                
                _, ciphertext = self.aead_cipher.encrypt(plaintext, ad, sequence)
                
                chunk_msg = ProtocolMessage.pack_file_chunk(
                    PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                    sequence, ciphertext
                )
                sock.sendall(chunk_msg)
                
                sent += len(plaintext)
                sequence += 1
                
                progress = (sent / file_size) * 100
                print(f"\r   Sending... {progress:.0f}%", end='', flush=True)
        
        file_hash = file_hasher.digest()
        
        file_end = ProtocolMessage.pack_file_end(
            PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
            sequence - 1, file_hash
        )
        sock.send(file_end)
        
        elapsed = time.time() - start_time
        avg_speed = (file_size / elapsed) / (1024*1024) if elapsed > 0 else 0
        print(f"\r   ✓ Sent ({avg_speed:.1f} MB/s)")
        
        return True

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("\n╔════════════════════════════════════════════════╗")
        print("║         SecureDrop - File Transfer            ║")
        print("╚════════════════════════════════════════════════╝")
        print("\nUsage: python sender.py <ip> <code> <files> [options]")
        print("\nOptions:")
        print("  --verbose, -v    Show detailed protocol information")
        print("\nExamples:")
        print("  python sender.py 192.168.1.5 123456 file.pdf")
        print("  python sender.py 192.168.1.5 123456 *.jpg -v")
        sys.exit(1)
    
    receiver_ip = sys.argv[1]
    pairing_code = sys.argv[2]
    
    verbose = False
    file_paths = []
    
    for arg in sys.argv[3:]:
        if arg in ['--verbose', '-v']:
            verbose = True
        else:
            file_paths.append(arg)
    
    if not file_paths:
        print("✗ No files specified")
        sys.exit(1)
    
    sender = SecureSender(receiver_ip, pairing_code, verbose=verbose)
    success = sender.send_files(file_paths)
    sys.exit(0 if success else 1)