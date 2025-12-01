"""
SecureDrop Receiver - SPAKE2 + X25519 + ChaCha20-Poly1305
Protocol Version 1.0 - Minimalist Output Mode
"""
import socket
import os
import struct
import hashlib
from pathlib import Path
import time
import sys

sys.path.append(os.path.dirname(__file__))
from .core.protocol import (
    ProtocolMessage, MessageType, RoleID, ErrorCode,
    generate_nonce, check_version_compatible,
    PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
    MAX_PAKE_PAYLOAD, MAX_FILENAME_LENGTH, MAX_CHUNK_SIZE
)
from .core.pake import SPAKE2Exchange, generate_6digit_code
from .core.crypto import (
    EphemeralDH, SessionKeyDerivation, AEADCipher,
    create_associated_data
)
from .core.sas import SASGenerator

class SecureReceiver:
    def __init__(self, port=5000, save_dir="received_files", verbose=False):
        self.port = port
        self.save_dir = Path(save_dir)
        self.save_dir.mkdir(exist_ok=True)
        self.verbose = verbose
        
        self.pairing_code = generate_6digit_code()
        self.client_nonce = None
        self.server_nonce = None
        self.session_keys = None
        self.aead_cipher = None
        self.sas = None
        
        self.failed_attempts = {}
        self.max_attempts = 3
        self.ban_duration = 300
    
    def log(self, message):
        """Print only in verbose mode"""
        if self.verbose:
            print(message)
    
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    
    def is_ip_banned(self, ip):
        if ip not in self.failed_attempts:
            return False
        count, last_attempt = self.failed_attempts[ip]
        if time.time() - last_attempt > self.ban_duration:
            del self.failed_attempts[ip]
            return False
        return count >= self.max_attempts
    
    def record_failed_attempt(self, ip):
        current_time = time.time()
        if ip in self.failed_attempts:
            count, last_attempt = self.failed_attempts[ip]
            if current_time - last_attempt > self.ban_duration:
                count = 0
            self.failed_attempts[ip] = (count + 1, current_time)
        else:
            self.failed_attempts[ip] = (1, current_time)
        
        count = self.failed_attempts[ip][0]
        if count >= self.max_attempts:
            remaining = self.ban_duration - (current_time - self.failed_attempts[ip][1])
            self.log(f"IP {ip} banned for {remaining:.0f} seconds")
    
    def sanitize_filename(self, filename):
        if not filename or len(filename) > MAX_FILENAME_LENGTH:
            raise ValueError(f"Invalid filename length: {len(filename)}")
        safe_name = os.path.basename(filename)
        if '/' in safe_name or '\\' in safe_name or '..' in safe_name:
            raise ValueError(f"Invalid filename: {filename}")
        if not safe_name or safe_name in ('.', '..'):
            raise ValueError(f"Invalid filename: {filename}")
        return safe_name
    
    def recv_exact(self, sock, n):
        data = b''
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError(f"Connection closed")
            data += chunk
        return data
    
    def handshake(self, conn, client_ip):
        try:
            if self.is_ip_banned(client_ip):
                self.log(f"Connection rejected - IP banned")
                error_msg = ProtocolMessage.pack_error(
                    PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                    ErrorCode.RATE_LIMIT
                )
                conn.send(error_msg)
                return False
            
            self.log("Receiving HELLO...")
            hello_data = self.recv_exact(conn, 19)
            major, minor, self.client_nonce = ProtocolMessage.unpack_hello(hello_data)
            
            if not check_version_compatible(major, minor):
                self.log(f"Incompatible version: {major}.{minor}")
                error_msg = ProtocolMessage.pack_error(
                    PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                    ErrorCode.PROTOCOL_MISMATCH
                )
                conn.send(error_msg)
                self.record_failed_attempt(client_ip)
                return False
            
            self.log(f"Version: {major}.{minor}")
            
            self.log("Sending HELLO_ACK...")
            self.server_nonce = generate_nonce()
            hello_ack = ProtocolMessage.pack_hello_ack(
                PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                self.server_nonce
            )
            conn.send(hello_ack)
            
            self.log("SPAKE2 exchange...")
            spake = SPAKE2Exchange(self.pairing_code, side="B")
            
            pake_init_header = self.recv_exact(conn, 5)
            msg_type, pake_major, pake_minor, payload_len = struct.unpack('!BBBH', pake_init_header)
            
            if msg_type != MessageType.PAKE_INIT or payload_len > MAX_PAKE_PAYLOAD:
                self.log("PAKE failed")
                self.record_failed_attempt(client_ip)
                return False
            
            pake_payload = self.recv_exact(conn, payload_len)
            pake_server_msg = spake.start()
            pake_reply = ProtocolMessage.pack_pake_reply(
                PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                pake_server_msg
            )
            conn.send(pake_reply)
            
            try:
                k_pake = spake.finish(pake_payload)
                self.log("SPAKE2 complete")
            except Exception as e:
                print("✗ Wrong pairing code")
                error_msg = ProtocolMessage.pack_error(
                    PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                    ErrorCode.PAKE_FAIL
                )
                conn.send(error_msg)
                self.record_failed_attempt(client_ip)
                return False
            
            self.log("X25519 exchange...")
            dh = EphemeralDH()
            dh_client_data = self.recv_exact(conn, 36)
            _, _, role_id, client_pubkey = ProtocolMessage.unpack_dh_pub(dh_client_data)
            
            dh_server_msg = ProtocolMessage.pack_dh_pub(
                PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                RoleID.RECEIVER,
                dh.get_public_bytes()
            )
            conn.send(dh_server_msg)
            
            dh_secret = dh.derive_shared_secret(client_pubkey)
            self.log("X25519 complete")
            
            self.log("Deriving session keys...")
            self.session_keys = SessionKeyDerivation.derive_session_keys(
                k_pake, dh_secret,
                self.client_nonce, self.server_nonce,
                RoleID.RECEIVER
            )
            self.log("Keys derived")
            
            self.log("Generating SAS...")
            self.sas = SASGenerator.generate_sas(
                self.session_keys['session_key'],
                self.client_nonce,
                self.server_nonce
            )
            
            # Show SAS
            print(f"\n🔐 SAS: {' '.join(self.sas['words'][:3])}")
            if self.verbose:
                print(f"    Hex: {self.sas['hex'][:16]}...")
            
            print("\n⚠️  Verify SAS matches sender (yes/no): ", end='', flush=True)
            user_input = input().strip().lower()
            
            if user_input not in ['yes', 'y']:
                print("✗ Transfer aborted")
                error_msg = ProtocolMessage.pack_error(
                    PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                    ErrorCode.PAKE_FAIL
                )
                conn.send(error_msg)
                self.record_failed_attempt(client_ip)
                return False
            
            self.log("Key confirmation...")
            kconfirm_data = self.recv_exact(conn, 19)
            _, _, client_mac = ProtocolMessage.unpack_kconfirm(kconfirm_data)
            
            expected_client_mac = SessionKeyDerivation.compute_kconfirm_mac(
                self.session_keys['k_confirm'],
                self.client_nonce, self.server_nonce,
                is_client=True
            )
            
            import hmac
            if not hmac.compare_digest(client_mac, expected_client_mac):
                print("✗ Key confirmation failed")
                error_msg = ProtocolMessage.pack_error(
                    PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                    ErrorCode.KCONFIRM_FAIL
                )
                conn.send(error_msg)
                self.record_failed_attempt(client_ip)
                return False
            
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
            
            print("✓ Secure channel established\n")
            
            self.aead_cipher = AEADCipher(self.session_keys['aead_key'])
            
            if client_ip in self.failed_attempts:
                del self.failed_attempts[client_ip]
            
            return True
            
        except Exception as e:
            print(f"✗ Handshake failed: {e}")
            self.record_failed_attempt(client_ip)
            if self.verbose:
                import traceback
                traceback.print_exc()
            return False
    
    def receive_files(self, conn):
        try:
            self.log("Receiving file list...")
            list_header = self.recv_exact(conn, 7)
            msg_type, major, minor, file_count = struct.unpack('!BBBI', list_header)
            
            if msg_type != MessageType.FILE_LIST:
                return False
            
            file_entries = []
            for _ in range(file_count):
                name_len_data = self.recv_exact(conn, 2)
                name_len = struct.unpack('!H', name_len_data)[0]
                
                if name_len > MAX_FILENAME_LENGTH:
                    return False
                
                name_bytes = self.recv_exact(conn, name_len)
                size_data = self.recv_exact(conn, 8)
                
                filename = name_bytes.decode('utf-8')
                size = struct.unpack('!Q', size_data)[0]
                file_entries.append((filename, size))
            
            total_files = len(file_entries)
            total_size = sum(s for _, s in file_entries)
            
            print(f"📥 Receiving {total_files} file(s) ({total_size / (1024*1024):.1f} MB)")
            
            sanitized_entries = []
            for filename, size in file_entries:
                try:
                    safe_name = self.sanitize_filename(filename)
                    sanitized_entries.append((safe_name, size))
                except ValueError as e:
                    print(f"✗ Invalid filename: {e}")
                    return False
            
            ack = ProtocolMessage.pack_file_list_ack(
                PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR
            )
            conn.send(ack)
            
            success_count = 0
            overall_start = time.time()
            
            for idx, (filename, file_size) in enumerate(sanitized_entries):
                print(f"\n[{idx+1}/{total_files}] {filename}")
                
                if self._receive_single_file(conn, filename, file_size):
                    success_count += 1
                else:
                    print(f"✗ Failed")
                    break
                
                if idx < total_files - 1:
                    self.aead_cipher.reset_counter()
                    next_msg = ProtocolMessage.pack_next_file(
                        PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                        idx + 1
                    )
                    conn.send(next_msg)
            
            all_success = (success_count == total_files)
            result_msg = ProtocolMessage.pack_transfer_result(
                PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
                all_success
            )
            conn.send(result_msg)
            
            overall_elapsed = time.time() - overall_start
            overall_speed = (total_size / overall_elapsed) / (1024*1024) if overall_elapsed > 0 else 0
            
            if all_success:
                print(f"\n✅ Transfer complete ({overall_speed:.1f} MB/s)")
            else:
                print(f"\n⚠️  Partial transfer: {success_count}/{total_files} files")
            
            return all_success
            
        except Exception as e:
            print(f"✗ Transfer failed: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()
            return False
    
    def _receive_single_file(self, conn, filename, file_size):
        meta_header = self.recv_exact(conn, 5)
        msg_type, major, minor, filename_len = struct.unpack('!BBBH', meta_header)
        
        if msg_type != MessageType.FILE_META or filename_len > MAX_FILENAME_LENGTH:
            return False
        
        filename_bytes = self.recv_exact(conn, filename_len)
        file_size_bytes = self.recv_exact(conn, 8)
        
        save_path = self.save_dir / filename
        received = 0
        sequence = 0
        file_hasher = hashlib.sha256()
        
        print(f"   Receiving... 0%", end='', flush=True)
        
        with open(save_path, 'wb') as f:
            while received < file_size:
                sequence += 1
                
                try:
                    chunk_header = self.recv_exact(conn, 13)
                except ConnectionError:
                    if received >= file_size:
                        break
                    else:
                        raise
                
                msg_type, major, minor, seq, ct_len = struct.unpack('!BBBQH', chunk_header)
                
                if msg_type != MessageType.FILE_CHUNK or ct_len > MAX_CHUNK_SIZE or ct_len == 0:
                    if save_path.exists():
                        os.remove(save_path)
                    return False
                
                ciphertext = self.recv_exact(conn, ct_len)
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
                    print(f"\r   Receiving... {progress:.0f}%", end='', flush=True)
                    
                except Exception as e:
                    self.log(f"Decrypt failed: {e}")
                    if save_path.exists():
                        os.remove(save_path)
                    return False
        
        file_end_data = self.recv_exact(conn, 43)
        _, _, final_seq, sender_hash = ProtocolMessage.unpack_file_end(file_end_data)
        
        calculated_hash = file_hasher.digest()
        
        import hmac
        if hmac.compare_digest(calculated_hash, sender_hash):
            print(f"\r   ✓ Received ({file_size / (1024*1024):.1f} MB)")
            return True
        else:
            print(f"\r   ✗ Hash mismatch")
            if save_path.exists():
                os.remove(save_path)
            return False
    
    def start(self, console):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', self.port))
        server.listen(1)
        server.settimeout(300)
        
        local_ip = self.get_local_ip()
        
        print(f"\n{'='*50}")
        print(f"SecureDrop Receiver v1.0")
        print(f"{'='*50}")
        print(f"\n🔑 Pairing Code: {self.pairing_code}")
        print(f"\n📱 Sender command:")
        print(f"   python sender.py {local_ip} {self.pairing_code} <files>")
        print(f"\n📂 Save: {self.save_dir.absolute()}")
        print(f"🌐 Listening: {local_ip}:{self.port}")
        if self.verbose:
            print(f"📊 Verbose mode enabled")
        print(f"\n⏳ Waiting for connection...\n")
        
        conn = None
        try:
            conn, addr = server.accept()
            conn.settimeout(300)
            client_ip = addr[0]
            print(f"✓ Connected: {client_ip}\n")
            
            if not self.handshake(conn, client_ip):
                if conn:
                    conn.close()
                return
            
            success = self.receive_files(conn)
            
        except socket.timeout:
            print("✗ Connection timeout")
        except KeyboardInterrupt:
            print("\n\n⚠️  Cancelled")
        except Exception as e:
            print(f"✗ Error: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()
        finally:
            if conn:
                conn.close()
            server.close()

if __name__ == "__main__":
    import sys
    
    port = 5000
    verbose = False
    
    if "--verbose" in sys.argv or "-v" in sys.argv:
        verbose = True
    
    if "--port" in sys.argv:
        idx = sys.argv.index("--port")
        port = int(sys.argv[idx + 1])
    
    receiver = SecureReceiver(port=port, verbose=verbose)
    receiver.start(console)