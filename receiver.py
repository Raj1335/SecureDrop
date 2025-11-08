import socket
import os
import struct
import hashlib
import random
import string
from pathlib import Path

class FileReceiver:
    def __init__(self, port=5000, save_dir="received_files"):
        print("getting port")
        self.port = port
        print("save dir")
        self.save_dir = Path(save_dir)
        self.save_dir.mkdir(exist_ok=True)
        print("generate code")
        self.auth_code = self.generate_auth_code()
        self.attempts_left = 3
        expected_code = self.auth_code

    def generate_auth_code(self):
        characters = string.ascii_uppercase + string.digits
        return ''.join(random.choice(characters) for _ in range(6))
    
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect("8.8.8.8", 80)
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
        
    def verify_auth_code(self, conn, expected_code):
        while self.attempts_left > 0:
            received_code = conn.recv(1024).decode('utf-8').strip()
            if received_code == expected_code:
                conn.send(b'1')
                return True
            else:
                self.attempts_left -= 1
                conn.send(b'2')
                if self.attempts_left == 0:
                    return False
        return False
   
    def receive_file(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", self.port))
        server.listen(1)

        local_ip = self.get_local_ip()

        print(f"\n{'='*60}")
        print(f"SecureDrop Receiver Started")
        print(f"{'='*60}")
        print(f"Authentication Code: {self.auth_code}") 
        print(f"Listening on: {local_ip}:{self.port}")
        print(f"Files will be saved to: {self.save_dir.absolute()}")
        print(f"Waiting for connection...\n")

        try:
            conn, addr = server.accept()
            print(f"✓ Connection from: {addr[0]}")

            print("🔐 Verifying authentication code...")
            conn.send(b"AUTH_REQUIRED")  
            
            if not self.verify_auth_code(conn, self.auth_code):
                print("✗ Authentication failed")
                conn.close()
                return
            
            print("✓ Authentication successful")
            
            filename_len = struct.unpack('!I', conn.recv(4))[0]
            filename = conn.recv(filename_len).decode('utf-8')
            

            file_size = struct.unpack('!Q', conn.recv(8))[0]
            print(f"✓ Receiving file: {filename}({file_size / (1024*1024):.2f} MB)")

            save_path = self.save_dir / filename
            received = 0
            chunk_size = 1024 * 1024
            hasher = hashlib.sha256()

            with open(save_path, 'wb') as f:
                print(f"\nReceiving... 0%", end='', flush=True)
                while received < file_size:
                    remaining = file_size - received
                    to_receive = min(chunk_size, remaining)
                    chunk = conn.recv(to_receive)
                    if not chunk:
                        break
                    f.write(chunk)
                    hasher.update(chunk)
                    received += len(chunk)
                    progress = (received / file_size) * 100
                    speed_mb = (received / (1024*1024))
                    print(f"\rReceiving... {progress:.1f}% ({speed_mb:.2f}MB received)", end='', flush=True)

            sender_hash = conn.recv(32)
            calculated_hash = hasher.digest()

            print(f"\n\n{'='*60}")
            if sender_hash == calculated_hash:
                print("✓ Transfer SUCCESSFUL - File integrity verified")
                print(f"✓ File saved: {save_path.absolute()}")
                conn.send(b"SUCCESS")
            else:
                print("✗ Transfer FAILED - File corrupted")
                conn.send(b"FAILED")
                os.remove(save_path)
            print(f"{'='*60}\n")

        except KeyboardInterrupt:
            print("\n\n✗ Transfer cancelled by user")
        except Exception as e:
            print(f"\n✗ Error: {e}")
        finally:
            conn.close()
            server.close()




if __name__ == "__main__":
    receiver = FileReceiver()
    receiver.receive_file()