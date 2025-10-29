import socket
import os
import struct
import hashlib
from pathlib import Path

class FileReceiver:
    def __init__(self, port=5000, save_dir="received_files"):
        self.port = port
        self.save_dir = Path(save_dir)
        self.save_dir.mkdir(exist_ok=True)
        
    def get_local_ip(self):
        """Get the local IP address of this device"""
        try:
            # Create a socket to find local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))  # Doesn't actually connect
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    
    def receive_file(self):
        """Start listening for incoming file transfers"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', self.port))
        server.listen(1)
        
        local_ip = self.get_local_ip()
        print(f"\n{'='*60}")
        print(f"SecureDrop Receiver Started")
        print(f"{'='*60}")
        print(f"Listening on: {local_ip}:{self.port}")
        print(f"Files will be saved to: {self.save_dir.absolute()}")
        print(f"Waiting for connection...\n")
        
        try:
            conn, addr = server.accept()
            print(f"✓ Connected to sender: {addr[0]}")
            
            # Receive filename length and filename
            filename_len = struct.unpack('!I', conn.recv(4))[0]
            filename = conn.recv(filename_len).decode('utf-8')
            print(f"✓ Receiving file: {filename}")
            
            # Receive file size
            file_size = struct.unpack('!Q', conn.recv(8))[0]
            print(f"✓ File size: {file_size / (1024*1024):.2f} MB")
            
            # Prepare to receive file
            save_path = self.save_dir / filename
            received = 0
            chunk_size = 1024 * 1024  # 1MB chunks
            hasher = hashlib.sha256()
            
            with open(save_path, 'wb') as f:
                print(f"\nReceiving... 0%", end='', flush=True)
                
                while received < file_size:
                    # Receive chunk
                    remaining = file_size - received
                    to_receive = min(chunk_size, remaining)
                    chunk = conn.recv(to_receive)
                    
                    if not chunk:
                        break
                    
                    f.write(chunk)
                    hasher.update(chunk)
                    received += len(chunk)
                    
                    # Progress update
                    progress = (received / file_size) * 100
                    speed_mb = (received / (1024*1024))
                    print(f"\rReceiving... {progress:.1f}% ({speed_mb:.2f}MB received)", 
                          end='', flush=True)
            
            # Receive sender's hash
            sender_hash = conn.recv(32)
            calculated_hash = hasher.digest()
            
            print(f"\n\n{'='*60}")
            if sender_hash == calculated_hash:
                print("✓ Transfer SUCCESSFUL - File integrity verified")
                print(f"✓ File saved: {save_path.absolute()}")
                conn.send(b"SUCCESS")
            else:
                print("✗ Transfer FAILED - File corrupted")
                print("✗ Hash mismatch detected")
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