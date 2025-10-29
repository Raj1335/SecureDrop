import socket
import os
import struct
import hashlib
import time
from pathlib import Path

class FileSender:
    def __init__(self, receiver_ip, receiver_port=5000):
        self.receiver_ip = receiver_ip
        self.receiver_port = receiver_port
        
    def send_file(self, file_path):
        """Send a file to the receiver"""
        file_path = Path(file_path)
        
        if not file_path.exists():
            print(f"✗ Error: File not found - {file_path}")
            return False
        
        file_size = file_path.stat().st_size
        filename = file_path.name
        
        print(f"\n{'='*60}")
        print(f"SecureDrop Sender")
        print(f"{'='*60}")
        print(f"File: {filename}")
        print(f"Size: {file_size / (1024*1024):.2f} MB")
        print(f"Receiver: {self.receiver_ip}:{self.receiver_port}")
        print(f"\nConnecting...", end='', flush=True)
        
        try:
            # Connect to receiver
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREApwdM)
            sock.connect((self.receiver_ip, self.receiver_port))
            print(" ✓ Connected")
            
            # Send filename
            filename_bytes = filename.encode('utf-8')
            sock.send(struct.pack('!I', len(filename_bytes)))
            sock.send(filename_bytes)
            
            # Send file size
            sock.send(struct.pack('!Q', file_size))
            
            # Send file in chunks
            sent = 0
            chunk_size = 1024 * 1024  # 1MB chunks
            hasher = hashlib.sha256()
            start_time = time.time()
            
            print(f"\nSending... 0%", end='', flush=True)
            
            with open(file_path, 'rb') as f:
                while sent < file_size:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    sock.sendall(chunk)
                    hasher.update(chunk)
                    sent += len(chunk)
                    
                    # Progress and speed calculation
                    progress = (sent / file_size) * 100
                    elapsed = time.time() - start_time
                    if elapsed > 0:
                        speed = (sent / elapsed) / (1024*1024)  # MB/s
                        print(f"\rSending... {progress:.1f}% | Speed: {speed:.2f} MB/s", 
                              end='', flush=True)
            
            # Send hash for verification
            file_hash = hasher.digest()
            sock.send(file_hash)
            
            # Wait for confirmation
            response = sock.recv(1024).decode('utf-8')
            
            elapsed = time.time() - start_time
            avg_speed = (file_size / elapsed) / (1024*1024)
            
            print(f"\n\n{'='*60}")
            if response == "SUCCESS":
                print("✓ Transfer SUCCESSFUL")
                print(f"✓ Time: {elapsed:.2f} seconds")
                print(f"✓ Average speed: {avg_speed:.2f} MB/s")
            else:
                print("✗ Transfer FAILED - Receiver reported error")
            print(f"{'='*60}\n")
            
            sock.close()
            return response == "SUCCESS"
            
        except ConnectionRefusedError:
            print(f"\n✗ Error: Could not connect to {self.receiver_ip}:{self.receiver_port}")
            print("  Make sure receiver is running and IP address is correct")
            return False
        except KeyboardInterrupt:
            print("\n\n✗ Transfer cancelled by user")
            return False
        except Exception as e:
            print(f"\n✗ Error: {e}")
            return False

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 3:
        print("\nUsage: python sender.py <receiver_ip> <file_path>")
        print("Example: python sender.py 192.168.1.5 document.pdf")
        sys.exit(1)
    
    receiver_ip = sys.argv[1]
    file_path = sys.argv[2]
    
    sender = FileSender(receiver_ip)
    sender.send_file(file_path)