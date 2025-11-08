import socket
import os
import struct
import hashlib
import time
import sys
from pathlib import Path

class FileSender:
    def __init__(self, receiver_ip, auth_code, receiver_port=5000):
        self.receiver_ip = receiver_ip
        self.receiver_port = receiver_port
        self.auth_code = auth_code  

    def send_file(self, file_path):

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

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.receiver_ip, self.receiver_port))
            print(" ✓ Connected")

            auth_response = sock.recv(1024).decode('utf-8')

            if auth_response != "AUTH_REQUIRED":
                print("✗ Protocol error: Expected authentication request")
                return False

            print("🔐 Sending authentication code...", end='', flush=True)
            sock.send(self.auth_code.encode('utf-8'))
            
            auth_result = sock.recv(1024).decode('utf-8').strip()
            
            if auth_result == "1":
                print(" ✓ Authentication successful")
            else:
                print(f" ✗ Authentication failed.")
                while True:
                    retry_code = input("Enter code again (or 'q' to quit): ").strip()
                    if retry_code.lower() == 'q':
                        sock.close()
                        return False
                    sock.send(retry_code.encode('utf-8'))
                    auth_result = sock.recv(1024).decode('utf-8').strip()
                    if auth_result == "1":
                        print(" ✓ Authentication successful")
                        break
                    elif auth_result == "0":
                        print(" ✗ Too many failed attempts. Connection closed.")
                        sock.close()
                        return False
                    else:
                        print(" ✗ Wrong code. Try again.")

            filename_bytes = filename.encode('utf-8')
            sock.send(struct.pack('!I', len(filename_bytes)))
            sock.send(filename_bytes)

            sock.send(struct.pack('!Q', file_size))

            sent = 0
            chunk_size = 1024 * 1024
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
                    progress = (sent / file_size) * 100
                    elapsed = time.time() - start_time
                    if elapsed > 0:
                        speed = (sent / elapsed) / (1024*1024)
                        print(f"\rSending... {progress:.1f}% | Speed: {speed:.2f} MB/s", end='', flush=True)

            file_hash = hasher.digest()
            sock.send(file_hash)

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

    if len(sys.argv) != 4:  
        print("\nUsage: python sender.py <receiver_ip> <auth_code> <file_path>")
        print("Example: python sender.py 192.168.1.5 A1B2C3 document.pdf")
        sys.exit(1)

    receiver_ip = sys.argv[1]
    auth_code = sys.argv[2]  
    file_path = sys.argv[3]

    sender = FileSender(receiver_ip, auth_code)
    sender.send_file(file_path)