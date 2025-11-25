"""
Protocol message types, framing, and constants.
Implements wire-format specification for SecureDrop v1.0
UPDATED: Added multi-file transfer support
"""

import struct
from enum import IntEnum

# Protocol version
PROTOCOL_VERSION_MAJOR = 0x01
PROTOCOL_VERSION_MINOR = 0x00

# Maximum message sizes for DoS protection
MAX_FILENAME_LENGTH = 4096
MAX_PAKE_PAYLOAD = 8192
MAX_CHUNK_SIZE = 1048576
MAX_FILE_SIZE = 10 * 1024 * 1024 * 1024
MAX_FILE_LIST_SIZE = 10000  # Maximum files per transfer

class MessageType(IntEnum):
    """Message type identifiers (1 byte)"""
    HELLO = 0x01
    HELLO_ACK = 0x02
    PAKE_INIT = 0x03
    PAKE_REPLY = 0x04
    DH_PUB = 0x05
    KCONFIRM = 0x06
    KCONFIRM_ACK = 0x07
    FILE_META = 0x10
    FILE_CHUNK = 0x11
    FILE_END = 0x12
    TRANSFER_RESULT = 0x13
    FILE_LIST = 0x14        # NEW: List of files to transfer
    FILE_LIST_ACK = 0x15    # NEW: Acknowledge file list
    NEXT_FILE = 0x16        # NEW: Ready for next file
    ERROR = 0xFF

class ErrorCode(IntEnum):
    """Error codes for ERROR messages"""
    PROTOCOL_MISMATCH = 0x01
    PAKE_FAIL = 0x02
    KCONFIRM_FAIL = 0x03
    AEAD_FAIL = 0x04
    FILE_CORRUPT = 0x05
    RATE_LIMIT = 0x06

class RoleID(IntEnum):
    """Peer role identifiers"""
    SENDER = 0x01
    RECEIVER = 0x02

class ProtocolMessage:
    """Base class for protocol messages with framing"""
    
    @staticmethod
    def pack_hello(version_major, version_minor, nonce):
        """Pack HELLO message. Format: [1B type][2B version][16B nonce]"""
        if len(nonce) != 16:
            raise ValueError("Nonce must be 16 bytes")
        return struct.pack('!BBB16s', MessageType.HELLO, version_major, version_minor, nonce)
    
    @staticmethod
    def unpack_hello(data):
        """Unpack HELLO message, return (major, minor, nonce)"""
        if len(data) < 19:
            raise ValueError("HELLO message too short")
        msg_type, major, minor, nonce = struct.unpack('!BBB16s', data[:19])
        if msg_type != MessageType.HELLO:
            raise ValueError(f"Expected HELLO, got {msg_type}")
        return major, minor, nonce
    
    @staticmethod
    def pack_hello_ack(version_major, version_minor, nonce):
        """Pack HELLO_ACK message. Format: [1B type][2B version][16B nonce]"""
        if len(nonce) != 16:
            raise ValueError("Nonce must be 16 bytes")
        return struct.pack('!BBB16s', MessageType.HELLO_ACK, version_major, version_minor, nonce)
    
    @staticmethod
    def unpack_hello_ack(data):
        """Unpack HELLO_ACK, return (major, minor, nonce)"""
        if len(data) < 19:
            raise ValueError("HELLO_ACK message too short")
        msg_type, major, minor, nonce = struct.unpack('!BBB16s', data[:19])
        if msg_type != MessageType.HELLO_ACK:
            raise ValueError(f"Expected HELLO_ACK, got {msg_type}")
        return major, minor, nonce
    
    @staticmethod
    def pack_pake_init(version_major, version_minor, pake_payload):
        """Pack PAKE_INIT message. Format: [1B type][2B version][2B len][payload]"""
        payload_len = len(pake_payload)
        if payload_len > MAX_PAKE_PAYLOAD:
            raise ValueError(f"PAKE payload too large: {payload_len} (max: {MAX_PAKE_PAYLOAD})")
        if payload_len == 0:
            raise ValueError("PAKE payload cannot be empty")
        return struct.pack(f'!BBBH{payload_len}s', MessageType.PAKE_INIT, version_major, 
                          version_minor, payload_len, pake_payload)
    
    @staticmethod
    def unpack_pake_init(data):
        """Unpack PAKE_INIT, return (major, minor, payload)"""
        if len(data) < 5:
            raise ValueError("PAKE_INIT message too short")
        msg_type, major, minor, payload_len = struct.unpack('!BBBH', data[:5])
        if msg_type != MessageType.PAKE_INIT:
            raise ValueError(f"Expected PAKE_INIT, got {msg_type}")
        if payload_len > MAX_PAKE_PAYLOAD:
            raise ValueError(f"PAKE payload too large: {payload_len}")
        if len(data) < 5 + payload_len:
            raise ValueError("PAKE_INIT payload incomplete")
        payload = data[5:5+payload_len]
        return major, minor, payload
    
    @staticmethod
    def pack_pake_reply(version_major, version_minor, pake_payload):
        """Pack PAKE_REPLY message. Format: [1B type][2B version][2B len][payload]"""
        payload_len = len(pake_payload)
        if payload_len > MAX_PAKE_PAYLOAD:
            raise ValueError(f"PAKE payload too large: {payload_len} (max: {MAX_PAKE_PAYLOAD})")
        if payload_len == 0:
            raise ValueError("PAKE payload cannot be empty")
        return struct.pack(f'!BBBH{payload_len}s', MessageType.PAKE_REPLY, version_major,
                          version_minor, payload_len, pake_payload)
    
    @staticmethod
    def unpack_pake_reply(data):
        """Unpack PAKE_REPLY, return (major, minor, payload)"""
        if len(data) < 5:
            raise ValueError("PAKE_REPLY message too short")
        msg_type, major, minor, payload_len = struct.unpack('!BBBH', data[:5])
        if msg_type != MessageType.PAKE_REPLY:
            raise ValueError(f"Expected PAKE_REPLY, got {msg_type}")
        if payload_len > MAX_PAKE_PAYLOAD:
            raise ValueError(f"PAKE payload too large: {payload_len}")
        if len(data) < 5 + payload_len:
            raise ValueError("PAKE_REPLY payload incomplete")
        payload = data[5:5+payload_len]
        return major, minor, payload
    
    @staticmethod
    def pack_dh_pub(version_major, version_minor, role_id, public_key):
        """Pack DH_PUB message. Format: [1B type][2B version][1B role][32B pubkey]"""
        if len(public_key) != 32:
            raise ValueError("X25519 public key must be 32 bytes")
        return struct.pack('!BBBB32s', MessageType.DH_PUB, version_major, version_minor,
                          role_id, public_key)
    
    @staticmethod
    def unpack_dh_pub(data):
        """Unpack DH_PUB, return (major, minor, role_id, pubkey)"""
        if len(data) < 36:
            raise ValueError("DH_PUB message too short")
        msg_type, major, minor, role_id, pubkey = struct.unpack('!BBBB32s', data[:36])
        if msg_type != MessageType.DH_PUB:
            raise ValueError(f"Expected DH_PUB, got {msg_type}")
        return major, minor, role_id, pubkey
    
    @staticmethod
    def pack_kconfirm(version_major, version_minor, mac):
        """Pack KCONFIRM message. Format: [1B type][2B version][16B mac]"""
        if len(mac) != 16:
            raise ValueError("MAC must be 16 bytes")
        return struct.pack('!BBB16s', MessageType.KCONFIRM, version_major, version_minor, mac)
    
    @staticmethod
    def unpack_kconfirm(data):
        """Unpack KCONFIRM, return (major, minor, mac)"""
        if len(data) < 19:
            raise ValueError("KCONFIRM message too short")
        msg_type, major, minor, mac = struct.unpack('!BBB16s', data[:19])
        if msg_type != MessageType.KCONFIRM:
            raise ValueError(f"Expected KCONFIRM, got {msg_type}")
        return major, minor, mac
    
    @staticmethod
    def pack_kconfirm_ack(version_major, version_minor, mac):
        """Pack KCONFIRM_ACK message"""
        if len(mac) != 16:
            raise ValueError("MAC must be 16 bytes")
        return struct.pack('!BBB16s', MessageType.KCONFIRM_ACK, version_major, version_minor, mac)
    
    @staticmethod
    def unpack_kconfirm_ack(data):
        """Unpack KCONFIRM_ACK, return (major, minor, mac)"""
        if len(data) < 19:
            raise ValueError("KCONFIRM_ACK message too short")
        msg_type, major, minor, mac = struct.unpack('!BBB16s', data[:19])
        if msg_type != MessageType.KCONFIRM_ACK:
            raise ValueError(f"Expected KCONFIRM_ACK, got {msg_type}")
        return major, minor, mac
    
    @staticmethod
    def pack_file_list(version_major, version_minor, file_entries):
        """
        Pack FILE_LIST message.
        Format: [1B type][2B version][4B count][entries]
        Entry: [2B name_len][name][8B size]
        """
        file_count = len(file_entries)
        if file_count > MAX_FILE_LIST_SIZE:
            raise ValueError(f"Too many files: {file_count} (max: {MAX_FILE_LIST_SIZE})")
        if file_count == 0:
            raise ValueError("File list cannot be empty")
        
        data = struct.pack('!BBBI', MessageType.FILE_LIST, version_major, version_minor, file_count)
        
        for filename, size in file_entries:
            name_bytes = filename.encode('utf-8')
            name_len = len(name_bytes)
            if name_len > MAX_FILENAME_LENGTH:
                raise ValueError(f"Filename too long: {name_len}")
            if size > MAX_FILE_SIZE:
                raise ValueError(f"File too large: {size}")
            data += struct.pack(f'!H{name_len}sQ', name_len, name_bytes, size)
        
        return data
    
    @staticmethod
    def unpack_file_list(data):
        """Unpack FILE_LIST, return (major, minor, file_entries)"""
        if len(data) < 7:
            raise ValueError("FILE_LIST message too short")
        msg_type, major, minor, count = struct.unpack('!BBBI', data[:7])
        if msg_type != MessageType.FILE_LIST:
            raise ValueError(f"Expected FILE_LIST, got {msg_type}")
        if count > MAX_FILE_LIST_SIZE:
            raise ValueError(f"Too many files: {count}")
        
        entries = []
        offset = 7
        for _ in range(count):
            if offset + 2 > len(data):
                raise ValueError("FILE_LIST entry incomplete")
            name_len = struct.unpack('!H', data[offset:offset+2])[0]
            offset += 2
            
            if name_len > MAX_FILENAME_LENGTH:
                raise ValueError(f"Filename too long: {name_len}")
            if offset + name_len + 8 > len(data):
                raise ValueError("FILE_LIST entry incomplete")
            
            name_bytes = data[offset:offset+name_len]
            offset += name_len
            size = struct.unpack('!Q', data[offset:offset+8])[0]
            offset += 8
            
            if size > MAX_FILE_SIZE:
                raise ValueError(f"File size too large: {size}")
            
            entries.append((name_bytes.decode('utf-8'), size))
        
        return major, minor, entries
    
    @staticmethod
    def pack_file_list_ack(version_major, version_minor):
        """Pack FILE_LIST_ACK message. Format: [1B type][2B version][1B status]"""
        return struct.pack('!BBBB', MessageType.FILE_LIST_ACK, version_major, version_minor, 0x01)
    
    @staticmethod
    def unpack_file_list_ack(data):
        """Unpack FILE_LIST_ACK, return (major, minor, status)"""
        if len(data) < 4:
            raise ValueError("FILE_LIST_ACK message too short")
        msg_type, major, minor, status = struct.unpack('!BBBB', data[:4])
        if msg_type != MessageType.FILE_LIST_ACK:
            raise ValueError(f"Expected FILE_LIST_ACK, got {msg_type}")
        return major, minor, status
    
    @staticmethod
    def pack_next_file(version_major, version_minor, file_index):
        """Pack NEXT_FILE message. Format: [1B type][2B version][4B index]"""
        return struct.pack('!BBBI', MessageType.NEXT_FILE, version_major, version_minor, file_index)
    
    @staticmethod
    def unpack_next_file(data):
        """Unpack NEXT_FILE, return (major, minor, file_index)"""
        if len(data) < 7:
            raise ValueError("NEXT_FILE message too short")
        msg_type, major, minor, file_index = struct.unpack('!BBBI', data[:7])
        if msg_type != MessageType.NEXT_FILE:
            raise ValueError(f"Expected NEXT_FILE, got {msg_type}")
        return major, minor, file_index
    
    @staticmethod
    def pack_file_meta(version_major, version_minor, filename, file_size):
        """Pack FILE_META message. Format: [1B type][2B version][2B filename_len][filename][8B size]"""
        filename_bytes = filename.encode('utf-8')
        filename_len = len(filename_bytes)
        
        if filename_len > MAX_FILENAME_LENGTH:
            raise ValueError(f"Filename too long: {filename_len} (max: {MAX_FILENAME_LENGTH})")
        if filename_len > 65535:
            raise ValueError("Filename too long for protocol (max 65535 bytes)")
        if filename_len == 0:
            raise ValueError("Filename cannot be empty")
        if file_size > MAX_FILE_SIZE:
            raise ValueError(f"File too large: {file_size} (max: {MAX_FILE_SIZE})")
        if file_size == 0:
            raise ValueError("File size cannot be zero")
        
        return struct.pack(f'!BBBH{filename_len}sQ', MessageType.FILE_META, version_major,
                          version_minor, filename_len, filename_bytes, file_size)
    
    @staticmethod
    def unpack_file_meta(data):
        """Unpack FILE_META, return (major, minor, filename, file_size)"""
        if len(data) < 5:
            raise ValueError("FILE_META message too short")
        msg_type, major, minor, filename_len = struct.unpack('!BBBH', data[:5])
        if msg_type != MessageType.FILE_META:
            raise ValueError(f"Expected FILE_META, got {msg_type}")
        if filename_len > MAX_FILENAME_LENGTH:
            raise ValueError(f"Filename too long: {filename_len}")
        if len(data) < 5 + filename_len + 8:
            raise ValueError("FILE_META message incomplete")
        
        filename_bytes = data[5:5+filename_len]
        filename = filename_bytes.decode('utf-8')
        file_size = struct.unpack('!Q', data[5+filename_len:5+filename_len+8])[0]
        
        if file_size > MAX_FILE_SIZE:
            raise ValueError(f"File size too large: {file_size}")
        if file_size == 0:
            raise ValueError("File size cannot be zero")
        
        return major, minor, filename, file_size
    
    @staticmethod
    def pack_file_chunk(version_major, version_minor, sequence, ciphertext):
        """Pack FILE_CHUNK message. Format: [1B type][2B version][8B seq][2B ctlen][ciphertext+tag]"""
        ct_len = len(ciphertext)
        
        if ct_len > MAX_CHUNK_SIZE:
            raise ValueError(f"Chunk too large: {ct_len} (max: {MAX_CHUNK_SIZE})")
        if ct_len == 0:
            raise ValueError("Ciphertext cannot be empty")
        if ct_len > 65535:
            raise ValueError("Ciphertext too large for protocol (max 65535 bytes)")
        
        return struct.pack(f'!BBBQH{ct_len}s', MessageType.FILE_CHUNK, version_major,
                          version_minor, sequence, ct_len, ciphertext)
    
    @staticmethod
    def unpack_file_chunk(data):
        """Unpack FILE_CHUNK, return (major, minor, sequence, ciphertext)"""
        if len(data) < 13:
            raise ValueError("FILE_CHUNK message too short")
        msg_type, major, minor, sequence, ct_len = struct.unpack('!BBBQH', data[:13])
        if msg_type != MessageType.FILE_CHUNK:
            raise ValueError(f"Expected FILE_CHUNK, got {msg_type}")
        if ct_len > MAX_CHUNK_SIZE:
            raise ValueError(f"Chunk size too large: {ct_len}")
        if ct_len == 0:
            raise ValueError("Chunk size cannot be zero")
        if len(data) < 13 + ct_len:
            raise ValueError("FILE_CHUNK ciphertext incomplete")
        
        ciphertext = data[13:13+ct_len]
        return major, minor, sequence, ciphertext
    
    @staticmethod
    def pack_file_end(version_major, version_minor, final_seq, file_hash):
        """Pack FILE_END message. Format: [1B type][2B version][8B final_seq][32B hash]"""
        if len(file_hash) != 32:
            raise ValueError("File hash must be 32 bytes (SHA-256)")
        return struct.pack('!BBBQ32s', MessageType.FILE_END, version_major, version_minor,
                          final_seq, file_hash)
    
    @staticmethod
    def unpack_file_end(data):
        """Unpack FILE_END, return (major, minor, final_seq, file_hash)"""
        if len(data) < 43:
            raise ValueError("FILE_END message too short")
        msg_type, major, minor, final_seq, file_hash = struct.unpack('!BBBQ32s', data[:43])
        if msg_type != MessageType.FILE_END:
            raise ValueError(f"Expected FILE_END, got {msg_type}")
        return major, minor, final_seq, file_hash
    
    @staticmethod
    def pack_transfer_result(version_major, version_minor, success):
        """Pack TRANSFER_RESULT message. Format: [1B type][2B version][1B result]"""
        result_code = 0x01 if success else 0x00
        return struct.pack('!BBBB', MessageType.TRANSFER_RESULT, version_major, version_minor, result_code)
    
    @staticmethod
    def unpack_transfer_result(data):
        """Unpack TRANSFER_RESULT, return (major, minor, success)"""
        if len(data) < 4:
            raise ValueError("TRANSFER_RESULT message too short")
        msg_type, major, minor, result_code = struct.unpack('!BBBB', data[:4])
        if msg_type != MessageType.TRANSFER_RESULT:
            raise ValueError(f"Expected TRANSFER_RESULT, got {msg_type}")
        return major, minor, (result_code == 0x01)
    
    @staticmethod
    def pack_error(version_major, version_minor, error_code):
        """Pack ERROR message. Format: [1B type][2B version][1B error_code]"""
        return struct.pack('!BBBB', MessageType.ERROR, version_major, version_minor, error_code)
    
    @staticmethod
    def unpack_error(data):
        """Unpack ERROR, return (major, minor, error_code)"""
        if len(data) < 4:
            raise ValueError("ERROR message too short")
        msg_type, major, minor, error_code = struct.unpack('!BBBB', data[:4])
        if msg_type != MessageType.ERROR:
            raise ValueError(f"Expected ERROR, got {msg_type}")
        return major, minor, error_code

def generate_nonce():
    """Generate cryptographically secure 16-byte nonce"""
    import os
    return os.urandom(16)

def check_version_compatible(their_major, their_minor):
    """Check if peer's version is compatible with ours"""
    if their_major != PROTOCOL_VERSION_MAJOR:
        return False
    return True