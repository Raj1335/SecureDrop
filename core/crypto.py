"""
Cryptographic primitives: X25519, HKDF, ChaCha20-Poly1305 AEAD.
Implements key derivation and authenticated encryption.
"""

import os
import hashlib
import hmac
import struct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

class EphemeralDH:
    """X25519 ephemeral Diffie-Hellman key exchange"""
    
    def __init__(self):
        """Generate ephemeral keypair"""
        self.private_key = X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
    
    def get_public_bytes(self):
        """Export public key as 32 bytes"""
        from cryptography.hazmat.primitives import serialization
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def derive_shared_secret(self, peer_public_bytes):
        """
        Perform DH exchange with peer's public key.
        
        Args:
            peer_public_bytes: 32-byte peer public key
            
        Returns:
            32-byte shared secret
        """
        if len(peer_public_bytes) != 32:
            raise ValueError("Peer public key must be 32 bytes")
        
        peer_public_key = X25519PublicKey.from_public_bytes(peer_public_bytes)
        shared_secret = self.private_key.exchange(peer_public_key)
        return shared_secret

class SessionKeyDerivation:
    """
    Derive session keys from PAKE output + ephemeral DH.
    Uses HKDF-SHA256 per specification.
    """
    
    @staticmethod
    def derive_session_keys(k_pake, dh_secret, client_nonce, server_nonce, role_id):
        """
        Derive all session keys using HKDF.
        
        Args:
            k_pake: 32-byte PAKE shared secret
            dh_secret: 32-byte DH shared secret
            client_nonce: 16-byte client nonce
            server_nonce: 16-byte server nonce
            role_id: RoleID.SENDER or RoleID.RECEIVER
            
        Returns:
            dict with keys: session_key, k_confirm, aead_key, nonce_seed
        """
        # FIXED: Use consistent ordering for both parties
        # Combine input material - same order regardless of role
        ikm_data = b'\x00' + k_pake + dh_secret + client_nonce + server_nonce
        ikm = hashlib.sha256(ikm_data).digest()
        
        # Salt for HKDF - consistent ordering
        version_bytes = b'\x01\x00'  # Version 1.0
        salt_data = client_nonce + server_nonce + version_bytes
        salt = hashlib.sha256(salt_data).digest()
        
        # HKDF-Extract
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=None
        )
        prk = hkdf.derive(ikm)
        
        # HKDF-Expand for each key - FIXED: Remove role from session key derivation
        # SessionKey (32 bytes) - same for both parties
        session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"session_key" + version_bytes  # Removed role byte
        ).derive(ikm)
        
        # K_confirm (32 bytes) - same for both parties  
        k_confirm = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"confirm_key" + version_bytes
        ).derive(ikm)
        
        # AEAD key (32 bytes) - same for both parties
        aead_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"aead_key" + version_bytes
        ).derive(ikm)
        
        # Nonce seed (12 bytes) - same for both parties
        nonce_seed = HKDF(
            algorithm=hashes.SHA256(),
            length=12,
            salt=salt,
            info=b"nonce_seed" + version_bytes
        ).derive(ikm)
        
        return {
            'session_key': session_key,
            'k_confirm': k_confirm,
            'aead_key': aead_key,
            'nonce_seed': nonce_seed
        }
    
    @staticmethod
    def compute_kconfirm_mac(k_confirm, client_nonce, server_nonce, is_client):
        """
        Compute key confirmation HMAC.
        
        Args:
            k_confirm: 32-byte confirmation key
            client_nonce: 16-byte client nonce
            server_nonce: 16-byte server nonce
            is_client: True if computing client MAC, False for server
            
        Returns:
            16-byte MAC (truncated HMAC-SHA256)
        """
        # FIXED: Consistent label ordering
        label = b"CLIENT" if is_client else b"SERVER"
        # Consistent data ordering
        data = label + client_nonce + server_nonce
        
        mac = hmac.new(k_confirm, data, hashlib.sha256).digest()
        return mac[:16]  # First 16 bytes

class AEADCipher:
    """ChaCha20-Poly1305 AEAD encryption"""
    
    def __init__(self, key):
        """
        Initialize AEAD cipher.
        
        Args:
            key: 32-byte encryption key
        """
        if len(key) != 32:
            raise ValueError("AEAD key must be 32 bytes")
        self.cipher = ChaCha20Poly1305(key)
        self.counter = 0
    
    def make_nonce(self, sequence_number=None):
        """
        Create 12-byte nonce from counter or sequence number.
        
        Args:
            sequence_number: Optional explicit sequence number
            
        Returns:
            12-byte nonce
        """
        if sequence_number is None:
            sequence_number = self.counter
            self.counter += 1
        
        # Encode as 12-byte big-endian
        # High 4 bytes = 0, low 8 bytes = sequence
        nonce = sequence_number.to_bytes(12, byteorder='big')
        return nonce
    
    def encrypt(self, plaintext, associated_data, sequence_number=None):
        """
        Encrypt plaintext with AEAD.
        
        Args:
            plaintext: Data to encrypt
            associated_data: Authenticated but unencrypted metadata
            sequence_number: Optional sequence number for nonce
            
        Returns:
            (nonce, ciphertext_with_tag) tuple
        """
        nonce = self.make_nonce(sequence_number)
        ciphertext = self.cipher.encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext
    
    def decrypt(self, nonce, ciphertext, associated_data):
        """
        Decrypt ciphertext with AEAD.
        
        Args:
            nonce: 12-byte nonce used for encryption
            ciphertext: Ciphertext with 16-byte tag appended
            associated_data: Same AD used during encryption
            
        Returns:
            Plaintext bytes
            
        Raises:
            cryptography.exceptions.InvalidTag if authentication fails
        """
        plaintext = self.cipher.decrypt(nonce, ciphertext, associated_data)
        return plaintext
    
    def reset_counter(self):
        """Reset nonce counter (for new session)"""
        self.counter = 0

def create_associated_data(msg_type, version_major, version_minor, sequence, filename=""):
    """
    Create associated data for AEAD per spec.
    
    Args:
        msg_type: Message type byte
        version_major: Protocol version major
        version_minor: Protocol version minor
        sequence: Sequence number
        filename: Optional filename (for FILE_CHUNK)
        
    Returns:
        Bytes suitable for AEAD associated_data parameter
    """
    filename_bytes = filename.encode('utf-8') if filename else b""
    filename_len = len(filename_bytes)
    
    # Format: [1B type][2B version][8B seq][2B filename_len][filename]
    ad = struct.pack(
        f'!BBBQH{filename_len}s',
        msg_type,
        version_major,
        version_minor,
        sequence,
        filename_len,
        filename_bytes
    )
    return ad

def secure_zero(data):
    """
    Attempt to securely zero memory (best-effort in Python).
    
    Args:
        data: bytes or bytearray to zero
    """
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0
    # For bytes (immutable), we can't truly zero in Python
    # This is a limitation of the language