"""
SPAKE2 wrapper for password-authenticated key exchange.
Uses spake2 library with Curve25519.
"""

import spake2
import hashlib

class SPAKE2Exchange:
    """
    Wrapper for SPAKE2 protocol.
    Provides simple interface for two-party password authentication.
    """
    
    def __init__(self, password, side, idA=b"Sender", idB=b"Receiver"):
        """
        Initialize SPAKE2 exchange.
        
        Args:
            password: String or bytes, shared secret (6-digit code)
            side: "A" for initiator (sender), "B" for responder (receiver)
            idA: Identity for side A (optional)
            idB: Identity for side B (optional)
        """
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        self.password = password
        self.side = side
        self.idA = idA
        self.idB = idB
        
        # Create SPAKE2 instance
        self.spake = spake2.SPAKE2_A(password, idA=idA, idB=idB) if side == "A" \
                     else spake2.SPAKE2_B(password, idA=idA, idB=idB)
        
        self.shared_key = None
    
    def start(self):
        """
        Generate first SPAKE2 message (outbound).
        Returns bytes to send to peer.
        """
        return self.spake.start()
    
    def finish(self, peer_message):
        """
        Process peer's SPAKE2 message and derive shared key.
        
        Args:
            peer_message: Bytes received from peer
            
        Returns:
            32-byte shared key (K_pake)
        """
        key = self.spake.finish(peer_message)
        
        # Hash the key to get consistent 32-byte output
        # SPAKE2 library may return variable length
        self.shared_key = hashlib.sha256(key).digest()
        return self.shared_key
    
    def get_shared_key(self):
        """Return derived shared key (must call finish() first)"""
        if self.shared_key is None:
            raise RuntimeError("Must call finish() before getting shared key")
        return self.shared_key

def verify_password_strength(password):
    """
    Check if password meets minimum strength requirements.
    
    Args:
        password: String password to check
        
    Returns:
        (is_valid, message) tuple
    """
    if len(password) < 6:
        return False, "Password must be at least 6 characters"
    
    if len(password) == 6 and not password.isdigit():
        return False, "6-character passwords must be numeric"
    
    return True, "Password acceptable"

def generate_6digit_code():
    """
    Generate cryptographically secure 6-digit code.
    
    Returns:
        String of 6 decimal digits (000000-999999)
    """
    import os
    # Generate random number 0-999999
    random_bytes = os.urandom(4)
    random_int = int.from_bytes(random_bytes, 'big')
    code = random_int % 1000000
    return f"{code:06d}"