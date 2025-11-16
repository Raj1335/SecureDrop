"""
Short Authentication String (SAS) generation.
Creates human-verifiable fingerprints for MITM detection.

SECURITY FIX: Added missing hmac import for constant-time comparison
"""

import hashlib
import hmac  # SECURITY FIX: Added missing import

# Diceware-style word list (2048 words for 11 bits each)
# Using simple, memorable words (shortened list for demo)
WORDLIST = [
    "alpha", "bravo", "charlie", "delta", "echo", "foxtrot",
    "golf", "hotel", "india", "juliet", "kilo", "lima",
    "mike", "november", "oscar", "papa", "quebec", "romeo",
    "sierra", "tango", "uniform", "victor", "whiskey", "xray",
    "yankee", "zulu", "able", "baker", "easy", "fox",
    "george", "king", "love", "nan", "oboe", "peter",
    "queen", "roger", "sugar", "uncle", "victor", "william",
    "apple", "banana", "cherry", "dragon", "eagle", "falcon",
    "grape", "horse", "igloo", "jacket", "knight", "lemon",
    "mango", "ninja", "ocean", "panda", "quartz", "rabbit",
    "snake", "tiger", "umbrella", "violet", "whale", "xerox",
    "yellow", "zebra", "anchor", "bridge", "castle", "diamond",
    "engine", "forest", "garden", "hammer", "island", "jungle",
    "kettle", "ladder", "mountain", "network", "orange", "palace",
    "quantum", "river", "sunset", "temple", "universe", "volcano",
    "window", "galaxy", "hockey", "iceberg", "jasmine", "kitten",
    "lizard", "mermaid", "narwhal", "orchid", "penguin", "quokka",
    "rainbow", "satellite", "tornado", "unicorn", "vampire", "wizard",
    # ... truncated for brevity, full list would have 2048 words
]

# Extend wordlist to 128 for demo (production needs 2048)
while len(WORDLIST) < 128:
    WORDLIST.append(f"word{len(WORDLIST)}")

class SASGenerator:
    """Generate and verify Short Authentication Strings"""
    
    @staticmethod
    def generate_sas(session_key, client_nonce, server_nonce, num_words=6):
        """
        Generate SAS from session key and nonces.
        
        Args:
            session_key: 32-byte session key
            client_nonce: 16-byte client nonce
            server_nonce: 16-byte server nonce
            num_words: Number of words to generate (default 6 for ~40 bits)
            
        Returns:
            dict with 'words' (list), 'hex' (string), 'decimal' (string)
        """
        # Compute SAS_raw = SHA256(SessionKey || "SAS v1" || nonces)
        sas_input = session_key + b"SAS v1" + client_nonce + server_nonce
        sas_raw = hashlib.sha256(sas_input).digest()
        
        # Generate word representation (6 words = ~40 bits)
        words = []
        for i in range(num_words):
            # Take 7 bits per word (128 words in list)
            byte_idx = i * 7 // 8
            bit_offset = (i * 7) % 8
            
            # Extract 7 bits
            if byte_idx + 1 < len(sas_raw):
                two_bytes = (sas_raw[byte_idx] << 8) | sas_raw[byte_idx + 1]
                index = (two_bytes >> (9 - bit_offset)) & 0x7F
            else:
                index = sas_raw[byte_idx] & 0x7F
            
            words.append(WORDLIST[index % len(WORDLIST)])
        
        # Generate hex representation (first 20 bytes = 40 hex chars)
        hex_repr = sas_raw[:20].hex().upper()
        
        # Generate decimal representation (first 8 digits)
        decimal_value = int.from_bytes(sas_raw[:4], 'big') % 100000000
        decimal_repr = f"{decimal_value:08d}"
        
        return {
            'words': words,
            'hex': hex_repr,
            'decimal': decimal_repr,
            'raw': sas_raw
        }
    
    @staticmethod
    def format_sas_display(sas_dict):
        """
        Format SAS for user display.
        
        Args:
            sas_dict: Dict from generate_sas()
            
        Returns:
            Formatted string for display
        """
        words_str = " - ".join(sas_dict['words'])
        hex_str = " ".join([sas_dict['hex'][i:i+4] for i in range(0, len(sas_dict['hex']), 4)])
        
        output = f"""
╔══════════════════════════════════════════════════════════╗
║          SHORT AUTHENTICATION STRING (SAS)               ║
╠══════════════════════════════════════════════════════════╣
║                                                          ║
║  Words:   {words_str:<50}║
║                                                          ║
║  Hex:     {hex_str:<50}║
║                                                          ║
║  Decimal: {sas_dict['decimal']:<50}║
║                                                          ║
╠══════════════════════════════════════════════════════════╣
║  ⚠️   Compare with peer - must match exactly!             ║
╚══════════════════════════════════════════════════════════╝
"""
        return output
    
    @staticmethod
    def verify_sas_match(sas1_raw, sas2_raw):
        """
        Verify two SAS values match using constant-time comparison.
        
        Args:
            sas1_raw: Raw SAS bytes from first party
            sas2_raw: Raw SAS bytes from second party
            
        Returns:
            True if match, False otherwise
        """
        # SECURITY FIX: Now hmac is properly imported at top of file
        # Constant-time comparison to prevent timing attacks
        return hmac.compare_digest(sas1_raw, sas2_raw)
    
    @staticmethod
    def get_sas_security_bits(num_words):
        """
        Calculate security bits for given number of words.
        
        Args:
            num_words: Number of words in SAS
            
        Returns:
            Approximate security bits
        """
        # With 128-word list: ~7 bits per word
        # With 2048-word list: ~11 bits per word
        bits_per_word = 7  # Current wordlist size
        return num_words * bits_per_word

def compare_sas_interactive(my_sas, peer_sas_input):
    """
    Interactive SAS comparison (for CLI).
    
    Args:
        my_sas: dict from generate_sas()
        peer_sas_input: User input (words, hex, or decimal)
        
    Returns:
        True if match, False otherwise
    """
    # Normalize input
    peer_input = peer_sas_input.strip().lower()
    
    # Try matching against different formats
    my_words = " ".join(my_sas['words']).lower()
    my_hex = my_sas['hex'].lower().replace(" ", "")
    my_decimal = my_sas['decimal']
    
    peer_normalized = peer_input.replace("-", " ").replace("  ", " ")
    
    if peer_normalized == my_words:
        return True
    if peer_input.replace(" ", "") == my_hex:
        return True
    if peer_input == my_decimal:
        return True
    
    return False