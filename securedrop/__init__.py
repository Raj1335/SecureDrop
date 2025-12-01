"""
SecureDrop - Secure P2P File Transfer
Version 1.0.0
"""

__version__ = "1.0.0"
__author__ = "Your Name"
__license__ = "MIT"

from .sender_module import SecureSender
from .receiver_module import SecureReceiver

__all__ = ["SecureSender", "SecureReceiver"]