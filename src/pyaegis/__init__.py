"""
Python bindings for libaegis - high-performance AEGIS authenticated encryption.

This module provides Pythonic interfaces to the AEGIS family of authenticated
encryption algorithms (AEGIS-128L, AEGIS-256, and their multi-lane variants).

Basic usage:
    >>> from pyaegis import Aegis128L
    >>> cipher = Aegis128L()
    >>> key = cipher.random_key()
    >>> nonce = cipher.random_nonce()
    >>> plaintext = b"Hello, World!"
    >>> ciphertext = cipher.encrypt(key, nonce, plaintext)
    >>> decrypted = cipher.decrypt(key, nonce, ciphertext)
    >>> assert decrypted == plaintext
"""

from .aegis import (
    Aegis128L,
    Aegis128X2,
    Aegis128X4,
    Aegis256,
    Aegis256X2,
    Aegis256X4,
    AegisError,
    AegisMac128L,
    AegisMac128X2,
    AegisMac128X4,
    AegisMac256,
    AegisMac256X2,
    AegisMac256X4,
    AegisStreamDecrypt128L,
    AegisStreamDecrypt128X2,
    AegisStreamDecrypt128X4,
    AegisStreamDecrypt256,
    AegisStreamDecrypt256X2,
    AegisStreamDecrypt256X4,
    AegisStreamEncrypt128L,
    AegisStreamEncrypt128X2,
    AegisStreamEncrypt128X4,
    AegisStreamEncrypt256,
    AegisStreamEncrypt256X2,
    AegisStreamEncrypt256X4,
    DecryptionError,
)

__version__ = "0.2.0"

__all__ = [
    "Aegis128L",
    "Aegis128X2",
    "Aegis128X4",
    "Aegis256",
    "Aegis256X2",
    "Aegis256X4",
    "AegisError",
    "AegisMac128L",
    "AegisMac128X2",
    "AegisMac128X4",
    "AegisMac256",
    "AegisMac256X2",
    "AegisMac256X4",
    "AegisStreamDecrypt128L",
    "AegisStreamDecrypt128X2",
    "AegisStreamDecrypt128X4",
    "AegisStreamDecrypt256",
    "AegisStreamDecrypt256X2",
    "AegisStreamDecrypt256X4",
    "AegisStreamEncrypt128L",
    "AegisStreamEncrypt128X2",
    "AegisStreamEncrypt128X4",
    "AegisStreamEncrypt256",
    "AegisStreamEncrypt256X2",
    "AegisStreamEncrypt256X4",
    "DecryptionError",
]
