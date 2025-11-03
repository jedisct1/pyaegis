# pyaegis

[![PyPI version](https://badge.fury.io/py/pyaegis.svg)](https://badge.fury.io/py/pyaegis)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/aegis-aead/pyaegis/blob/main/LICENSE)

Python bindings for libaegis - high-performance AEGIS authenticated encryption.

## Overview

pyaegis provides Pythonic interfaces to the AEGIS family of authenticated encryption algorithms.

AEGIS is a high-performance authenticated cipher that provides both confidentiality and authenticity guarantees.

### Supported Variants

#### Authenticated Encryption (AEAD)

- AEGIS-128L: 16-byte key, 16-byte nonce - optimized for performance
- AEGIS-256: 32-byte key, 32-byte nonce - higher security margin
- AEGIS-128X2: Dual-lane variant for higher throughput
- AEGIS-128X4: Quad-lane variant for maximum throughput on AVX-512
- AEGIS-256X2: Dual-lane variant with 256-bit security
- AEGIS-256X4: Quad-lane variant with 256-bit security

#### Message Authentication Codes (MAC)

All AEAD variants have corresponding MAC variants for authentication without encryption:

- AEGIS128L_MAC, AEGIS256_MAC
- AEGIS128X2_MAC, AEGIS128X4_MAC
- AEGIS256X2_MAC, AEGIS256X4_MAC

## Installation

### From PyPI

Using [uv](https://docs.astral.sh/uv/):

```bash
uv pip install pyaegis
```

Or using pip:

```bash
pip install pyaegis
```

### From Source

The package compiles the C library automatically using any installed C compiler:

```bash
# Clone the repository
git clone https://github.com/aegis-aead/pyaegis.git
cd pyaegis

# Install with uv (compiles C sources automatically)
uv pip install .

# Or for development
uv pip install -e .
```

Alternatively with pip:

```bash
pip install .
# Or for development
pip install -e .
```

### Building a Distribution

```bash
# With uv
uv run python -m build

# Or with pip
python -m build
```

This creates both source and wheel distributions in the `dist/` directory. The C sources are bundled in the package and compiled during installation.

## Usage

### Basic Encryption/Decryption

```python
from pyaegis import AEGIS128L

# Create a cipher instance
cipher = AEGIS128L()

# Generate random key and nonce
key = cipher.random_key()
nonce = cipher.random_nonce()

# Encrypt a message
plaintext = b"Hello, World!"
ciphertext = cipher.encrypt(key, nonce, plaintext)

# Decrypt the message
decrypted = cipher.decrypt(key, nonce, ciphertext)
assert decrypted == plaintext
```

### With Additional Authenticated Data (AAD)

```python
from pyaegis import AEGIS256

cipher = AEGIS256()
key = cipher.random_key()
nonce = cipher.random_nonce()

# AAD is authenticated but not encrypted
associated_data = b"metadata"

ciphertext = cipher.encrypt(key, nonce, b"secret", associated_data=associated_data)
plaintext = cipher.decrypt(key, nonce, ciphertext, associated_data=associated_data)
```

### Detached Tag Mode

```python
from pyaegis import AEGIS128L

cipher = AEGIS128L()
key = cipher.random_key()
nonce = cipher.random_nonce()

# Encrypt with detached tag
ciphertext, tag = cipher.encrypt_detached(key, nonce, b"secret")

# Decrypt with detached tag
plaintext = cipher.decrypt_detached(key, nonce, ciphertext, tag)
```

### Tag Size

By default, a 32-byte (256-bit) tag is used for maximum security. You can also use a 16-byte (128-bit) tag:

```python
cipher = AEGIS128L(tag_size=16)
```

### Stream Generation

Generate a deterministic pseudo-random byte sequence (AEGIS-128L and AEGIS-256 only):

```python
from pyaegis import AEGIS128L

key = AEGIS128L.random_key()
nonce = AEGIS128L.random_nonce()

# Generate 1024 pseudo-random bytes
random_bytes = AEGIS128L.stream(key, nonce, 1024)
```

### Message Authentication Code (MAC)

Generate and verify authentication tags without encryption:

```python
from pyaegis import AEGIS128L_MAC, DecryptionError

key = AEGIS128L_MAC.random_key()
nonce = AEGIS128L_MAC.random_nonce()

# Generate MAC tag
mac = AEGIS128L_MAC(key, nonce)
mac.update(b"message part 1")
mac.update(b"message part 2")
tag = mac.final()

# Verify MAC tag
mac_verify = AEGIS128L_MAC(key, nonce)
mac_verify.update(b"message part 1message part 2")
try:
    mac_verify.verify(tag)
    print("Authentication successful!")
except DecryptionError:
    print("Authentication failed!")
```

Important: The same key must NOT be used for both MAC and encryption operations.

## Error Handling

```python
from pyaegis import AEGIS128L, DecryptionError

cipher = AEGIS128L()
key = cipher.random_key()
nonce = cipher.random_nonce()

try:
    # This will raise DecryptionError if authentication fails
    plaintext = cipher.decrypt(key, nonce, tampered_ciphertext)
except DecryptionError:
    print("Authentication failed - ciphertext was tampered with!")
```

## Performance

The library automatically detects CPU features at runtime and uses the most optimized implementation available:

- AES-NI on Intel/AMD processors
- ARM Crypto Extensions on ARM processors
- AVX2 and AVX-512 for multi-lane variants
- Software fallback for other platforms

Multi-lane variants (X2, X4) provide higher throughput on systems with appropriate SIMD support.

## Security Considerations

- Nonce Uniqueness: Never reuse a nonce with the same key. If you can't maintain a counter, use `random_nonce()` for each message.
- Key Management: Use `random_key()` to generate cryptographically secure keys. Keep keys secret.
- AAD: Additional authenticated data is not encrypted but is protected against tampering.
