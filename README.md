# pyaegis

[![PyPI version](https://badge.fury.io/py/pyaegis.svg)](https://badge.fury.io/py/pyaegis)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jedisct1/pyaegis/blob/main/LICENSE)

Python bindings for libaegis - high-performance AEGIS authenticated encryption.

## Overview

pyaegis provides Pythonic interfaces to the AEGIS family of authenticated encryption algorithms.

AEGIS is a high-performance authenticated cipher that provides both confidentiality and authenticity guarantees.

### Supported Variants

#### Authenticated Encryption (AEAD)

- AEGIS-128L: 16-byte key, 16-byte nonce
- AEGIS-256: 32-byte key, 32-byte nonce
- AEGIS-128X2: 16-byte key, 16-byte nonce (recommended on most platforms)
- AEGIS-128X4: 16-byte key, 16-byte nonce (recommended on high-end Intel CPUs)
- AEGIS-256X2: 32-byte key, 32-byte nonce
- AEGIS-256X4: 32-byte key, 32-byte nonce (recommended if a 256-bit nonce is required)

#### Message Authentication Codes (MAC)

All AEAD variants have corresponding MAC variants for authentication without encryption:

- AegisMac128L, AegisMac256
- AegisMac128X2, AegisMac128X4
- AegisMac256X2, AegisMac256X4

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
git clone https://github.com/jedisct1/pyaegis.git
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
from pyaegis import Aegis128L

# Create a cipher instance
cipher = Aegis128L()

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
from pyaegis import Aegis256

cipher = Aegis256()
key = cipher.random_key()
nonce = cipher.random_nonce()

# AAD is authenticated but not encrypted
associated_data = b"metadata"

ciphertext = cipher.encrypt(key, nonce, b"secret", associated_data=associated_data)
plaintext = cipher.decrypt(key, nonce, ciphertext, associated_data=associated_data)
```

### Detached Tag Mode

```python
from pyaegis import Aegis128L

cipher = Aegis128L()
key = cipher.random_key()
nonce = cipher.random_nonce()

# Encrypt with detached tag
ciphertext, tag = cipher.encrypt_detached(key, nonce, b"secret")

# Decrypt with detached tag
plaintext = cipher.decrypt_detached(key, nonce, ciphertext, tag)
```

### Pre-allocated Buffers

For performance-sensitive applications, you can provide pre-allocated buffers to avoid memory allocation:

```python
from pyaegis import Aegis128L

cipher = Aegis128L()
key = cipher.random_key()
nonce = cipher.random_nonce()
plaintext = b"secret message"

# Pre-allocate output buffer for encryption
output_buffer = bytearray(len(plaintext) + cipher.tag_size)
cipher.encrypt(key, nonce, plaintext, into=output_buffer)

# Pre-allocate output buffer for decryption
plaintext_buffer = bytearray(len(output_buffer) - cipher.tag_size)
cipher.decrypt(key, nonce, output_buffer, into=plaintext_buffer)

# Also works with encrypt_detached
ciphertext_buffer = bytearray(len(plaintext))
ciphertext, tag = cipher.encrypt_detached(key, nonce, plaintext, ciphertext_into=ciphertext_buffer)
```

### Tag Size

By default, a 32-byte (256-bit) tag is used for maximum security. You can also use a 16-byte (128-bit) tag:

```python
cipher = Aegis128L(tag_size=16)
```

### In-Place Encryption/Decryption

For performance-critical applications, especially when working with large buffers (>10MB), in-place operations can provide 30-50% performance improvement by reducing memory bandwidth:

```python
from pyaegis import Aegis128X4

cipher = Aegis128X4()
key = cipher.random_key()
nonce = cipher.random_nonce()

# Encrypt in-place
buffer = bytearray(b"secret message")
tag = cipher.encrypt_inplace(key, nonce, buffer)
# buffer now contains ciphertext

# Decrypt in-place
cipher.decrypt_inplace(key, nonce, buffer, tag)
# buffer now contains plaintext again
```

In-place operations work with `bytearray` or `memoryview` objects and overwrite the input buffer directly. If decryption fails, the buffer is zeroed for security.

### Streaming Encryption/Decryption

For processing large data in chunks or when data arrives incrementally, use the streaming encryption/decryption classes. These allow you to encrypt or decrypt data piece by piece without loading everything into memory at once.

#### Streaming Encryption

```python
from pyaegis import AegisStreamEncrypt128L

key = AegisStreamEncrypt128L.random_key()
nonce = AegisStreamEncrypt128L.random_nonce()

# Create a streaming encryption context
with AegisStreamEncrypt128L(key, nonce, associated_data=b"metadata") as enc:
    # Encrypt data in chunks
    ciphertext1 = enc.update(b"first chunk of data")
    ciphertext2 = enc.update(b"second chunk of data")

    # Finalize and get the authentication tag
    tag = enc.final()

# Send ciphertext1 + ciphertext2 + tag to the recipient
```

#### Streaming Decryption

```python
from pyaegis import AegisStreamDecrypt128L, DecryptionError

# Create a streaming decryption context
with AegisStreamDecrypt128L(key, nonce, associated_data=b"metadata") as dec:
    # Decrypt data in chunks
    dec.update(ciphertext1)
    dec.update(ciphertext2)

    # Verify the authentication tag and get all plaintext
    try:
        plaintext = dec.verify(tag)
        # plaintext is only released after successful verification
    except DecryptionError:
        print("Authentication failed!")
```

**Security Note**: The streaming decryption API buffers all plaintext internally and only releases it after successful tag verification. This prevents using unauthenticated data.

**Available Streaming Classes**:
- `AegisStreamEncrypt128L` / `AegisStreamDecrypt128L`
- `AegisStreamEncrypt256` / `AegisStreamDecrypt256`
- `AegisStreamEncrypt128X2` / `AegisStreamDecrypt128X2`
- `AegisStreamEncrypt128X4` / `AegisStreamDecrypt128X4`
- `AegisStreamEncrypt256X2` / `AegisStreamDecrypt256X2`
- `AegisStreamEncrypt256X4` / `AegisStreamDecrypt256X4`

### Stream Generation

Generate a deterministic pseudo-random byte sequence (AEGIS-128L and AEGIS-256 only):

```python
from pyaegis import Aegis128L

key = Aegis128L.random_key()
nonce = Aegis128L.random_nonce()

# Generate 1024 pseudo-random bytes
random_bytes = Aegis128L.stream(key, nonce, 1024)

# With pre-allocated buffer for better performance
buffer = bytearray(1024)
random_bytes = Aegis128L.stream(key, nonce, 1024, into=buffer)
```

### Message Authentication Code (MAC)

Generate and verify authentication tags without encryption:

```python
from pyaegis import AegisMac128L, DecryptionError

key = AegisMac128L.random_key()
nonce = AegisMac128L.random_nonce()

# Generate MAC tag
mac = AegisMac128L(key, nonce)
mac.update(b"message part 1")
mac.update(b"message part 2")
tag = mac.final()

# Verify MAC tag
mac_verify = AegisMac128L(key, nonce)
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
from pyaegis import Aegis128L, DecryptionError

cipher = Aegis128L()
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
