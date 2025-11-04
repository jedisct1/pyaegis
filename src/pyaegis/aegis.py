"""
High-level Pythonic API for AEGIS authenticated encryption.
"""

import os

from pyaegis._aegis_ffi import ffi, lib


class AEGISError(Exception):
    """Base exception for AEGIS operations."""

    pass


class DecryptionError(AEGISError):
    """Raised when decryption or authentication fails."""

    pass


# Initialize the library on import (runtime CPU detection)
lib.aegis_init()


class _AEGISBase:
    """Base class for AEGIS cipher implementations with shared functionality."""

    KEY_SIZE: int
    NONCE_SIZE: int
    TAG_SIZE_MIN: int = 16
    TAG_SIZE_MAX: int = 32

    # Subclasses should define these as references to C library functions
    _encrypt_func = None
    _decrypt_func = None
    _encrypt_detached_func = None
    _decrypt_detached_func = None
    _stream_func = None

    def __init__(self, tag_size: int = 32) -> None:
        """
        Initialize an AEGIS cipher.

        Args:
            tag_size: Size of the authentication tag in bytes (16 or 32).
                     32 bytes is recommended for maximum security.

        Raises:
            ValueError: If tag_size is not 16 or 32.
        """
        if tag_size not in (16, 32):
            raise ValueError(f"tag_size must be 16 or 32, got {tag_size}")
        self.tag_size = tag_size

    @classmethod
    def random_key(cls) -> bytes:
        """Generate a random key suitable for this cipher."""
        return os.urandom(cls.KEY_SIZE)

    @classmethod
    def random_nonce(cls) -> bytes:
        """Generate a random nonce suitable for this cipher."""
        return os.urandom(cls.NONCE_SIZE)

    def _check_key(self, key: bytes) -> None:
        """Validate key length."""
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be {self.KEY_SIZE} bytes, got {len(key)}")

    def _check_nonce(self, nonce: bytes) -> None:
        """Validate nonce length."""
        if len(nonce) != self.NONCE_SIZE:
            raise ValueError(f"Nonce must be {self.NONCE_SIZE} bytes, got {len(nonce)}")

    def encrypt(
        self,
        key: bytes,
        nonce: bytes,
        plaintext: bytes,
        associated_data: bytes | None = None,
    ) -> bytes:
        """
        Encrypt and authenticate a message.

        Args:
            key: Encryption key (size depends on cipher variant)
            nonce: Nonce (must be unique for each message with the same key)
            plaintext: Message to encrypt
            associated_data: Optional additional authenticated data (not encrypted)

        Returns:
            Ciphertext with authentication tag appended

        Raises:
            ValueError: If key or nonce has incorrect length
            AEGISError: If encryption fails
        """
        self._check_key(key)
        self._check_nonce(nonce)

        plaintext_len = len(plaintext)
        if associated_data:
            ad_len = len(associated_data)
            ad_ptr = associated_data if ad_len > 0 else ffi.NULL
        else:
            ad_len = 0
            ad_ptr = ffi.NULL

        # Multi-lane variants use detached mode internally
        if self._encrypt_func is None:
            assert self._encrypt_detached_func is not None
            output_len = plaintext_len + self.tag_size
            output_buf = ffi.new(f"uint8_t[{output_len}]")
            ciphertext_buf = output_buf
            tag_buf = ffi.cast("uint8_t*", output_buf) + plaintext_len

            result = self._encrypt_detached_func(
                ciphertext_buf,
                tag_buf,
                self.tag_size,
                plaintext,
                plaintext_len,
                ad_ptr,
                ad_len,
                nonce,
                key,
            )

            if result != 0:
                raise AEGISError("Encryption failed")

            return bytes(ffi.buffer(output_buf, output_len))

        # Standard variants use combined mode
        output_len = plaintext_len + self.tag_size
        output_buf = ffi.new(f"uint8_t[{output_len}]")

        result = self._encrypt_func(
            output_buf,
            self.tag_size,
            plaintext,
            plaintext_len,
            ad_ptr,
            ad_len,
            nonce,
            key,
        )

        if result != 0:
            raise AEGISError("Encryption failed")

        return bytes(ffi.buffer(output_buf, output_len))

    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        associated_data: bytes | None = None,
    ) -> bytes:
        """
        Decrypt and verify an authenticated message.

        Args:
            key: Encryption key (size depends on cipher variant)
            nonce: Nonce used during encryption
            ciphertext: Encrypted message with authentication tag
            associated_data: Optional additional authenticated data

        Returns:
            Decrypted plaintext

        Raises:
            ValueError: If key or nonce has incorrect length
            DecryptionError: If authentication fails
        """
        self._check_key(key)
        self._check_nonce(nonce)

        ciphertext_len = len(ciphertext)
        if ciphertext_len < self.tag_size:
            raise DecryptionError("Ciphertext too short")

        if associated_data:
            ad_len = len(associated_data)
            ad_ptr = associated_data if ad_len > 0 else ffi.NULL
        else:
            ad_len = 0
            ad_ptr = ffi.NULL

        plaintext_len = ciphertext_len - self.tag_size
        plaintext_buf = ffi.new(f"uint8_t[{plaintext_len}]")

        # Multi-lane variants use detached mode internally
        if self._decrypt_func is None:
            assert self._decrypt_detached_func is not None
            ct_ptr = ffi.cast("const uint8_t*", ffi.from_buffer(ciphertext))
            tag_ptr = ct_ptr + plaintext_len

            result = self._decrypt_detached_func(
                plaintext_buf,
                ct_ptr,
                plaintext_len,
                tag_ptr,
                self.tag_size,
                ad_ptr,
                ad_len,
                nonce,
                key,
            )
        else:
            # Standard variants use combined mode
            result = self._decrypt_func(
                plaintext_buf,
                ciphertext,
                ciphertext_len,
                self.tag_size,
                ad_ptr,
                ad_len,
                nonce,
                key,
            )

        if result != 0:
            raise DecryptionError("Authentication failed")

        return bytes(ffi.buffer(plaintext_buf, plaintext_len))


class _AEGISWithDetached(_AEGISBase):
    """Base class for AEGIS variants that support detached mode explicitly."""

    def encrypt_detached(
        self,
        key: bytes,
        nonce: bytes,
        plaintext: bytes,
        associated_data: bytes | None = None,
    ) -> tuple[bytes, bytes]:
        """
        Encrypt and authenticate a message, returning ciphertext and tag separately.

        Args:
            key: Encryption key
            nonce: Nonce
            plaintext: Message to encrypt
            associated_data: Optional additional authenticated data

        Returns:
            Tuple of (ciphertext, authentication_tag)

        Raises:
            ValueError: If key or nonce has incorrect length
            AEGISError: If encryption fails
        """
        self._check_key(key)
        self._check_nonce(nonce)

        if associated_data is None:
            associated_data = b""

        assert self._encrypt_detached_func is not None
        ciphertext_buf = ffi.new(f"uint8_t[{len(plaintext)}]")
        tag_buf = ffi.new(f"uint8_t[{self.tag_size}]")

        result = self._encrypt_detached_func(
            ciphertext_buf,
            tag_buf,
            self.tag_size,
            plaintext,
            len(plaintext),
            associated_data if len(associated_data) > 0 else ffi.NULL,
            len(associated_data),
            nonce,
            key,
        )

        if result != 0:
            raise AEGISError("Encryption failed")

        return (
            bytes(ffi.buffer(ciphertext_buf, len(plaintext))),
            bytes(ffi.buffer(tag_buf, self.tag_size)),
        )

    def decrypt_detached(
        self,
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        tag: bytes,
        associated_data: bytes | None = None,
    ) -> bytes:
        """
        Decrypt and verify a message with detached authentication tag.

        Args:
            key: Encryption key
            nonce: Nonce
            ciphertext: Encrypted message
            tag: Authentication tag
            associated_data: Optional additional authenticated data

        Returns:
            Decrypted plaintext

        Raises:
            ValueError: If key or nonce has incorrect length
            DecryptionError: If authentication fails
        """
        self._check_key(key)
        self._check_nonce(nonce)

        if associated_data is None:
            associated_data = b""

        assert self._decrypt_detached_func is not None
        plaintext_buf = ffi.new(f"uint8_t[{len(ciphertext)}]")

        result = self._decrypt_detached_func(
            plaintext_buf,
            ciphertext,
            len(ciphertext),
            tag,
            len(tag),
            associated_data if len(associated_data) > 0 else ffi.NULL,
            len(associated_data),
            nonce,
            key,
        )

        if result != 0:
            raise DecryptionError("Authentication failed")

        return bytes(ffi.buffer(plaintext_buf, len(ciphertext)))

    def encrypt_inplace(
        self,
        key: bytes,
        nonce: bytes,
        buffer,  # bytearray or memoryview
        associated_data: bytes | None = None,
    ) -> bytes:
        """
        Encrypt buffer in-place, return authentication tag.

        This method encrypts data directly in the provided mutable buffer,
        avoiding memory allocation and reducing bandwidth usage. This is
        especially beneficial for large buffers (>10MB).

        Args:
            key: Encryption key
            nonce: Nonce
            buffer: Mutable buffer (bytearray or memoryview) containing plaintext.
                   Will be overwritten with ciphertext in-place.
            associated_data: Optional additional authenticated data

        Returns:
            Authentication tag (16 or 32 bytes depending on tag_size)

        Raises:
            TypeError: If buffer is not mutable (bytearray/memoryview)
            ValueError: If key or nonce has incorrect length
            AEGISError: If encryption fails

        Example:
            >>> cipher = AEGIS128X4()
            >>> key, nonce = cipher.random_key(), cipher.random_nonce()
            >>> buffer = bytearray(b"secret message")
            >>> tag = cipher.encrypt_inplace(key, nonce, buffer)
            >>> # buffer now contains ciphertext
            >>> # Send both: bytes(buffer) + tag

        Note:
            The plaintext is destroyed and replaced with ciphertext.
            For large buffers (>10MB), this can provide 30-50% performance
            improvement over regular encrypt() due to reduced memory bandwidth.
        """
        self._check_key(key)
        self._check_nonce(nonce)

        # Validate buffer type
        if not isinstance(buffer, (bytearray, memoryview)):
            raise TypeError(
                f"buffer must be bytearray or memoryview, got {type(buffer).__name__}"
            )

        plaintext_len = len(buffer)

        # Handle associated data
        if associated_data is None:
            associated_data = b""

        assert self._encrypt_detached_func is not None

        # Allocate tag buffer
        tag_buf = ffi.new(f"uint8_t[{self.tag_size}]")

        # Get pointer to mutable buffer (for both input and output)
        buf_ptr = ffi.from_buffer(buffer)

        # Encrypt in-place: buf_ptr is both source and destination
        result = self._encrypt_detached_func(
            buf_ptr,  # Output ciphertext (overwrites input)
            tag_buf,
            self.tag_size,
            buf_ptr,  # Input plaintext (same as output)
            plaintext_len,
            associated_data if len(associated_data) > 0 else ffi.NULL,
            len(associated_data),
            nonce,
            key,
        )

        if result != 0:
            raise AEGISError("Encryption failed")

        return bytes(ffi.buffer(tag_buf, self.tag_size))

    def decrypt_inplace(
        self,
        key: bytes,
        nonce: bytes,
        buffer,  # bytearray or memoryview
        tag: bytes,
        associated_data: bytes | None = None,
    ) -> None:
        """
        Decrypt buffer in-place and verify authentication tag.

        This method decrypts data directly in the provided mutable buffer,
        avoiding memory allocation and reducing bandwidth usage.

        Args:
            key: Encryption key
            nonce: Nonce
            buffer: Mutable buffer (bytearray or memoryview) containing ciphertext.
                   Will be overwritten with plaintext in-place.
            tag: Authentication tag
            associated_data: Optional additional authenticated data

        Raises:
            TypeError: If buffer is not mutable (bytearray/memoryview)
            ValueError: If key or nonce has incorrect length
            DecryptionError: If authentication fails

        Example:
            >>> cipher = AEGIS128X4()
            >>> # Received ciphertext and tag
            >>> buffer = bytearray(ciphertext)
            >>> cipher.decrypt_inplace(key, nonce, buffer, tag)
            >>> # buffer now contains plaintext
            >>> plaintext = bytes(buffer)

        Note:
            If authentication fails, the buffer contents are zeroed for security.
            For large buffers (>10MB), this provides 30-50% performance improvement
            over regular decrypt() due to reduced memory bandwidth.
        """
        self._check_key(key)
        self._check_nonce(nonce)

        # Validate buffer type
        if not isinstance(buffer, (bytearray, memoryview)):
            raise TypeError(
                f"buffer must be bytearray or memoryview, got {type(buffer).__name__}"
            )

        ciphertext_len = len(buffer)

        # Handle associated data
        if associated_data is None:
            associated_data = b""

        assert self._decrypt_detached_func is not None

        # Get pointer to mutable buffer (for both input and output)
        buf_ptr = ffi.from_buffer(buffer)

        # Decrypt in-place: buf_ptr is both source and destination
        result = self._decrypt_detached_func(
            buf_ptr,  # Output plaintext (overwrites input)
            buf_ptr,  # Input ciphertext (same as output)
            ciphertext_len,
            tag,
            len(tag),
            associated_data if len(associated_data) > 0 else ffi.NULL,
            len(associated_data),
            nonce,
            key,
        )

        if result != 0:
            # Zero buffer on authentication failure for security
            for i in range(len(buffer)):
                buffer[i] = 0
            raise DecryptionError("Authentication failed")


class _AEGISWithStream(_AEGISWithDetached):
    """Base class for AEGIS variants that support stream generation."""

    @classmethod
    def stream(cls, key: bytes, nonce: bytes, length: int) -> bytes:
        """
        Generate a deterministic pseudo-random byte sequence.

        Args:
            key: Encryption key
            nonce: Nonce (can be reused for stream generation)
            length: Number of bytes to generate

        Returns:
            Pseudo-random bytes

        Raises:
            ValueError: If key has incorrect length
        """
        if len(key) != cls.KEY_SIZE:
            raise ValueError(f"Key must be {cls.KEY_SIZE} bytes, got {len(key)}")

        assert cls._stream_func is not None
        output_buf = ffi.new(f"uint8_t[{length}]")
        cls._stream_func(output_buf, length, nonce, key)
        return bytes(ffi.buffer(output_buf, length))


class AEGIS128L(_AEGISWithStream):
    """
    AEGIS-128L authenticated encryption.

    Uses a 16-byte (128-bit) key and 16-byte nonce.
    Provides high performance on modern CPUs with AES-NI support.

    Example:
        >>> cipher = AEGIS128L()
        >>> key = cipher.random_key()
        >>> nonce = cipher.random_nonce()
        >>> ciphertext = cipher.encrypt(key, nonce, b"secret message")
        >>> plaintext = cipher.decrypt(key, nonce, ciphertext)
    """

    KEY_SIZE = 16
    NONCE_SIZE = 16

    _encrypt_func = lib.aegis128l_encrypt
    _decrypt_func = lib.aegis128l_decrypt
    _encrypt_detached_func = lib.aegis128l_encrypt_detached
    _decrypt_detached_func = lib.aegis128l_decrypt_detached
    _stream_func = lib.aegis128l_stream


class AEGIS256(_AEGISWithStream):
    """
    AEGIS-256 authenticated encryption.

    Uses a 32-byte (256-bit) key and 32-byte nonce.
    Provides higher security margin than AEGIS-128L.

    Example:
        >>> cipher = AEGIS256()
        >>> key = cipher.random_key()
        >>> nonce = cipher.random_nonce()
        >>> ciphertext = cipher.encrypt(key, nonce, b"secret message")
        >>> plaintext = cipher.decrypt(key, nonce, ciphertext)
    """

    KEY_SIZE = 32
    NONCE_SIZE = 32

    _encrypt_func = lib.aegis256_encrypt
    _decrypt_func = lib.aegis256_decrypt
    _encrypt_detached_func = lib.aegis256_encrypt_detached
    _decrypt_detached_func = lib.aegis256_decrypt_detached
    _stream_func = lib.aegis256_stream


class AEGIS128X2(_AEGISWithDetached):
    """
    AEGIS-128X2 - dual-lane variant for higher performance.

    Uses a 16-byte key and 16-byte nonce.
    Provides higher throughput on CPUs with wide SIMD capabilities.

    Example:
        >>> cipher = AEGIS128X2()
        >>> key = cipher.random_key()
        >>> nonce = cipher.random_nonce()
        >>> ciphertext = cipher.encrypt(key, nonce, b"secret message")
        >>> plaintext = cipher.decrypt(key, nonce, ciphertext)
    """

    KEY_SIZE = 16
    NONCE_SIZE = 16

    _encrypt_detached_func = lib.aegis128x2_encrypt_detached
    _decrypt_detached_func = lib.aegis128x2_decrypt_detached


class AEGIS128X4(_AEGISWithDetached):
    """
    AEGIS-128X4 - quad-lane variant for highest performance on AVX-512.

    Uses a 16-byte key and 16-byte nonce.
    Provides maximum throughput on CPUs with AVX-512 support.

    Example:
        >>> cipher = AEGIS128X4()
        >>> key = cipher.random_key()
        >>> nonce = cipher.random_nonce()
        >>> ciphertext = cipher.encrypt(key, nonce, b"secret message")
        >>> plaintext = cipher.decrypt(key, nonce, ciphertext)
    """

    KEY_SIZE = 16
    NONCE_SIZE = 16

    _encrypt_detached_func = lib.aegis128x4_encrypt_detached
    _decrypt_detached_func = lib.aegis128x4_decrypt_detached


class AEGIS256X2(_AEGISWithDetached):
    """
    AEGIS-256X2 - dual-lane variant with 256-bit security.

    Uses a 32-byte key and 32-byte nonce.
    Provides higher throughput with increased security margin.

    Example:
        >>> cipher = AEGIS256X2()
        >>> key = cipher.random_key()
        >>> nonce = cipher.random_nonce()
        >>> ciphertext = cipher.encrypt(key, nonce, b"secret message")
        >>> plaintext = cipher.decrypt(key, nonce, ciphertext)
    """

    KEY_SIZE = 32
    NONCE_SIZE = 32

    _encrypt_detached_func = lib.aegis256x2_encrypt_detached
    _decrypt_detached_func = lib.aegis256x2_decrypt_detached


class AEGIS256X4(_AEGISWithDetached):
    """
    AEGIS-256X4 - quad-lane variant with 256-bit security.

    Uses a 32-byte key and 32-byte nonce.
    Provides maximum throughput with increased security margin on AVX-512 CPUs.

    Example:
        >>> cipher = AEGIS256X4()
        >>> key = cipher.random_key()
        >>> nonce = cipher.random_nonce()
        >>> ciphertext = cipher.encrypt(key, nonce, b"secret message")
        >>> plaintext = cipher.decrypt(key, nonce, ciphertext)
    """

    KEY_SIZE = 32
    NONCE_SIZE = 32

    _encrypt_detached_func = lib.aegis256x4_encrypt_detached
    _decrypt_detached_func = lib.aegis256x4_decrypt_detached


# MAC classes for message authentication


class _AEGISMACBase:
    """Base class for AEGIS-MAC implementations with shared functionality."""

    KEY_SIZE: int
    NONCE_SIZE: int
    TAG_SIZE_MIN: int = 16
    TAG_SIZE_MAX: int = 32

    # Subclasses should define these
    _mac_state_type = None
    _mac_init_func = None
    _mac_update_func = None
    _mac_final_func = None
    _mac_verify_func = None
    _mac_reset_func = None

    def __init__(self, key: bytes, nonce: bytes, tag_size: int = 32) -> None:
        """
        Initialize an AEGIS-MAC instance.

        Args:
            key: MAC key (size depends on cipher variant)
            nonce: Nonce (size depends on cipher variant)
            tag_size: Size of the authentication tag in bytes (16 or 32).
                     32 bytes is recommended for maximum security.

        Raises:
            ValueError: If key, nonce, or tag_size is invalid

        Note:
            The same key MUST NOT be used both for MAC and encryption.
            Generate a random key and keep it secret for secure MAC operations.
        """
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be {self.KEY_SIZE} bytes, got {len(key)}")
        if len(nonce) != self.NONCE_SIZE:
            raise ValueError(f"Nonce must be {self.NONCE_SIZE} bytes, got {len(nonce)}")
        if tag_size not in (16, 32):
            raise ValueError(f"tag_size must be 16 or 32, got {tag_size}")

        self.tag_size = tag_size
        self._state = ffi.new(f"{self._mac_state_type}*")
        self._mac_init_func(self._state, key, nonce)
        self._finalized = False

    @classmethod
    def random_key(cls) -> bytes:
        """Generate a random key suitable for this MAC."""
        return os.urandom(cls.KEY_SIZE)

    @classmethod
    def random_nonce(cls) -> bytes:
        """Generate a random nonce suitable for this MAC."""
        return os.urandom(cls.NONCE_SIZE)

    def update(self, data: bytes) -> None:
        """
        Update the MAC state with input data.

        Args:
            data: Input data to authenticate

        Raises:
            AEGISError: If update fails or MAC has been finalized
        """
        if self._finalized:
            raise AEGISError("Cannot update after finalization")

        result = self._mac_update_func(self._state, data, len(data))
        if result != 0:
            raise AEGISError("MAC update failed")

    def final(self) -> bytes:
        """
        Finalize the MAC and generate the authentication tag.

        Returns:
            Authentication tag

        Raises:
            AEGISError: If MAC has already been finalized
        """
        if self._finalized:
            raise AEGISError("MAC already finalized")

        tag_buf = ffi.new(f"uint8_t[{self.tag_size}]")
        result = self._mac_final_func(self._state, tag_buf, self.tag_size)
        if result != 0:
            raise AEGISError("MAC finalization failed")

        self._finalized = True
        return bytes(ffi.buffer(tag_buf, self.tag_size))

    def verify(self, tag: bytes) -> None:
        """
        Verify a MAC in constant time.

        Args:
            tag: Authentication tag to verify

        Raises:
            DecryptionError: If the tag is not authentic
            AEGISError: If MAC has already been finalized
        """
        if self._finalized:
            raise AEGISError("MAC already finalized")

        result = self._mac_verify_func(self._state, tag, len(tag))
        self._finalized = True

        if result != 0:
            raise DecryptionError("MAC verification failed")

    def reset(self) -> None:
        """Reset the MAC state for reuse."""
        self._mac_reset_func(self._state)
        self._finalized = False


class AEGIS128L_MAC(_AEGISMACBase):
    """
    AEGIS-128L MAC - message authentication using AEGIS-128L.

    Uses a 16-byte key and 16-byte nonce.

    Example:
        >>> mac = AEGIS128L_MAC(key, nonce)
        >>> mac.update(b"hello")
        >>> mac.update(b" world")
        >>> tag = mac.final()

    Example (verification):
        >>> mac2 = AEGIS128L_MAC(key, nonce)
        >>> mac2.update(b"hello world")
        >>> mac2.verify(tag)  # raises DecryptionError if invalid
    """

    KEY_SIZE = 16
    NONCE_SIZE = 16

    _mac_state_type = "aegis128l_mac_state"
    _mac_init_func = lib.aegis128l_mac_init
    _mac_update_func = lib.aegis128l_mac_update
    _mac_final_func = lib.aegis128l_mac_final
    _mac_verify_func = lib.aegis128l_mac_verify
    _mac_reset_func = lib.aegis128l_mac_reset


class AEGIS256_MAC(_AEGISMACBase):
    """
    AEGIS-256 MAC - message authentication using AEGIS-256.

    Uses a 32-byte key and 32-byte nonce.

    Example:
        >>> mac = AEGIS256_MAC(key, nonce)
        >>> mac.update(b"hello")
        >>> mac.update(b" world")
        >>> tag = mac.final()
    """

    KEY_SIZE = 32
    NONCE_SIZE = 32

    _mac_state_type = "aegis256_mac_state"
    _mac_init_func = lib.aegis256_mac_init
    _mac_update_func = lib.aegis256_mac_update
    _mac_final_func = lib.aegis256_mac_final
    _mac_verify_func = lib.aegis256_mac_verify
    _mac_reset_func = lib.aegis256_mac_reset


class AEGIS128X2_MAC(_AEGISMACBase):
    """
    AEGIS-128X2 MAC - message authentication using dual-lane AEGIS-128.

    Uses a 16-byte key and 16-byte nonce.
    Provides higher throughput on CPUs with wide SIMD capabilities.

    Example:
        >>> mac = AEGIS128X2_MAC(key, nonce)
        >>> mac.update(b"data")
        >>> tag = mac.final()
    """

    KEY_SIZE = 16
    NONCE_SIZE = 16

    _mac_state_type = "aegis128x2_mac_state"
    _mac_init_func = lib.aegis128x2_mac_init
    _mac_update_func = lib.aegis128x2_mac_update
    _mac_final_func = lib.aegis128x2_mac_final
    _mac_verify_func = lib.aegis128x2_mac_verify
    _mac_reset_func = lib.aegis128x2_mac_reset


class AEGIS128X4_MAC(_AEGISMACBase):
    """
    AEGIS-128X4 MAC - message authentication using quad-lane AEGIS-128.

    Uses a 16-byte key and 16-byte nonce.
    Provides maximum throughput on CPUs with AVX-512 support.

    Example:
        >>> mac = AEGIS128X4_MAC(key, nonce)
        >>> mac.update(b"data")
        >>> tag = mac.final()
    """

    KEY_SIZE = 16
    NONCE_SIZE = 16

    _mac_state_type = "aegis128x4_mac_state"
    _mac_init_func = lib.aegis128x4_mac_init
    _mac_update_func = lib.aegis128x4_mac_update
    _mac_final_func = lib.aegis128x4_mac_final
    _mac_verify_func = lib.aegis128x4_mac_verify
    _mac_reset_func = lib.aegis128x4_mac_reset


class AEGIS256X2_MAC(_AEGISMACBase):
    """
    AEGIS-256X2 MAC - message authentication using dual-lane AEGIS-256.

    Uses a 32-byte key and 32-byte nonce.
    Provides higher throughput with increased security margin.

    Example:
        >>> mac = AEGIS256X2_MAC(key, nonce)
        >>> mac.update(b"data")
        >>> tag = mac.final()
    """

    KEY_SIZE = 32
    NONCE_SIZE = 32

    _mac_state_type = "aegis256x2_mac_state"
    _mac_init_func = lib.aegis256x2_mac_init
    _mac_update_func = lib.aegis256x2_mac_update
    _mac_final_func = lib.aegis256x2_mac_final
    _mac_verify_func = lib.aegis256x2_mac_verify
    _mac_reset_func = lib.aegis256x2_mac_reset


class AEGIS256X4_MAC(_AEGISMACBase):
    """
    AEGIS-256X4 MAC - message authentication using quad-lane AEGIS-256.

    Uses a 32-byte key and 32-byte nonce.
    Provides maximum throughput with increased security margin on AVX-512 CPUs.

    Example:
        >>> mac = AEGIS256X4_MAC(key, nonce)
        >>> mac.update(b"data")
        >>> tag = mac.final()
    """

    KEY_SIZE = 32
    NONCE_SIZE = 32

    _mac_state_type = "aegis256x4_mac_state"
    _mac_init_func = lib.aegis256x4_mac_init
    _mac_update_func = lib.aegis256x4_mac_update
    _mac_final_func = lib.aegis256x4_mac_final
    _mac_verify_func = lib.aegis256x4_mac_verify
    _mac_reset_func = lib.aegis256x4_mac_reset
