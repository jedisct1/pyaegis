"""Tests for pyaegis Python bindings."""

import pytest

from pyaegis import (
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
    DecryptionError,
)


class TestAEGIS128L:
    """Tests for AEGIS-128L."""

    def test_encrypt_decrypt_basic(self):
        """Test basic encryption and decryption."""
        cipher = Aegis128L()
        key = cipher.random_key()
        nonce = cipher.random_nonce()
        plaintext = b"Hello, World!"

        ciphertext = cipher.encrypt(key, nonce, plaintext)
        assert len(ciphertext) == len(plaintext) + 32  # 32-byte tag

        decrypted = cipher.decrypt(key, nonce, ciphertext)
        assert decrypted == plaintext

    def test_encrypt_decrypt_with_aad(self):
        """Test encryption with additional authenticated data."""
        cipher = Aegis128L()
        key = cipher.random_key()
        nonce = cipher.random_nonce()
        plaintext = b"Secret message"
        aad = b"metadata"

        ciphertext = cipher.encrypt(key, nonce, plaintext, associated_data=aad)
        decrypted = cipher.decrypt(key, nonce, ciphertext, associated_data=aad)
        assert decrypted == plaintext

    def test_decrypt_fails_with_wrong_aad(self):
        """Test that decryption fails with incorrect AAD."""
        cipher = Aegis128L()
        key = cipher.random_key()
        nonce = cipher.random_nonce()
        plaintext = b"Secret"

        ciphertext = cipher.encrypt(key, nonce, plaintext, associated_data=b"correct")

        with pytest.raises(DecryptionError):
            cipher.decrypt(key, nonce, ciphertext, associated_data=b"wrong")

    def test_decrypt_fails_with_tampered_ciphertext(self):
        """Test that decryption fails with tampered ciphertext."""
        cipher = Aegis128L()
        key = cipher.random_key()
        nonce = cipher.random_nonce()
        plaintext = b"Secret"

        ciphertext = cipher.encrypt(key, nonce, plaintext)
        tampered = bytearray(ciphertext)
        tampered[0] ^= 1  # Flip a bit

        with pytest.raises(DecryptionError):
            cipher.decrypt(key, nonce, bytes(tampered))

    def test_encrypt_decrypt_detached(self):
        """Test encryption with detached tag."""
        cipher = Aegis128L()
        key = cipher.random_key()
        nonce = cipher.random_nonce()
        plaintext = b"Hello, World!"

        ciphertext, tag = cipher.encrypt_detached(key, nonce, plaintext)
        assert len(ciphertext) == len(plaintext)
        assert len(tag) == 32

        decrypted = cipher.decrypt_detached(key, nonce, ciphertext, tag)
        assert decrypted == plaintext

    def test_tag_size_16(self):
        """Test with 16-byte tag."""
        cipher = Aegis128L(tag_size=16)
        key = cipher.random_key()
        nonce = cipher.random_nonce()
        plaintext = b"Test"

        ciphertext = cipher.encrypt(key, nonce, plaintext)
        assert len(ciphertext) == len(plaintext) + 16

        decrypted = cipher.decrypt(key, nonce, ciphertext)
        assert decrypted == plaintext

    def test_invalid_tag_size(self):
        """Test that invalid tag sizes are rejected."""
        with pytest.raises(ValueError):
            Aegis128L(tag_size=20)

    def test_invalid_key_length(self):
        """Test that invalid key length is rejected."""
        cipher = Aegis128L()
        nonce = cipher.random_nonce()

        with pytest.raises(ValueError):
            cipher.encrypt(b"short", nonce, b"data")

    def test_invalid_nonce_length(self):
        """Test that invalid nonce length is rejected."""
        cipher = Aegis128L()
        key = cipher.random_key()

        with pytest.raises(ValueError):
            cipher.encrypt(key, b"short", b"data")

    def test_empty_plaintext(self):
        """Test encryption of empty plaintext."""
        cipher = Aegis128L()
        key = cipher.random_key()
        nonce = cipher.random_nonce()

        ciphertext = cipher.encrypt(key, nonce, b"")
        assert len(ciphertext) == 32  # Only the tag

        decrypted = cipher.decrypt(key, nonce, ciphertext)
        assert decrypted == b""

    def test_large_plaintext(self):
        """Test encryption of large plaintext."""
        cipher = Aegis128L()
        key = cipher.random_key()
        nonce = cipher.random_nonce()
        plaintext = b"X" * 10000

        ciphertext = cipher.encrypt(key, nonce, plaintext)
        decrypted = cipher.decrypt(key, nonce, ciphertext)
        assert decrypted == plaintext

    def test_stream(self):
        """Test stream generation."""
        key = Aegis128L.random_key()
        nonce = Aegis128L.random_nonce()

        stream1 = Aegis128L.stream(key, nonce, 1024)
        stream2 = Aegis128L.stream(key, nonce, 1024)

        assert len(stream1) == 1024
        assert stream1 == stream2  # Deterministic

        # Different nonce produces different stream
        nonce2 = Aegis128L.random_nonce()
        stream3 = Aegis128L.stream(key, nonce2, 1024)
        assert stream1 != stream3

    def test_key_sizes(self):
        """Test that key and nonce sizes are correct."""
        assert Aegis128L.KEY_SIZE == 16
        assert Aegis128L.NONCE_SIZE == 16


class TestAEGIS256:
    """Tests for AEGIS-256."""

    def test_encrypt_decrypt_basic(self):
        """Test basic encryption and decryption."""
        cipher = Aegis256()
        key = cipher.random_key()
        nonce = cipher.random_nonce()
        plaintext = b"Hello, World!"

        ciphertext = cipher.encrypt(key, nonce, plaintext)
        decrypted = cipher.decrypt(key, nonce, ciphertext)
        assert decrypted == plaintext

    def test_encrypt_decrypt_detached(self):
        """Test encryption with detached tag."""
        cipher = Aegis256()
        key = cipher.random_key()
        nonce = cipher.random_nonce()
        plaintext = b"Secret"

        ciphertext, tag = cipher.encrypt_detached(key, nonce, plaintext)
        decrypted = cipher.decrypt_detached(key, nonce, ciphertext, tag)
        assert decrypted == plaintext

    def test_key_sizes(self):
        """Test that key and nonce sizes are correct."""
        assert Aegis256.KEY_SIZE == 32
        assert Aegis256.NONCE_SIZE == 32

    def test_stream(self):
        """Test stream generation."""
        key = Aegis256.random_key()
        nonce = Aegis256.random_nonce()

        stream = Aegis256.stream(key, nonce, 512)
        assert len(stream) == 512


class TestAEGIS128X2:
    """Tests for AEGIS-128X2."""

    def test_encrypt_decrypt_basic(self):
        """Test basic encryption and decryption."""
        cipher = Aegis128X2()
        key = cipher.random_key()
        nonce = cipher.random_nonce()
        plaintext = b"Hello, World!"

        ciphertext = cipher.encrypt(key, nonce, plaintext)
        decrypted = cipher.decrypt(key, nonce, ciphertext)
        assert decrypted == plaintext

    def test_encrypt_decrypt_with_aad(self):
        """Test encryption with additional authenticated data."""
        cipher = Aegis128X2()
        key = cipher.random_key()
        nonce = cipher.random_nonce()
        plaintext = b"Secret message"
        aad = b"metadata"

        ciphertext = cipher.encrypt(key, nonce, plaintext, associated_data=aad)
        decrypted = cipher.decrypt(key, nonce, ciphertext, associated_data=aad)
        assert decrypted == plaintext

    def test_decrypt_fails_with_wrong_aad(self):
        """Test that decryption fails with incorrect AAD."""
        cipher = Aegis128X2()
        key = cipher.random_key()
        nonce = cipher.random_nonce()
        plaintext = b"Secret"

        ciphertext = cipher.encrypt(key, nonce, plaintext, associated_data=b"correct")

        with pytest.raises(DecryptionError):
            cipher.decrypt(key, nonce, ciphertext, associated_data=b"wrong")

    def test_decrypt_fails_with_tampered_ciphertext(self):
        """Test that decryption fails with tampered ciphertext."""
        cipher = Aegis128X2()
        key = cipher.random_key()
        nonce = cipher.random_nonce()
        plaintext = b"Secret"

        ciphertext = cipher.encrypt(key, nonce, plaintext)
        tampered = bytearray(ciphertext)
        tampered[0] ^= 1

        with pytest.raises(DecryptionError):
            cipher.decrypt(key, nonce, bytes(tampered))

    def test_encrypt_decrypt_detached(self):
        """Test encryption with detached tag."""
        cipher = Aegis128X2()
        key = cipher.random_key()
        nonce = cipher.random_nonce()
        plaintext = b"Hello, World!"

        ciphertext, tag = cipher.encrypt_detached(key, nonce, plaintext)
        assert len(ciphertext) == len(plaintext)
        assert len(tag) == 32

        decrypted = cipher.decrypt_detached(key, nonce, ciphertext, tag)
        assert decrypted == plaintext

    def test_tag_size_16(self):
        """Test with 16-byte tag."""
        cipher = Aegis128X2(tag_size=16)
        key = cipher.random_key()
        nonce = cipher.random_nonce()
        plaintext = b"Test"

        ciphertext = cipher.encrypt(key, nonce, plaintext)
        assert len(ciphertext) == len(plaintext) + 16

        decrypted = cipher.decrypt(key, nonce, ciphertext)
        assert decrypted == plaintext

    def test_empty_plaintext(self):
        """Test encryption of empty plaintext."""
        cipher = Aegis128X2()
        key = cipher.random_key()
        nonce = cipher.random_nonce()
        plaintext = b""

        ciphertext = cipher.encrypt(key, nonce, plaintext)
        assert len(ciphertext) == 32

        decrypted = cipher.decrypt(key, nonce, ciphertext)
        assert decrypted == plaintext

    def test_large_plaintext(self):
        """Test encryption of large plaintext."""
        cipher = Aegis128X2()
        key = cipher.random_key()
        nonce = cipher.random_nonce()
        plaintext = b"x" * 10000

        ciphertext = cipher.encrypt(key, nonce, plaintext)
        decrypted = cipher.decrypt(key, nonce, ciphertext)
        assert decrypted == plaintext

    def test_key_sizes(self):
        """Test that key and nonce sizes are correct."""
        assert Aegis128X2.KEY_SIZE == 16
        assert Aegis128X2.NONCE_SIZE == 16


class TestAEGIS128X4:
    """Tests for AEGIS-128X4."""

    def test_encrypt_decrypt_basic(self):
        """Test basic encryption and decryption."""
        cipher = Aegis128X4()
        key = cipher.random_key()
        nonce = cipher.random_nonce()
        plaintext = b"Hello, World!"

        ciphertext = cipher.encrypt(key, nonce, plaintext)
        decrypted = cipher.decrypt(key, nonce, ciphertext)
        assert decrypted == plaintext

    def test_encrypt_decrypt_with_aad(self):
        """Test encryption with additional authenticated data."""
        cipher = Aegis128X4()
        key = cipher.random_key()
        nonce = cipher.random_nonce()
        plaintext = b"Secret message"
        aad = b"metadata"

        ciphertext = cipher.encrypt(key, nonce, plaintext, associated_data=aad)
        decrypted = cipher.decrypt(key, nonce, ciphertext, associated_data=aad)
        assert decrypted == plaintext

    def test_decrypt_fails_with_tampered_ciphertext(self):
        """Test that decryption fails with tampered ciphertext."""
        cipher = Aegis128X4()
        key = cipher.random_key()
        nonce = cipher.random_nonce()
        plaintext = b"Secret"

        ciphertext = cipher.encrypt(key, nonce, plaintext)
        tampered = bytearray(ciphertext)
        tampered[0] ^= 1

        with pytest.raises(DecryptionError):
            cipher.decrypt(key, nonce, bytes(tampered))

    def test_encrypt_decrypt_detached(self):
        """Test encryption with detached tag."""
        cipher = Aegis128X4()
        key = cipher.random_key()
        nonce = cipher.random_nonce()
        plaintext = b"Hello, World!"

        ciphertext, tag = cipher.encrypt_detached(key, nonce, plaintext)
        assert len(ciphertext) == len(plaintext)
        assert len(tag) == 32

        decrypted = cipher.decrypt_detached(key, nonce, ciphertext, tag)
        assert decrypted == plaintext

    def test_key_sizes(self):
        """Test that key and nonce sizes are correct."""
        assert Aegis128X4.KEY_SIZE == 16
        assert Aegis128X4.NONCE_SIZE == 16


class TestAEGIS256X2:
    """Tests for AEGIS-256X2."""

    def test_encrypt_decrypt_basic(self):
        """Test basic encryption and decryption."""
        cipher = Aegis256X2()
        key = cipher.random_key()
        nonce = cipher.random_nonce()
        plaintext = b"Hello, World!"

        ciphertext = cipher.encrypt(key, nonce, plaintext)
        decrypted = cipher.decrypt(key, nonce, ciphertext)
        assert decrypted == plaintext

    def test_encrypt_decrypt_with_aad(self):
        """Test encryption with additional authenticated data."""
        cipher = Aegis256X2()
        key = cipher.random_key()
        nonce = cipher.random_nonce()
        plaintext = b"Secret message"
        aad = b"metadata"

        ciphertext = cipher.encrypt(key, nonce, plaintext, associated_data=aad)
        decrypted = cipher.decrypt(key, nonce, ciphertext, associated_data=aad)
        assert decrypted == plaintext

    def test_decrypt_fails_with_wrong_aad(self):
        """Test that decryption fails with incorrect AAD."""
        cipher = Aegis256X2()
        key = cipher.random_key()
        nonce = cipher.random_nonce()
        plaintext = b"Secret"

        ciphertext = cipher.encrypt(key, nonce, plaintext, associated_data=b"correct")

        with pytest.raises(DecryptionError):
            cipher.decrypt(key, nonce, ciphertext, associated_data=b"wrong")

    def test_encrypt_decrypt_detached(self):
        """Test encryption with detached tag."""
        cipher = Aegis256X2()
        key = cipher.random_key()
        nonce = cipher.random_nonce()
        plaintext = b"Hello, World!"

        ciphertext, tag = cipher.encrypt_detached(key, nonce, plaintext)
        assert len(ciphertext) == len(plaintext)
        assert len(tag) == 32

        decrypted = cipher.decrypt_detached(key, nonce, ciphertext, tag)
        assert decrypted == plaintext

    def test_tag_size_16(self):
        """Test with 16-byte tag."""
        cipher = Aegis256X2(tag_size=16)
        key = cipher.random_key()
        nonce = cipher.random_nonce()
        plaintext = b"Test"

        ciphertext = cipher.encrypt(key, nonce, plaintext)
        assert len(ciphertext) == len(plaintext) + 16

        decrypted = cipher.decrypt(key, nonce, ciphertext)
        assert decrypted == plaintext

    def test_key_sizes(self):
        """Test that key and nonce sizes are correct."""
        assert Aegis256X2.KEY_SIZE == 32
        assert Aegis256X2.NONCE_SIZE == 32


class TestAEGIS256X4:
    """Tests for AEGIS-256X4."""

    def test_encrypt_decrypt_basic(self):
        """Test basic encryption and decryption."""
        cipher = Aegis256X4()
        key = cipher.random_key()
        nonce = cipher.random_nonce()
        plaintext = b"Hello, World!"

        ciphertext = cipher.encrypt(key, nonce, plaintext)
        decrypted = cipher.decrypt(key, nonce, ciphertext)
        assert decrypted == plaintext

    def test_encrypt_decrypt_with_aad(self):
        """Test encryption with additional authenticated data."""
        cipher = Aegis256X4()
        key = cipher.random_key()
        nonce = cipher.random_nonce()
        plaintext = b"Secret message"
        aad = b"metadata"

        ciphertext = cipher.encrypt(key, nonce, plaintext, associated_data=aad)
        decrypted = cipher.decrypt(key, nonce, ciphertext, associated_data=aad)
        assert decrypted == plaintext

    def test_decrypt_fails_with_tampered_ciphertext(self):
        """Test that decryption fails with tampered ciphertext."""
        cipher = Aegis256X4()
        key = cipher.random_key()
        nonce = cipher.random_nonce()
        plaintext = b"Secret"

        ciphertext = cipher.encrypt(key, nonce, plaintext)
        tampered = bytearray(ciphertext)
        tampered[-1] ^= 1

        with pytest.raises(DecryptionError):
            cipher.decrypt(key, nonce, bytes(tampered))

    def test_encrypt_decrypt_detached(self):
        """Test encryption with detached tag."""
        cipher = Aegis256X4()
        key = cipher.random_key()
        nonce = cipher.random_nonce()
        plaintext = b"Hello, World!"

        ciphertext, tag = cipher.encrypt_detached(key, nonce, plaintext)
        assert len(ciphertext) == len(plaintext)
        assert len(tag) == 32

        decrypted = cipher.decrypt_detached(key, nonce, ciphertext, tag)
        assert decrypted == plaintext

    def test_key_sizes(self):
        """Test that key and nonce sizes are correct."""
        assert Aegis256X4.KEY_SIZE == 32
        assert Aegis256X4.NONCE_SIZE == 32


class TestCrossVariant:
    """Tests to ensure different variants are incompatible."""

    def test_different_variants_incompatible(self):
        """Test that ciphertext from one variant can't be decrypted by another."""
        plaintext = b"Test message"

        # Encrypt with AEGIS-128L
        cipher128l = Aegis128L()
        key = cipher128l.random_key()
        nonce = cipher128l.random_nonce()
        ciphertext = cipher128l.encrypt(key, nonce, plaintext)

        # Try to decrypt with AEGIS-128X2 (should fail)
        cipher128x2 = Aegis128X2()
        with pytest.raises(DecryptionError):
            cipher128x2.decrypt(key, nonce, ciphertext)


# MAC tests


class TestAEGISMAC128L:
    """Tests for AEGIS-128L MAC."""

    def test_mac_basic(self):
        """Test basic MAC generation."""
        key = AegisMac128L.random_key()
        nonce = AegisMac128L.random_nonce()
        mac = AegisMac128L(key, nonce)
        mac.update(b"test data")
        tag = mac.final()
        assert len(tag) == 32

    def test_mac_incremental(self):
        """Test incremental MAC updates."""
        key = AegisMac128L.random_key()
        nonce = AegisMac128L.random_nonce()

        # Generate MAC incrementally
        mac1 = AegisMac128L(key, nonce)
        mac1.update(b"hello ")
        mac1.update(b"world")
        tag1 = mac1.final()

        # Generate MAC all at once
        mac2 = AegisMac128L(key, nonce)
        mac2.update(b"hello world")
        tag2 = mac2.final()

        assert tag1 == tag2

    def test_mac_verify(self):
        """Test MAC verification."""
        key = AegisMac128L.random_key()
        nonce = AegisMac128L.random_nonce()

        # Generate tag
        mac1 = AegisMac128L(key, nonce)
        mac1.update(b"test data")
        tag = mac1.final()

        # Verify correct tag
        mac2 = AegisMac128L(key, nonce)
        mac2.update(b"test data")
        mac2.verify(tag)  # Should not raise

    def test_mac_verify_fails_wrong_data(self):
        """Test that MAC verification fails with wrong data."""
        key = AegisMac128L.random_key()
        nonce = AegisMac128L.random_nonce()

        mac1 = AegisMac128L(key, nonce)
        mac1.update(b"correct data")
        tag = mac1.final()

        mac2 = AegisMac128L(key, nonce)
        mac2.update(b"wrong data")
        with pytest.raises(DecryptionError):
            mac2.verify(tag)

    def test_mac_verify_fails_wrong_tag(self):
        """Test that MAC verification fails with wrong tag."""
        key = AegisMac128L.random_key()
        nonce = AegisMac128L.random_nonce()

        mac = AegisMac128L(key, nonce)
        mac.update(b"test data")
        wrong_tag = b"x" * 32
        with pytest.raises(DecryptionError):
            mac.verify(wrong_tag)

    def test_mac_tag_size_16(self):
        """Test MAC with 16-byte tag."""
        key = AegisMac128L.random_key()
        nonce = AegisMac128L.random_nonce()
        mac = AegisMac128L(key, nonce, tag_size=16)
        mac.update(b"test")
        tag = mac.final()
        assert len(tag) == 16

    def test_mac_invalid_tag_size(self):
        """Test that invalid tag sizes are rejected."""
        key = AegisMac128L.random_key()
        nonce = AegisMac128L.random_nonce()
        with pytest.raises(ValueError):
            AegisMac128L(key, nonce, tag_size=24)

    def test_mac_reset(self):
        """Test MAC reset functionality."""
        key = AegisMac128L.random_key()
        nonce = AegisMac128L.random_nonce()

        # Generate first tag
        mac = AegisMac128L(key, nonce)
        mac.update(b"first")
        tag1 = mac.final()

        # Reset and generate second tag
        mac2 = AegisMac128L(key, nonce)
        mac2.update(b"first")
        mac2.reset()
        mac2.update(b"second")
        tag2 = mac2.final()

        # Verify tags are different
        assert tag1 != tag2

        # Verify second tag is for "second"
        mac3 = AegisMac128L(key, nonce)
        mac3.update(b"second")
        mac3.verify(tag2)

    def test_mac_cannot_update_after_final(self):
        """Test that update fails after finalization."""
        key = AegisMac128L.random_key()
        nonce = AegisMac128L.random_nonce()
        mac = AegisMac128L(key, nonce)
        mac.update(b"data")
        mac.final()

        with pytest.raises(AegisError):
            mac.update(b"more data")

    def test_mac_cannot_final_twice(self):
        """Test that final can't be called twice."""
        key = AegisMac128L.random_key()
        nonce = AegisMac128L.random_nonce()
        mac = AegisMac128L(key, nonce)
        mac.update(b"data")
        mac.final()

        with pytest.raises(AegisError):
            mac.final()

    def test_mac_key_sizes(self):
        """Test that key and nonce sizes are correct."""
        assert AegisMac128L.KEY_SIZE == 16
        assert AegisMac128L.NONCE_SIZE == 16

    def test_mac_invalid_key_size(self):
        """Test that invalid key size is rejected."""
        with pytest.raises(ValueError):
            AegisMac128L(b"short", b"x" * 16)

    def test_mac_invalid_nonce_size(self):
        """Test that invalid nonce size is rejected."""
        with pytest.raises(ValueError):
            AegisMac128L(b"x" * 16, b"short")


class TestAEGISMAC256:
    """Tests for AEGIS-256 MAC."""

    def test_mac_basic(self):
        """Test basic MAC generation."""
        key = AegisMac256.random_key()
        nonce = AegisMac256.random_nonce()
        mac = AegisMac256(key, nonce)
        mac.update(b"test data")
        tag = mac.final()
        assert len(tag) == 32

    def test_mac_incremental(self):
        """Test incremental MAC updates."""
        key = AegisMac256.random_key()
        nonce = AegisMac256.random_nonce()

        mac1 = AegisMac256(key, nonce)
        mac1.update(b"hello ")
        mac1.update(b"world")
        tag1 = mac1.final()

        mac2 = AegisMac256(key, nonce)
        mac2.update(b"hello world")
        tag2 = mac2.final()

        assert tag1 == tag2

    def test_mac_verify(self):
        """Test MAC verification."""
        key = AegisMac256.random_key()
        nonce = AegisMac256.random_nonce()

        mac1 = AegisMac256(key, nonce)
        mac1.update(b"test data")
        tag = mac1.final()

        mac2 = AegisMac256(key, nonce)
        mac2.update(b"test data")
        mac2.verify(tag)

    def test_mac_key_sizes(self):
        """Test that key and nonce sizes are correct."""
        assert AegisMac256.KEY_SIZE == 32
        assert AegisMac256.NONCE_SIZE == 32


class TestAEGISMAC128X2:
    """Tests for AEGIS-128X2 MAC."""

    def test_mac_basic(self):
        """Test basic MAC generation."""
        key = AegisMac128X2.random_key()
        nonce = AegisMac128X2.random_nonce()
        mac = AegisMac128X2(key, nonce)
        mac.update(b"test data")
        tag = mac.final()
        assert len(tag) == 32

    def test_mac_verify(self):
        """Test MAC verification."""
        key = AegisMac128X2.random_key()
        nonce = AegisMac128X2.random_nonce()

        mac1 = AegisMac128X2(key, nonce)
        mac1.update(b"test data")
        tag = mac1.final()

        mac2 = AegisMac128X2(key, nonce)
        mac2.update(b"test data")
        mac2.verify(tag)

    def test_mac_key_sizes(self):
        """Test that key and nonce sizes are correct."""
        assert AegisMac128X2.KEY_SIZE == 16
        assert AegisMac128X2.NONCE_SIZE == 16


class TestAEGISMAC128X4:
    """Tests for AEGIS-128X4 MAC."""

    def test_mac_basic(self):
        """Test basic MAC generation."""
        key = AegisMac128X4.random_key()
        nonce = AegisMac128X4.random_nonce()
        mac = AegisMac128X4(key, nonce)
        mac.update(b"test data")
        tag = mac.final()
        assert len(tag) == 32

    def test_mac_key_sizes(self):
        """Test that key and nonce sizes are correct."""
        assert AegisMac128X4.KEY_SIZE == 16
        assert AegisMac128X4.NONCE_SIZE == 16


class TestAEGISMAC256X2:
    """Tests for AEGIS-256X2 MAC."""

    def test_mac_basic(self):
        """Test basic MAC generation."""
        key = AegisMac256X2.random_key()
        nonce = AegisMac256X2.random_nonce()
        mac = AegisMac256X2(key, nonce)
        mac.update(b"test data")
        tag = mac.final()
        assert len(tag) == 32

    def test_mac_key_sizes(self):
        """Test that key and nonce sizes are correct."""
        assert AegisMac256X2.KEY_SIZE == 32
        assert AegisMac256X2.NONCE_SIZE == 32


class TestAEGISMAC256X4:
    """Tests for AEGIS-256X4 MAC."""

    def test_mac_basic(self):
        """Test basic MAC generation."""
        key = AegisMac256X4.random_key()
        nonce = AegisMac256X4.random_nonce()
        mac = AegisMac256X4(key, nonce)
        mac.update(b"test data")
        tag = mac.final()
        assert len(tag) == 32

    def test_mac_key_sizes(self):
        """Test that key and nonce sizes are correct."""
        assert AegisMac256X4.KEY_SIZE == 32
        assert AegisMac256X4.NONCE_SIZE == 32


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
