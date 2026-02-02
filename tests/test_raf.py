"""Tests for RAF (Random Access Format) encrypted file API."""

import pytest

from pyaegis import (
    AegisRaf128L,
    AegisRaf128X2,
    AegisRaf128X4,
    AegisRaf256,
    AegisRaf256X2,
    AegisRaf256X4,
    BytesIOStorage,
    FileStorage,
    RAFAuthenticationError,
    RAFConfigError,
    RAFError,
    raf_open,
    raf_probe,
)


class TestBytesIOStorage:
    """Tests for BytesIOStorage backend."""

    def test_read_write_basic(self):
        """Test basic read/write operations."""
        storage = BytesIOStorage()
        storage.write_at(b"hello", 0)
        buf = bytearray(5)
        storage.read_at(buf, 0)
        assert buf == b"hello"

    def test_read_past_eof_raises(self):
        """Test that reading past EOF raises IOError."""
        storage = BytesIOStorage(b"short")
        buf = bytearray(10)
        with pytest.raises(IOError):
            storage.read_at(buf, 0)

    def test_write_extends_buffer(self):
        """Test that writing past end extends the buffer."""
        storage = BytesIOStorage()
        storage.write_at(b"hello", 10)
        assert storage.get_size() == 15
        assert storage.getvalue()[:10] == b"\x00" * 10
        assert storage.getvalue()[10:] == b"hello"

    def test_set_size_truncate(self):
        """Test truncating via set_size."""
        storage = BytesIOStorage(b"hello world")
        storage.set_size(5)
        assert storage.getvalue() == b"hello"

    def test_set_size_extend(self):
        """Test extending via set_size."""
        storage = BytesIOStorage(b"hi")
        storage.set_size(5)
        assert storage.getvalue() == b"hi\x00\x00\x00"

    def test_context_manager(self):
        """Test context manager support."""
        with BytesIOStorage(b"test") as storage:
            buf = bytearray(4)
            storage.read_at(buf, 0)
            assert buf == b"test"


class TestFileStorage:
    """Tests for FileStorage backend."""

    def test_read_write_basic(self, tmp_path):
        """Test basic file read/write operations."""
        path = tmp_path / "test.bin"
        with FileStorage(path, "w+b") as storage:
            storage.write_at(b"hello", 0)
            buf = bytearray(5)
            storage.read_at(buf, 0)
            assert buf == b"hello"

    def test_read_short_raises(self, tmp_path):
        """Test that short read raises IOError."""
        path = tmp_path / "test.bin"
        with FileStorage(path, "w+b") as storage:
            storage.write_at(b"hi", 0)
            buf = bytearray(10)
            with pytest.raises(IOError, match="Short read"):
                storage.read_at(buf, 0)

    def test_file_size(self, tmp_path):
        """Test get_size and set_size."""
        path = tmp_path / "test.bin"
        with FileStorage(path, "w+b") as storage:
            storage.write_at(b"hello world", 0)
            assert storage.get_size() == 11
            storage.set_size(5)
            assert storage.get_size() == 5

    def test_invalid_mode_raises(self, tmp_path):
        """Test that invalid mode raises ValueError."""
        path = tmp_path / "test.bin"
        with pytest.raises(ValueError, match="Unsupported mode"):
            FileStorage(path, "rb")


class TestAegisRaf128L:
    """Tests for AEGIS-128L RAF."""

    def test_create_write_read_basic(self):
        """Test creating a file, writing, closing, reopening, and reading."""
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()

        with AegisRaf128L(storage, key, create=True) as f:
            f.write(b"Hello, World!")

        with AegisRaf128L(storage, key) as f:
            assert f.read() == b"Hello, World!"

    def test_create_with_file_storage(self, tmp_path):
        """Test with FileStorage backend."""
        path = tmp_path / "test.raf"
        key = AegisRaf128L.random_key()

        with FileStorage(path, "w+b") as storage, AegisRaf128L(storage, key, create=True) as f:
            f.write(b"Hello, World!")

        with FileStorage(path, "r+b") as storage, AegisRaf128L(storage, key) as f:
            assert f.read() == b"Hello, World!"

    def test_random_access(self):
        """Test random access read/write."""
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()

        with AegisRaf128L(storage, key, create=True) as f:
            f.write(b"AAAAAAAAAA")
            f.seek(5)
            f.write(b"BBBBB")
            f.seek(0)
            assert f.read() == b"AAAAABBBBB"

    def test_pread_pwrite(self):
        """Test pread/pwrite don't update position."""
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()

        with AegisRaf128L(storage, key, create=True) as f:
            f.write(b"0123456789")
            assert f.tell() == 10

            # pread doesn't update position
            assert f.pread(3, 0) == b"012"
            assert f.tell() == 10

            # pwrite doesn't update position and preserves existing data
            f.pwrite(b"ABC", 5)
            assert f.tell() == 10

            f.seek(0)
            assert f.read() == b"01234ABC89"

    def test_read_into(self):
        """Test read_into with pre-allocated buffer."""
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()

        with AegisRaf128L(storage, key, create=True) as f:
            f.write(b"Hello, World!")

        with AegisRaf128L(storage, key) as f:
            buf = bytearray(5)
            n = f.read_into(buf)
            assert n == 5
            assert buf == b"Hello"
            assert f.tell() == 5

    def test_seek_operations(self):
        """Test seek with different whence values."""
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()

        with AegisRaf128L(storage, key, create=True) as f:
            f.write(b"0123456789")

            assert f.seek(0) == 0
            assert f.seek(5, 0) == 5
            assert f.seek(2, 1) == 7
            assert f.seek(-3, 2) == 7
            assert f.seek(0, 2) == 10

    def test_truncate(self):
        """Test file truncation."""
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()

        with AegisRaf128L(storage, key, create=True) as f:
            f.write(b"Hello, World!")
            assert f.size == 13
            f.truncate(5)
            assert f.size == 5
            f.seek(0)
            assert f.read() == b"Hello"

    def test_truncate_uses_position(self):
        """Test truncate with no argument uses current position."""
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()

        with AegisRaf128L(storage, key, create=True) as f:
            f.write(b"Hello, World!")
            f.seek(5)
            f.truncate()
            assert f.size == 5

    def test_wrong_key_fails(self):
        """Test that wrong key fails authentication."""
        storage = BytesIOStorage()
        key1 = AegisRaf128L.random_key()
        key2 = AegisRaf128L.random_key()

        with AegisRaf128L(storage, key1, create=True) as f:
            f.write(b"secret")

        with pytest.raises(RAFAuthenticationError):
            AegisRaf128L(storage, key2)

    def test_invalid_key_size_rejected(self):
        """Test that invalid key size is rejected."""
        storage = BytesIOStorage()

        with pytest.raises(ValueError, match="Key must be 16 bytes"):
            AegisRaf128L(storage, b"short", create=True)

    def test_invalid_chunk_size_rejected(self):
        """Test invalid chunk_size is rejected."""
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()

        with pytest.raises(RAFConfigError, match="chunk_size must be"):
            AegisRaf128L(storage, key, create=True, chunk_size=100)

        with pytest.raises(RAFConfigError, match="multiple of 16"):
            AegisRaf128L(storage, key, create=True, chunk_size=1025)

    def test_truncate_overwrite(self):
        """Test create with truncate=True overwrites existing file."""
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()

        with AegisRaf128L(storage, key, create=True) as f:
            f.write(b"original content")

        with AegisRaf128L(storage, key, create=True, truncate=True) as f:
            f.write(b"new")

        with AegisRaf128L(storage, key) as f:
            assert f.read() == b"new"

    def test_empty_file(self):
        """Test empty file operations."""
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()

        with AegisRaf128L(storage, key, create=True) as f:
            assert f.size == 0
            assert f.read() == b""

    def test_single_byte(self):
        """Test single byte read/write."""
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()

        with AegisRaf128L(storage, key, create=True) as f:
            f.write(b"X")
            f.seek(0)
            assert f.read() == b"X"

    def test_large_file(self):
        """Test large file operations."""
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()
        data = b"X" * 100000

        with AegisRaf128L(storage, key, create=True) as f:
            f.write(data)

        with AegisRaf128L(storage, key) as f:
            assert f.read() == data

    def test_custom_chunk_size(self):
        """Test with custom chunk size."""
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()
        chunk_size = 4096

        with AegisRaf128L(storage, key, create=True, chunk_size=chunk_size) as f:
            data = b"A" * (chunk_size * 2 + 100)
            f.write(data)

        with AegisRaf128L(storage, key) as f:
            assert f.read() == data

    def test_negative_offset_rejected(self):
        """Test that negative offsets raise ValueError."""
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()

        with AegisRaf128L(storage, key, create=True) as f:
            f.write(b"test")

            with pytest.raises(ValueError, match="non-negative"):
                f.read(10, offset=-1)
            with pytest.raises(ValueError, match="non-negative"):
                f.pread(10, -1)
            with pytest.raises(ValueError, match="non-negative"):
                f.read_into(bytearray(10), offset=-1)
            with pytest.raises(ValueError, match="non-negative"):
                f.write(b"x", offset=-1)
            with pytest.raises(ValueError, match="non-negative"):
                f.pwrite(b"x", -1)

    def test_negative_size_rejected(self):
        """Test that negative size in pread raises ValueError."""
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()

        with AegisRaf128L(storage, key, create=True) as f:
            f.write(b"test")
            with pytest.raises(ValueError, match="non-negative"):
                f.pread(-5, 0)

    def test_context_manager(self):
        """Test context manager properly closes file."""
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()

        with AegisRaf128L(storage, key, create=True) as f:
            f.write(b"test")
            assert not f.closed

        assert f.closed

    def test_operations_on_closed_file_fail(self):
        """Test that operations on closed file raise ValueError."""
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()

        f = AegisRaf128L(storage, key, create=True)
        f.write(b"test")
        f.close()

        with pytest.raises(ValueError, match="closed"):
            f.read()
        with pytest.raises(ValueError, match="closed"):
            f.write(b"x")
        with pytest.raises(ValueError, match="closed"):
            f.seek(0)
        with pytest.raises(ValueError, match="closed"):
            _ = f.size

    def test_key_sizes(self):
        """Test that key sizes are correct."""
        assert AegisRaf128L.KEY_SIZE == 16
        assert AegisRaf128L.NONCE_SIZE == 16


class TestAegisRaf256:
    """Tests for AEGIS-256 RAF."""

    def test_create_write_read_basic(self):
        """Test basic operations."""
        storage = BytesIOStorage()
        key = AegisRaf256.random_key()

        with AegisRaf256(storage, key, create=True) as f:
            f.write(b"Hello, World!")

        with AegisRaf256(storage, key) as f:
            assert f.read() == b"Hello, World!"

    def test_key_sizes(self):
        """Test that key sizes are correct."""
        assert AegisRaf256.KEY_SIZE == 32
        assert AegisRaf256.NONCE_SIZE == 32

    def test_wrong_key_fails(self):
        """Test wrong key authentication failure."""
        storage = BytesIOStorage()
        key1 = AegisRaf256.random_key()
        key2 = AegisRaf256.random_key()

        with AegisRaf256(storage, key1, create=True) as f:
            f.write(b"secret")

        with pytest.raises(RAFAuthenticationError):
            AegisRaf256(storage, key2)


class TestAegisRaf128X2:
    """Tests for AEGIS-128X2 RAF."""

    def test_create_write_read_basic(self):
        """Test basic operations."""
        storage = BytesIOStorage()
        key = AegisRaf128X2.random_key()

        with AegisRaf128X2(storage, key, create=True) as f:
            f.write(b"Hello from X2!")

        with AegisRaf128X2(storage, key) as f:
            assert f.read() == b"Hello from X2!"

    def test_key_sizes(self):
        """Test key sizes."""
        assert AegisRaf128X2.KEY_SIZE == 16
        assert AegisRaf128X2.NONCE_SIZE == 16


class TestAegisRaf128X4:
    """Tests for AEGIS-128X4 RAF."""

    def test_create_write_read_basic(self):
        """Test basic operations."""
        storage = BytesIOStorage()
        key = AegisRaf128X4.random_key()

        with AegisRaf128X4(storage, key, create=True) as f:
            f.write(b"Hello from X4!")

        with AegisRaf128X4(storage, key) as f:
            assert f.read() == b"Hello from X4!"

    def test_key_sizes(self):
        """Test key sizes."""
        assert AegisRaf128X4.KEY_SIZE == 16
        assert AegisRaf128X4.NONCE_SIZE == 16


class TestAegisRaf256X2:
    """Tests for AEGIS-256X2 RAF."""

    def test_create_write_read_basic(self):
        """Test basic operations."""
        storage = BytesIOStorage()
        key = AegisRaf256X2.random_key()

        with AegisRaf256X2(storage, key, create=True) as f:
            f.write(b"Hello from 256X2!")

        with AegisRaf256X2(storage, key) as f:
            assert f.read() == b"Hello from 256X2!"

    def test_key_sizes(self):
        """Test key sizes."""
        assert AegisRaf256X2.KEY_SIZE == 32
        assert AegisRaf256X2.NONCE_SIZE == 32


class TestAegisRaf256X4:
    """Tests for AEGIS-256X4 RAF."""

    def test_create_write_read_basic(self):
        """Test basic operations."""
        storage = BytesIOStorage()
        key = AegisRaf256X4.random_key()

        with AegisRaf256X4(storage, key, create=True) as f:
            f.write(b"Hello from 256X4!")

        with AegisRaf256X4(storage, key) as f:
            assert f.read() == b"Hello from 256X4!"

    def test_key_sizes(self):
        """Test key sizes."""
        assert AegisRaf256X4.KEY_SIZE == 32
        assert AegisRaf256X4.NONCE_SIZE == 32


class TestRafProbe:
    """Tests for raf_probe function."""

    def test_probe_128l(self):
        """Test probing AEGIS-128L file."""
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()

        with AegisRaf128L(storage, key, create=True) as f:
            f.write(b"test data")

        alg_id, chunk_size, file_size = raf_probe(storage)
        assert alg_id == AegisRaf128L.ALG_ID
        assert chunk_size == 65536
        assert file_size == 9

    def test_probe_256(self):
        """Test probing AEGIS-256 file."""
        storage = BytesIOStorage()
        key = AegisRaf256.random_key()

        with AegisRaf256(storage, key, create=True, chunk_size=4096) as f:
            f.write(b"hello")

        alg_id, chunk_size, _ = raf_probe(storage)
        assert alg_id == AegisRaf256.ALG_ID
        assert chunk_size == 4096

    def test_probe_invalid_file_fails(self):
        """Test that probing invalid file fails."""
        storage = BytesIOStorage(b"not a valid RAF file")

        with pytest.raises(RAFError):
            raf_probe(storage)


class TestRafOpen:
    """Tests for raf_open function."""

    def test_auto_detect_128l(self):
        """Test auto-detecting AEGIS-128L."""
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()

        with AegisRaf128L(storage, key, create=True) as f:
            f.write(b"test 128L")

        with raf_open(storage, key) as f:
            assert isinstance(f, AegisRaf128L)
            assert f.read() == b"test 128L"

    def test_auto_detect_256(self):
        """Test auto-detecting AEGIS-256."""
        storage = BytesIOStorage()
        key = AegisRaf256.random_key()

        with AegisRaf256(storage, key, create=True) as f:
            f.write(b"test 256")

        with raf_open(storage, key) as f:
            assert isinstance(f, AegisRaf256)
            assert f.read() == b"test 256"

    def test_auto_detect_128x2(self):
        """Test auto-detecting AEGIS-128X2."""
        storage = BytesIOStorage()
        key = AegisRaf128X2.random_key()

        with AegisRaf128X2(storage, key, create=True) as f:
            f.write(b"test 128X2")

        with raf_open(storage, key) as f:
            assert isinstance(f, AegisRaf128X2)
            assert f.read() == b"test 128X2"

    def test_wrong_key_fails(self):
        """Test raf_open with wrong key fails."""
        storage = BytesIOStorage()
        key1 = AegisRaf128L.random_key()
        key2 = AegisRaf128L.random_key()

        with AegisRaf128L(storage, key1, create=True) as f:
            f.write(b"secret")

        with pytest.raises(RAFAuthenticationError):
            raf_open(storage, key2)


class TestAlgorithmMismatch:
    """Test opening file with wrong algorithm class."""

    def test_wrong_algorithm_class_rejected(self):
        """Test that opening with wrong class is rejected."""
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()

        with AegisRaf128L(storage, key, create=True) as f:
            f.write(b"test")

        with pytest.raises(RAFConfigError, match="uses algorithm"):
            AegisRaf256(storage, AegisRaf256.random_key())


class TestChunkBoundary:
    """Tests for operations at chunk boundaries."""

    def test_exact_chunk_write(self):
        """Test writing exactly one chunk."""
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()
        chunk_size = 4096

        with AegisRaf128L(storage, key, create=True, chunk_size=chunk_size) as f:
            data = b"X" * chunk_size
            f.write(data)

        with AegisRaf128L(storage, key) as f:
            assert f.read() == data

    def test_cross_chunk_read(self):
        """Test read spanning multiple chunks."""
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()
        chunk_size = 4096

        with AegisRaf128L(storage, key, create=True, chunk_size=chunk_size) as f:
            data = b"ABCD" * chunk_size
            f.write(data)

        with AegisRaf128L(storage, key) as f:
            # Read spanning chunk boundary
            partial = f.pread(100, chunk_size - 50)
            assert len(partial) == 100

    def test_cross_chunk_write(self):
        """Test write spanning multiple chunks (overwriting)."""
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()
        chunk_size = 4096

        with AegisRaf128L(storage, key, create=True, chunk_size=chunk_size) as f:
            # Write initial data spanning two chunks
            f.write(b"0" * (chunk_size + 100))
            # Overwrite across chunk boundary
            f.pwrite(b"X" * 100, chunk_size - 50)

        with AegisRaf128L(storage, key) as f:
            data = f.read()
            assert len(data) == chunk_size + 100
            # First part unchanged
            assert data[: chunk_size - 50] == b"0" * (chunk_size - 50)
            # Overwritten part
            assert data[chunk_size - 50 : chunk_size + 50] == b"X" * 100
            # Trailing part unchanged
            assert data[chunk_size + 50 :] == b"0" * 50


class TestSync:
    """Tests for sync operation."""

    def test_sync_basic(self, tmp_path):
        """Test sync flushes to storage."""
        path = tmp_path / "test.raf"
        key = AegisRaf128L.random_key()

        with FileStorage(path, "w+b") as storage, AegisRaf128L(storage, key, create=True) as f:
            f.write(b"data to sync")
            f.sync()


class TestReadAtEOF:
    """Tests for reading at/past EOF."""

    def test_read_at_eof_returns_empty(self):
        """Test reading at EOF returns empty bytes."""
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()

        with AegisRaf128L(storage, key, create=True) as f:
            f.write(b"hello")

        with AegisRaf128L(storage, key) as f:
            f.seek(0, 2)
            assert f.read() == b""

    def test_read_partial_at_eof(self):
        """Test reading more bytes than available returns partial."""
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()

        with AegisRaf128L(storage, key, create=True) as f:
            f.write(b"hello")

        with AegisRaf128L(storage, key) as f:
            data = f.pread(100, 0)
            assert data == b"hello"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
