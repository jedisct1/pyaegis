"""
RAF (Random Access Format) encrypted file API.

Provides pread/pwrite-style access to encrypted files. Files are divided into
fixed-size chunks, each independently encrypted with a fresh nonce. This enables
efficient random access to large encrypted files without decrypting the entire file.
"""

from __future__ import annotations

import errno as errno_module
import os
from typing import Protocol, runtime_checkable

from pyaegis._aegis_ffi import ffi, lib
from pyaegis.aegis import AegisError


class RAFError(AegisError):
    """Base exception for RAF operations."""

    pass


class RAFIOError(RAFError):
    """Raised when I/O operations fail."""

    pass


class RAFAuthenticationError(RAFError):
    """Raised when chunk authentication fails (corruption/tampering)."""

    pass


class RAFConfigError(RAFError):
    """Raised for invalid configuration (chunk size, etc.)."""

    pass


# EBADMSG may not be defined on all platforms
EBADMSG = getattr(errno_module, "EBADMSG", None)


def _check_auth_error(err: int) -> bool:
    """Check if errno indicates authentication failure."""
    return EBADMSG is not None and err == EBADMSG


def _raise_io_error(err: int, operation: str) -> None:
    """Raise appropriate exception based on errno."""
    if _check_auth_error(err):
        raise RAFAuthenticationError(
            f"Chunk authentication failed during {operation} (data corrupted or tampered)"
        )
    raise RAFIOError(f"{operation} failed: errno={err}")


@runtime_checkable
class RAFStorage(Protocol):
    """Protocol for RAF backing storage.

    All operations must complete fully or raise IOError.
    Partial reads/writes are not supported.
    """

    def read_at(self, buf: bytearray, offset: int) -> None:
        """Read exactly len(buf) bytes at offset into buf.

        Raises:
            IOError: If fewer than len(buf) bytes available or I/O fails.
        """
        ...

    def write_at(self, data: bytes, offset: int) -> None:
        """Write exactly len(data) bytes at offset.

        Raises:
            IOError: If write fails.
        """
        ...

    def get_size(self) -> int:
        """Return current storage size in bytes."""
        ...

    def set_size(self, size: int) -> None:
        """Resize storage (truncate or extend)."""
        ...

    def sync(self) -> None:
        """Flush writes to durable storage. Optional, may be no-op."""
        ...


class FileStorage:
    """File-based storage using os.pread/pwrite.

    Note: Requires Unix (Linux, macOS, BSD). os.pread/pwrite are not
    available on Windows. For Windows, use a custom implementation with
    file locking and seek/read/write, or use BytesIOStorage for testing.
    """

    def __init__(self, path: str | os.PathLike, mode: str = "r+b"):
        """Open a file for RAF storage.

        Args:
            path: Path to the file
            mode: File mode. Use "w+b" or "x+b" to create new files,
                  "r+b" to open existing files for read/write.
        """
        # Convert mode to os.open flags
        if mode == "r+b":
            flags = os.O_RDWR
        elif mode == "w+b":
            flags = os.O_RDWR | os.O_CREAT | os.O_TRUNC
        elif mode == "x+b":
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
        else:
            raise ValueError(f"Unsupported mode: {mode}")

        self._fd = os.open(path, flags, 0o644)
        self._closed = False

    def read_at(self, buf: bytearray, offset: int) -> None:
        """Read exactly len(buf) bytes. Raises IOError on short read."""
        data = os.pread(self._fd, len(buf), offset)
        if len(data) != len(buf):
            raise OSError(f"Short read: expected {len(buf)}, got {len(data)}")
        buf[:] = data

    def write_at(self, data: bytes, offset: int) -> None:
        """Write exactly len(data) bytes."""
        written = os.pwrite(self._fd, data, offset)
        if written != len(data):
            raise OSError(f"Short write: expected {len(data)}, wrote {written}")

    def get_size(self) -> int:
        """Return current file size."""
        return os.fstat(self._fd).st_size

    def set_size(self, size: int) -> None:
        """Truncate or extend file to given size."""
        os.ftruncate(self._fd, size)

    def sync(self) -> None:
        """Flush file data to disk."""
        os.fsync(self._fd)

    def close(self) -> None:
        """Close the file."""
        if not self._closed:
            os.close(self._fd)
            self._closed = True

    def __enter__(self) -> FileStorage:
        return self

    def __exit__(self, *args) -> None:
        self.close()


class BytesIOStorage:
    """In-memory storage backed by bytearray.

    Thread-safe for concurrent reads, but not for concurrent writes.
    Useful for testing and small files.
    """

    def __init__(self, initial_data: bytes = b""):
        """Create in-memory storage.

        Args:
            initial_data: Optional initial contents
        """
        self._data = bytearray(initial_data)

    def read_at(self, buf: bytearray, offset: int) -> None:
        """Read exactly len(buf) bytes at offset into buf."""
        end = offset + len(buf)
        if end > len(self._data):
            raise OSError(f"Read past EOF: offset={offset}, len={len(buf)}, size={len(self._data)}")
        buf[:] = self._data[offset:end]

    def write_at(self, data: bytes, offset: int) -> None:
        """Write exactly len(data) bytes at offset."""
        end = offset + len(data)
        if end > len(self._data):
            self._data.extend(b"\x00" * (end - len(self._data)))
        self._data[offset:end] = data

    def get_size(self) -> int:
        """Return current buffer size."""
        return len(self._data)

    def set_size(self, size: int) -> None:
        """Resize buffer (truncate or extend with zeros)."""
        current = len(self._data)
        if size < current:
            del self._data[size:]
        elif size > current:
            self._data.extend(b"\x00" * (size - current))

    def sync(self) -> None:
        """No-op for in-memory storage."""
        pass

    def getvalue(self) -> bytes:
        """Return the entire buffer contents."""
        return bytes(self._data)

    def __enter__(self) -> BytesIOStorage:
        return self

    def __exit__(self, *args) -> None:
        pass


# CFFI callback wrappers
# These are module-level to avoid issues with garbage collection


@ffi.callback("int(void*, uint8_t*, size_t, uint64_t)")
def _read_at_callback(user, buf, length, offset):
    """Read callback: must read exactly `length` bytes into `buf`."""
    try:
        storage = ffi.from_handle(user)
        buf_view = ffi.buffer(buf, length)
        temp = bytearray(length)
        storage.read_at(temp, offset)
        buf_view[:] = temp
        return 0
    except Exception:
        return -1


@ffi.callback("int(void*, const uint8_t*, size_t, uint64_t)")
def _write_at_callback(user, buf, length, offset):
    """Write callback: must write exactly `length` bytes."""
    try:
        storage = ffi.from_handle(user)
        data = bytes(ffi.buffer(buf, length))
        storage.write_at(data, offset)
        return 0
    except Exception:
        return -1


@ffi.callback("int(void*, uint64_t*)")
def _get_size_callback(user, size_ptr):
    """Get size callback."""
    try:
        storage = ffi.from_handle(user)
        size_ptr[0] = storage.get_size()
        return 0
    except Exception:
        return -1


@ffi.callback("int(void*, uint64_t)")
def _set_size_callback(user, size):
    """Set size callback."""
    try:
        storage = ffi.from_handle(user)
        storage.set_size(size)
        return 0
    except Exception:
        return -1


@ffi.callback("int(void*)")
def _sync_callback(user):
    """Sync callback."""
    try:
        storage = ffi.from_handle(user)
        storage.sync()
        return 0
    except Exception:
        return -1


@ffi.callback("int(void*, uint8_t*, size_t)")
def _random_callback(user, out, length):
    """RNG callback using os.urandom."""
    try:
        random_bytes = os.urandom(length)
        ffi.memmove(out, random_bytes, length)
        return 0
    except Exception:
        return -1


def raf_probe(storage: RAFStorage) -> tuple[int, int, int]:
    """Probe an encrypted file to determine its parameters.

    WARNING: The returned values are read from the file header WITHOUT
    cryptographic verification. An attacker can modify these values.
    Only trust these values for sizing scratch buffers and selecting
    the algorithm class. The actual open() call will verify the header
    MAC with the provided key.

    Args:
        storage: Backing storage to probe

    Returns:
        Tuple of (alg_id, chunk_size, file_size)
        - alg_id: AEGIS_RAF_ALG_* constant identifying the variant
        - chunk_size: Plaintext bytes per chunk (for scratch sizing)
        - file_size: Logical plaintext file size (untrusted until open)

    Raises:
        RAFError: Invalid header magic/version or I/O failure
    """
    storage_handle = ffi.new_handle(storage)

    io = ffi.new("aegis_raf_io*")
    io.user = storage_handle
    io.read_at = _read_at_callback
    io.write_at = _write_at_callback
    io.get_size = _get_size_callback
    io.set_size = _set_size_callback
    io.sync = _sync_callback

    info = ffi.new("aegis_raf_info*")

    result = lib.aegis_raf_probe(io, info)
    if result != 0:
        raise RAFError("Failed to probe file: invalid header or I/O error")

    return (info.alg_id, info.chunk_size, info.file_size)


class _AEGISRAFBase:
    """Base class for RAF encrypted file operations."""

    KEY_SIZE: int
    NONCE_SIZE: int
    ALG_ID: int

    CHUNK_MIN: int = lib.AEGIS_RAF_CHUNK_MIN
    CHUNK_MAX: int = lib.AEGIS_RAF_CHUNK_MAX
    DEFAULT_CHUNK_SIZE: int = 65536  # 64 KB default

    _ctx_type: str
    _create_func = None
    _open_func = None
    _read_func = None
    _write_func = None
    _truncate_func = None
    _get_size_func = None
    _sync_func = None
    _close_func = None
    _scratch_size_func = None

    def __init__(
        self,
        storage: RAFStorage,
        key: bytes,
        *,
        chunk_size: int = 65536,
        create: bool = False,
        truncate: bool = False,
        _probe_result: tuple[int, int] | None = None,
    ):
        """Open or create an encrypted RAF file.

        Args:
            storage: Backing storage implementing RAFStorage protocol
            key: Master encryption key
            chunk_size: Plaintext bytes per chunk (1KB-1MB, must be multiple of 16,
                       used only for create; ignored when opening existing files)
            create: If True, create a new file (fails if exists without truncate)
            truncate: If True with create, overwrite existing file
            _probe_result: Internal. Tuple of (alg_id, chunk_size) from prior probe,
                          to avoid double-probing when called via raf_open().

        Raises:
            RAFConfigError: Invalid chunk_size or key length mismatch
            RAFIOError: I/O failure during open/create
            RAFAuthenticationError: Header MAC verification failed (wrong key)
        """
        self._check_key(key)
        self._closed = False
        self._position = 0

        if create:
            if not (self.CHUNK_MIN <= chunk_size <= self.CHUNK_MAX):
                raise RAFConfigError(
                    f"chunk_size must be {self.CHUNK_MIN}-{self.CHUNK_MAX}, got {chunk_size}"
                )
            if chunk_size % 16 != 0:
                raise RAFConfigError(f"chunk_size must be multiple of 16, got {chunk_size}")
            actual_chunk_size = chunk_size
        else:
            if _probe_result is not None:
                alg_id, actual_chunk_size = _probe_result
            else:
                alg_id, actual_chunk_size, _ = raf_probe(storage)

            if alg_id != self.ALG_ID:
                raise RAFConfigError(f"File uses algorithm {alg_id}, expected {self.ALG_ID}")

        self._storage = storage
        self._storage_handle = ffi.new_handle(storage)

        self._ctx = ffi.new(f"{self._ctx_type}*")
        self._raw_scratch, self._scratch = self._allocate_scratch(actual_chunk_size)

        self._io = ffi.new("aegis_raf_io*")
        self._io.user = self._storage_handle
        self._io.read_at = _read_at_callback
        self._io.write_at = _write_at_callback
        self._io.get_size = _get_size_callback
        self._io.set_size = _set_size_callback
        self._io.sync = _sync_callback

        self._rng = ffi.new("aegis_raf_rng*")
        self._rng.user = ffi.NULL
        self._rng.random = _random_callback

        flags = 0
        if create:
            flags |= lib.AEGIS_RAF_CREATE
            if truncate:
                flags |= lib.AEGIS_RAF_TRUNCATE

        self._config = ffi.new("aegis_raf_config*")
        self._config.scratch = self._scratch
        self._config.merkle = ffi.NULL
        self._config.chunk_size = actual_chunk_size
        self._config.flags = flags

        if create:
            result = self._create_func(self._ctx, self._io, self._rng, self._config, key)
        else:
            result = self._open_func(self._ctx, self._io, self._rng, self._config, key)

        if result != 0:
            err = ffi.errno
            if err == errno_module.EEXIST:
                raise RAFError("File exists (use truncate=True to overwrite)")
            elif err == errno_module.ENOENT:
                raise RAFError("File not found (use create=True to create)")
            elif _check_auth_error(err):
                raise RAFAuthenticationError("Header MAC verification failed (wrong key?)")
            else:
                raise RAFIOError(f"Failed to {'create' if create else 'open'} file")

    def _check_key(self, key: bytes) -> None:
        """Validate key length."""
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be {self.KEY_SIZE} bytes, got {len(key)}")

    def _allocate_scratch(self, chunk_size: int) -> tuple[bytearray, ffi.CData]:
        """Allocate aligned scratch buffer."""
        size = self._scratch_size_func(chunk_size)
        raw = bytearray(size + 64)
        raw_ptr = ffi.from_buffer(raw)
        raw_addr = int(ffi.cast("uintptr_t", raw_ptr))
        aligned_addr = (raw_addr + 63) & ~63
        offset = aligned_addr - raw_addr

        scratch = ffi.new("aegis_raf_scratch*")
        scratch.buf = ffi.cast("uint8_t*", raw_ptr) + offset
        scratch.len = size

        return raw, scratch

    @classmethod
    def random_key(cls) -> bytes:
        """Generate a random key suitable for this cipher."""
        return os.urandom(cls.KEY_SIZE)

    def read(self, size: int = -1, offset: int | None = None) -> bytes:
        """Read and decrypt bytes. Updates internal position.

        Args:
            size: Number of bytes to read (-1 for all remaining)
            offset: Position to read from (None uses current position)

        Returns:
            Decrypted bytes (may be fewer than requested at EOF)

        Raises:
            RAFIOError: I/O failure
            RAFAuthenticationError: Chunk authentication failed
        """
        if self._closed:
            raise ValueError("I/O operation on closed file")

        if offset is None:
            offset = self._position
        elif offset < 0:
            raise ValueError(f"offset must be non-negative, got {offset}")

        if size < 0:
            size = max(0, self.size - offset)

        if size == 0:
            return b""

        out = bytearray(size)
        out_ptr = ffi.from_buffer(out)
        bytes_read = ffi.new("size_t*")

        result = self._read_func(self._ctx, out_ptr, bytes_read, size, offset)

        if result != 0:
            _raise_io_error(ffi.errno, "read")

        actual = bytes_read[0]
        self._position = offset + actual

        return bytes(out[:actual])

    def pread(self, size: int, offset: int) -> bytes:
        """Read at offset without updating position (like os.pread).

        Args:
            size: Number of bytes to read
            offset: Position to read from

        Returns:
            Decrypted bytes (may be fewer at EOF)
        """
        if self._closed:
            raise ValueError("I/O operation on closed file")

        if offset < 0:
            raise ValueError(f"offset must be non-negative, got {offset}")
        if size < 0:
            raise ValueError(f"size must be non-negative, got {size}")
        if size == 0:
            return b""

        out = bytearray(size)
        out_ptr = ffi.from_buffer(out)
        bytes_read = ffi.new("size_t*")

        result = self._read_func(self._ctx, out_ptr, bytes_read, size, offset)

        if result != 0:
            _raise_io_error(ffi.errno, "pread")

        return bytes(out[: bytes_read[0]])

    def read_into(self, buf: bytearray, offset: int | None = None) -> int:
        """Read and decrypt into pre-allocated buffer. Updates position.

        Args:
            buf: Buffer to read into (reads up to len(buf) bytes)
            offset: Position to read from (None uses current position)

        Returns:
            Number of bytes actually read
        """
        if self._closed:
            raise ValueError("I/O operation on closed file")

        if offset is None:
            offset = self._position
        elif offset < 0:
            raise ValueError(f"offset must be non-negative, got {offset}")

        if len(buf) == 0:
            return 0

        buf_ptr = ffi.from_buffer(buf)
        bytes_read = ffi.new("size_t*")

        result = self._read_func(self._ctx, buf_ptr, bytes_read, len(buf), offset)

        if result != 0:
            _raise_io_error(ffi.errno, "read_into")

        actual = bytes_read[0]
        self._position = offset + actual
        return actual

    def write(self, data: bytes, offset: int | None = None) -> int:
        """Encrypt and write bytes. Updates internal position.

        Args:
            data: Data to encrypt and write
            offset: Position to write at (None uses current position)

        Returns:
            Number of bytes written (always len(data) on success)

        Raises:
            RAFIOError: I/O failure
            RAFAuthenticationError: Partial chunk read-modify-write failed
        """
        if self._closed:
            raise ValueError("I/O operation on closed file")

        if offset is None:
            offset = self._position
        elif offset < 0:
            raise ValueError(f"offset must be non-negative, got {offset}")

        if len(data) == 0:
            return 0

        bytes_written = ffi.new("size_t*")
        result = self._write_func(self._ctx, bytes_written, data, len(data), offset)

        if result != 0:
            _raise_io_error(ffi.errno, "write")

        self._position = offset + bytes_written[0]
        return bytes_written[0]

    def pwrite(self, data: bytes, offset: int) -> int:
        """Write at offset without updating position (like os.pwrite).

        Args:
            data: Data to encrypt and write
            offset: Position to write at

        Returns:
            Number of bytes written
        """
        if self._closed:
            raise ValueError("I/O operation on closed file")

        if offset < 0:
            raise ValueError(f"offset must be non-negative, got {offset}")

        if len(data) == 0:
            return 0

        bytes_written = ffi.new("size_t*")
        result = self._write_func(self._ctx, bytes_written, data, len(data), offset)

        if result != 0:
            _raise_io_error(ffi.errno, "pwrite")

        return bytes_written[0]

    def truncate(self, size: int | None = None) -> int:
        """Resize the file.

        Args:
            size: New size (None uses current position)

        Returns:
            New file size
        """
        if self._closed:
            raise ValueError("I/O operation on closed file")

        if size is None:
            size = self._position

        result = self._truncate_func(self._ctx, size)
        if result != 0:
            _raise_io_error(ffi.errno, "truncate")

        return size

    def seek(self, offset: int, whence: int = 0) -> int:
        """Move the file position.

        Args:
            offset: Position offset
            whence: 0=absolute, 1=relative, 2=from end

        Returns:
            New absolute position
        """
        if self._closed:
            raise ValueError("I/O operation on closed file")

        if whence == 0:
            new_pos = offset
        elif whence == 1:
            new_pos = self._position + offset
        elif whence == 2:
            new_pos = self.size + offset
        else:
            raise ValueError(f"Invalid whence: {whence}")

        if new_pos < 0:
            raise ValueError(f"Negative seek position: {new_pos}")

        self._position = new_pos
        return new_pos

    def tell(self) -> int:
        """Return current position."""
        return self._position

    @property
    def size(self) -> int:
        """Return logical plaintext file size."""
        if self._closed:
            raise ValueError("I/O operation on closed file")

        size_ptr = ffi.new("uint64_t*")
        result = self._get_size_func(self._ctx, size_ptr)
        if result != 0:
            _raise_io_error(ffi.errno, "get_size")

        return size_ptr[0]

    def sync(self) -> None:
        """Flush writes to backing storage."""
        if self._closed:
            raise ValueError("I/O operation on closed file")

        result = self._sync_func(self._ctx)
        if result != 0:
            _raise_io_error(ffi.errno, "sync")

    def close(self) -> None:
        """Close the file and zeroize key material."""
        if not self._closed:
            self._close_func(self._ctx)
            self._closed = True

    def __enter__(self) -> _AEGISRAFBase:
        return self

    def __exit__(self, *args) -> None:
        self.close()

    @property
    def closed(self) -> bool:
        """True if the file has been closed."""
        return self._closed


class AegisRaf128L(_AEGISRAFBase):
    """RAF encrypted file using AEGIS-128L."""

    KEY_SIZE = 16
    NONCE_SIZE = 16
    ALG_ID = lib.AEGIS_RAF_ALG_128L

    _ctx_type = "aegis128l_raf_ctx"
    _create_func = staticmethod(lib.aegis128l_raf_create)
    _open_func = staticmethod(lib.aegis128l_raf_open)
    _read_func = staticmethod(lib.aegis128l_raf_read)
    _write_func = staticmethod(lib.aegis128l_raf_write)
    _truncate_func = staticmethod(lib.aegis128l_raf_truncate)
    _get_size_func = staticmethod(lib.aegis128l_raf_get_size)
    _sync_func = staticmethod(lib.aegis128l_raf_sync)
    _close_func = staticmethod(lib.aegis128l_raf_close)
    _scratch_size_func = staticmethod(lib.aegis128l_raf_scratch_size)


class AegisRaf256(_AEGISRAFBase):
    """RAF encrypted file using AEGIS-256."""

    KEY_SIZE = 32
    NONCE_SIZE = 32
    ALG_ID = lib.AEGIS_RAF_ALG_256

    _ctx_type = "aegis256_raf_ctx"
    _create_func = staticmethod(lib.aegis256_raf_create)
    _open_func = staticmethod(lib.aegis256_raf_open)
    _read_func = staticmethod(lib.aegis256_raf_read)
    _write_func = staticmethod(lib.aegis256_raf_write)
    _truncate_func = staticmethod(lib.aegis256_raf_truncate)
    _get_size_func = staticmethod(lib.aegis256_raf_get_size)
    _sync_func = staticmethod(lib.aegis256_raf_sync)
    _close_func = staticmethod(lib.aegis256_raf_close)
    _scratch_size_func = staticmethod(lib.aegis256_raf_scratch_size)


class AegisRaf128X2(_AEGISRAFBase):
    """RAF encrypted file using AEGIS-128X2."""

    KEY_SIZE = 16
    NONCE_SIZE = 16
    ALG_ID = lib.AEGIS_RAF_ALG_128X2

    _ctx_type = "aegis128x2_raf_ctx"
    _create_func = staticmethod(lib.aegis128x2_raf_create)
    _open_func = staticmethod(lib.aegis128x2_raf_open)
    _read_func = staticmethod(lib.aegis128x2_raf_read)
    _write_func = staticmethod(lib.aegis128x2_raf_write)
    _truncate_func = staticmethod(lib.aegis128x2_raf_truncate)
    _get_size_func = staticmethod(lib.aegis128x2_raf_get_size)
    _sync_func = staticmethod(lib.aegis128x2_raf_sync)
    _close_func = staticmethod(lib.aegis128x2_raf_close)
    _scratch_size_func = staticmethod(lib.aegis128x2_raf_scratch_size)


class AegisRaf128X4(_AEGISRAFBase):
    """RAF encrypted file using AEGIS-128X4."""

    KEY_SIZE = 16
    NONCE_SIZE = 16
    ALG_ID = lib.AEGIS_RAF_ALG_128X4

    _ctx_type = "aegis128x4_raf_ctx"
    _create_func = staticmethod(lib.aegis128x4_raf_create)
    _open_func = staticmethod(lib.aegis128x4_raf_open)
    _read_func = staticmethod(lib.aegis128x4_raf_read)
    _write_func = staticmethod(lib.aegis128x4_raf_write)
    _truncate_func = staticmethod(lib.aegis128x4_raf_truncate)
    _get_size_func = staticmethod(lib.aegis128x4_raf_get_size)
    _sync_func = staticmethod(lib.aegis128x4_raf_sync)
    _close_func = staticmethod(lib.aegis128x4_raf_close)
    _scratch_size_func = staticmethod(lib.aegis128x4_raf_scratch_size)


class AegisRaf256X2(_AEGISRAFBase):
    """RAF encrypted file using AEGIS-256X2."""

    KEY_SIZE = 32
    NONCE_SIZE = 32
    ALG_ID = lib.AEGIS_RAF_ALG_256X2

    _ctx_type = "aegis256x2_raf_ctx"
    _create_func = staticmethod(lib.aegis256x2_raf_create)
    _open_func = staticmethod(lib.aegis256x2_raf_open)
    _read_func = staticmethod(lib.aegis256x2_raf_read)
    _write_func = staticmethod(lib.aegis256x2_raf_write)
    _truncate_func = staticmethod(lib.aegis256x2_raf_truncate)
    _get_size_func = staticmethod(lib.aegis256x2_raf_get_size)
    _sync_func = staticmethod(lib.aegis256x2_raf_sync)
    _close_func = staticmethod(lib.aegis256x2_raf_close)
    _scratch_size_func = staticmethod(lib.aegis256x2_raf_scratch_size)


class AegisRaf256X4(_AEGISRAFBase):
    """RAF encrypted file using AEGIS-256X4."""

    KEY_SIZE = 32
    NONCE_SIZE = 32
    ALG_ID = lib.AEGIS_RAF_ALG_256X4

    _ctx_type = "aegis256x4_raf_ctx"
    _create_func = staticmethod(lib.aegis256x4_raf_create)
    _open_func = staticmethod(lib.aegis256x4_raf_open)
    _read_func = staticmethod(lib.aegis256x4_raf_read)
    _write_func = staticmethod(lib.aegis256x4_raf_write)
    _truncate_func = staticmethod(lib.aegis256x4_raf_truncate)
    _get_size_func = staticmethod(lib.aegis256x4_raf_get_size)
    _sync_func = staticmethod(lib.aegis256x4_raf_sync)
    _close_func = staticmethod(lib.aegis256x4_raf_close)
    _scratch_size_func = staticmethod(lib.aegis256x4_raf_scratch_size)


_ALG_MAP = {
    lib.AEGIS_RAF_ALG_128L: AegisRaf128L,
    lib.AEGIS_RAF_ALG_128X2: AegisRaf128X2,
    lib.AEGIS_RAF_ALG_128X4: AegisRaf128X4,
    lib.AEGIS_RAF_ALG_256: AegisRaf256,
    lib.AEGIS_RAF_ALG_256X2: AegisRaf256X2,
    lib.AEGIS_RAF_ALG_256X4: AegisRaf256X4,
}


def raf_open(storage: RAFStorage, key: bytes, **kwargs) -> _AEGISRAFBase:
    """Open an encrypted file, auto-detecting the algorithm.

    Probes the file header to determine which AEGIS variant to use,
    then opens the file with the appropriate class.

    Args:
        storage: Backing storage
        key: Master key (must match the variant's key size)
        **kwargs: Passed to the RAF class constructor

    Returns:
        Appropriate AegisRaf* instance

    Raises:
        RAFError: Unknown algorithm or I/O failure
        RAFAuthenticationError: Header MAC verification failed
    """
    alg_id, chunk_size, _ = raf_probe(storage)

    cls = _ALG_MAP.get(alg_id)
    if cls is None:
        raise RAFError(f"Unknown algorithm ID: {alg_id}")

    return cls(storage, key, _probe_result=(alg_id, chunk_size), **kwargs)
