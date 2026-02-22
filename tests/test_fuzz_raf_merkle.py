"""Fuzz tests for RAF and Merkle tree features.

Exercises random operation sequences, edge cases, and consistency invariants
to verify reliability of the encrypted random-access file and Merkle tree.
"""

import hashlib
import os
import random

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
    RAFIOError,
    raf_open,
    raf_probe,
)

ALL_RAF_CLASSES = [
    AegisRaf128L,
    AegisRaf256,
    AegisRaf128X2,
    AegisRaf128X4,
    AegisRaf256X2,
    AegisRaf256X4,
]

VALID_CHUNK_SIZES = [1024, 2048, 4096, 16384, 65536]


class RefFile:
    """Reference in-memory plaintext file for oracle comparison."""

    def __init__(self):
        self._data = bytearray()
        self._pos = 0

    @property
    def size(self):
        return len(self._data)

    def write(self, data, offset=None):
        if offset is None:
            offset = self._pos
        end = offset + len(data)
        if end > len(self._data):
            self._data.extend(b"\x00" * (end - len(self._data)))
        self._data[offset : offset + len(data)] = data
        self._pos = end
        return len(data)

    def pwrite(self, data, offset):
        end = offset + len(data)
        if end > len(self._data):
            self._data.extend(b"\x00" * (end - len(self._data)))
        self._data[offset : offset + len(data)] = data
        return len(data)

    def read(self, size=-1, offset=None):
        if offset is None:
            offset = self._pos
        if size < 0:
            size = max(0, len(self._data) - offset)
        result = bytes(self._data[offset : offset + size])
        self._pos = offset + len(result)
        return result

    def pread(self, size, offset):
        return bytes(self._data[offset : offset + size])

    def truncate(self, size=None):
        if size is None:
            size = self._pos
        if size < len(self._data):
            self._data = self._data[:size]
        else:
            self._data.extend(b"\x00" * (size - len(self._data)))
        return size

    def seek(self, offset, whence=0):
        if whence == 0:
            self._pos = offset
        elif whence == 1:
            self._pos += offset
        elif whence == 2:
            self._pos = len(self._data) + offset
        self._pos = max(0, self._pos)
        return self._pos

    def tell(self):
        return self._pos


def random_data(max_size=8192):
    """Generate random data of random length."""
    size = random.randint(0, max_size)
    return os.urandom(size)


class TestFuzzRAFRandomOps:
    """Random operation sequences compared against a reference oracle."""

    @pytest.mark.parametrize("seed", range(20))
    @pytest.mark.parametrize("cls", [AegisRaf128L, AegisRaf256], ids=lambda c: c.__name__)
    def test_random_ops_no_merkle(self, seed, cls):
        """Random write/read/seek/truncate ops match reference."""
        rng = random.Random(seed)
        storage = BytesIOStorage()
        key = cls.random_key()
        chunk_size = rng.choice([1024, 2048, 4096])
        ref = RefFile()

        with cls(storage, key, create=True, chunk_size=chunk_size) as f:
            for _ in range(50):
                op = rng.choice(
                    [
                        "write",
                        "write",
                        "pwrite",
                        "read",
                        "pread",
                        "seek",
                        "truncate",
                        "read_all",
                        "size",
                    ]
                )
                self._do_op(rng, f, ref, op)

    @pytest.mark.parametrize("seed", range(20))
    def test_random_ops_with_merkle(self, seed):
        """Random ops with merkle=True; root stays consistent."""
        rng = random.Random(seed)
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()
        chunk_size = rng.choice([1024, 2048])
        ref = RefFile()

        with AegisRaf128L(
            storage,
            key,
            create=True,
            chunk_size=chunk_size,
            merkle=True,
            merkle_max_chunks=256,
        ) as f:
            for _ in range(40):
                op = rng.choice(
                    [
                        "write",
                        "write",
                        "pwrite",
                        "read",
                        "pread",
                        "seek",
                        "truncate",
                        "read_all",
                        "size",
                    ]
                )
                self._do_op(rng, f, ref, op, max_data=chunk_size * 2)

            root = f.root_hash
            assert root is not None and len(root) == 32

        # Reopen and verify
        with AegisRaf128L(storage, key, merkle=True, merkle_max_chunks=256) as f:
            f.merkle_rebuild()
            assert f.root_hash == root
            assert f.merkle_verify() is None
            # Data still matches reference
            assert f.pread(ref.size, 0) == bytes(ref._data)

    def _do_op(self, rng, f, ref, op, max_data=4096):
        if op == "write":
            data = os.urandom(rng.randint(0, max_data))
            # Sometimes write at current pos, sometimes at explicit offset
            if rng.random() < 0.3 and ref.size > 0:
                offset = rng.randint(0, ref.size)
                f.write(data, offset=offset)
                ref.write(data, offset=offset)
            else:
                f.write(data)
                ref.write(data)

        elif op == "pwrite":
            data = os.urandom(rng.randint(0, max_data))
            offset = rng.randint(0, max(1, ref.size))
            f.pwrite(data, offset)
            ref.pwrite(data, offset)

        elif op == "read":
            size = rng.randint(0, max_data)
            got = f.read(size)
            expected = ref.read(size)
            assert got == expected, f"read({size}): got {len(got)} bytes, expected {len(expected)}"

        elif op == "pread":
            if ref.size > 0:
                offset = rng.randint(0, ref.size - 1)
                size = rng.randint(0, ref.size - offset + 100)
            else:
                offset = 0
                size = rng.randint(0, 100)
            got = f.pread(size, offset)
            expected = ref.pread(size, offset)
            assert got == expected

        elif op == "read_all":
            offset = rng.randint(0, max(1, ref.size))
            f.seek(offset)
            ref.seek(offset)
            got = f.read(-1)
            expected = ref.read(-1)
            assert got == expected

        elif op == "seek":
            whence = rng.choice([0, 1, 2])
            if whence == 0:
                offset = rng.randint(0, max(1, ref.size + 100))
            elif whence == 1:
                # Avoid negative resulting position
                offset = rng.randint(-ref.tell(), ref.size + 50)
            else:
                offset = rng.randint(-ref.size, 0) if ref.size > 0 else 0
            new_pos = f.seek(offset, whence)
            ref_pos = ref.seek(offset, whence)
            assert new_pos == ref_pos, f"seek({offset}, {whence}): {new_pos} != {ref_pos}"

        elif op == "truncate":
            new_size = rng.randint(0, max(1, ref.size + 100))
            got = f.truncate(new_size)
            expected = ref.truncate(new_size)
            assert got == expected

        elif op == "size":
            assert f.size == ref.size


class TestFuzzMerkleConsistency:
    """Merkle tree consistency under random operations."""

    @pytest.mark.parametrize("seed", range(10))
    @pytest.mark.parametrize("cls", [AegisRaf128L, AegisRaf256], ids=lambda c: c.__name__)
    def test_merkle_rebuild_always_matches(self, seed, cls):
        """After random writes, close/reopen/rebuild always reproduces root."""
        rng = random.Random(seed)
        storage = BytesIOStorage()
        key = cls.random_key()
        chunk_size = 1024

        with cls(
            storage, key, create=True, chunk_size=chunk_size, merkle=True, merkle_max_chunks=128
        ) as f:
            # Do random writes
            for _ in range(rng.randint(5, 20)):
                data = os.urandom(rng.randint(1, chunk_size * 3))
                if rng.random() < 0.5 and f.size > 0:
                    offset = rng.randint(0, f.size)
                    f.pwrite(data, offset)
                else:
                    f.write(data)
            root = f.root_hash

        with cls(storage, key, merkle=True, merkle_max_chunks=128) as f:
            f.merkle_rebuild()
            assert f.root_hash == root
            assert f.merkle_verify() is None

    @pytest.mark.parametrize("seed", range(10))
    def test_verify_root_after_random_ops(self, seed):
        """verify_root succeeds after random ops."""
        rng = random.Random(seed)
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()

        with AegisRaf128L(
            storage, key, create=True, chunk_size=1024, merkle=True, merkle_max_chunks=128
        ) as f:
            for _ in range(rng.randint(3, 15)):
                data = os.urandom(rng.randint(1, 3000))
                f.write(data)

            # Also some truncations
            if f.size > 0 and rng.random() < 0.3:
                f.truncate(rng.randint(0, f.size))

            root = f.root_hash

        with AegisRaf128L(storage, key, merkle=True, merkle_max_chunks=128) as f:
            f.verify_root(root)

    @pytest.mark.parametrize("seed", range(10))
    def test_merkle_root_deterministic_across_write_patterns(self, seed):
        """Different write patterns for same content produce same root after rebuild."""
        rng = random.Random(seed)
        key = AegisRaf128L.random_key()
        total_size = rng.randint(100, 4000)
        full_data = os.urandom(total_size)

        # Pattern 1: single write
        s1 = BytesIOStorage()
        with AegisRaf128L(
            s1, key, create=True, chunk_size=1024, merkle=True, merkle_max_chunks=64
        ) as f:
            f.write(full_data)
            root1 = f.root_hash

        # Reopen and rebuild - must match
        with AegisRaf128L(s1, key, merkle=True, merkle_max_chunks=64) as f:
            f.merkle_rebuild()
            assert f.root_hash == root1

        # Pattern 2: chunked writes to same file (truncate and rewrite)
        with AegisRaf128L(s1, key, merkle=True, merkle_max_chunks=64) as f:
            f.merkle_rebuild()
            f.truncate(0)
            pos = 0
            while pos < total_size:
                chunk = rng.randint(1, min(500, total_size - pos))
                f.write(full_data[pos : pos + chunk])
                pos += chunk
            root2 = f.root_hash

        # Pattern 3: pwrite in random order to same file
        with AegisRaf128L(s1, key, merkle=True, merkle_max_chunks=64) as f:
            f.merkle_rebuild()
            f.truncate(0)
            f.write(b"\x00" * total_size)
            offsets = list(range(0, total_size, 100))
            rng.shuffle(offsets)
            for off in offsets:
                end = min(off + 100, total_size)
                f.pwrite(full_data[off:end], off)
            root3 = f.root_hash

        assert root1 == root2
        assert root1 == root3


class TestFuzzMerkleTampering:
    """Detect tampering in ciphertext with Merkle verification."""

    @pytest.mark.parametrize("seed", range(15))
    def test_tamper_random_byte_detected(self, seed):
        """Flipping a random byte in the ciphertext is detected by rebuild or verify."""
        rng = random.Random(seed)
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()

        with AegisRaf128L(
            storage, key, create=True, chunk_size=1024, merkle=True, merkle_max_chunks=64
        ) as f:
            data = os.urandom(rng.randint(100, 5000))
            f.write(data)
            original_root = f.root_hash

        raw = storage._data
        # Skip the 92-byte header to tamper only chunk data
        if len(raw) > 100:
            tamper_pos = rng.randint(92, len(raw) - 1)
            raw[tamper_pos] ^= rng.randint(1, 255)

            # Either rebuild fails (auth error) or verify detects mismatch
            try:
                with AegisRaf128L(storage, key, merkle=True, merkle_max_chunks=64) as f:
                    f.merkle_rebuild()
                    result = f.merkle_verify()
                    # If rebuild succeeded, verify should find mismatch
                    # OR the root changed
                    assert result is not None or f.root_hash != original_root
            except (RAFAuthenticationError, RAFIOError):
                pass  # Expected: tampered chunk fails authentication

    @pytest.mark.parametrize("seed", range(10))
    def test_tamper_multiple_bytes_detected(self, seed):
        """Flipping multiple random bytes is detected."""
        rng = random.Random(seed)
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()

        with AegisRaf128L(
            storage, key, create=True, chunk_size=1024, merkle=True, merkle_max_chunks=64
        ) as f:
            f.write(os.urandom(rng.randint(2000, 8000)))
            original_root = f.root_hash

        raw = storage._data
        # Tamper 3-10 random bytes
        n_tampers = rng.randint(3, 10)
        for _ in range(n_tampers):
            if len(raw) > 100:
                pos = rng.randint(92, len(raw) - 1)
                raw[pos] ^= rng.randint(1, 255)

        try:
            with AegisRaf128L(storage, key, merkle=True, merkle_max_chunks=64) as f:
                f.merkle_rebuild()
                result = f.merkle_verify()
                assert result is not None or f.root_hash != original_root
        except (RAFAuthenticationError, RAFIOError):
            pass


class TestFuzzChunkBoundaries:
    """Test operations at exact chunk boundaries and crossing them."""

    @pytest.mark.parametrize("chunk_size", [1024, 2048])
    @pytest.mark.parametrize("seed", range(5))
    def test_write_at_chunk_boundaries(self, chunk_size, seed):
        """Writes that start/end/cross chunk boundaries."""
        rng = random.Random(seed)
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()
        ref = RefFile()

        with AegisRaf128L(
            storage, key, create=True, chunk_size=chunk_size, merkle=True, merkle_max_chunks=64
        ) as f:
            for _i in range(20):
                # Choose offsets near chunk boundaries
                chunk_idx = rng.randint(0, 5)
                boundary = chunk_idx * chunk_size
                offset = boundary + rng.choice([-2, -1, 0, 1, 2, chunk_size // 2])
                offset = max(0, offset)
                size = rng.choice(
                    [
                        1,
                        chunk_size - 1,
                        chunk_size,
                        chunk_size + 1,
                        chunk_size * 2,
                        rng.randint(1, chunk_size * 3),
                    ]
                )
                data = os.urandom(size)

                f.pwrite(data, offset)
                ref.pwrite(data, offset)

            # Verify full content matches
            assert f.size == ref.size
            assert f.pread(f.size, 0) == bytes(ref._data)

            root = f.root_hash

        # Verify merkle
        with AegisRaf128L(storage, key, merkle=True, merkle_max_chunks=64) as f:
            f.merkle_rebuild()
            assert f.root_hash == root
            assert f.merkle_verify() is None

    @pytest.mark.parametrize("seed", range(5))
    def test_read_across_chunk_boundaries(self, seed):
        """Reads that span multiple chunks."""
        rng = random.Random(seed)
        chunk_size = 1024
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()

        total = chunk_size * 5
        data = os.urandom(total)

        with AegisRaf128L(storage, key, create=True, chunk_size=chunk_size) as f:
            f.write(data)

            # Random reads crossing boundaries
            for _ in range(30):
                offset = rng.randint(0, total - 1)
                size = rng.randint(1, total - offset)
                got = f.pread(size, offset)
                assert got == data[offset : offset + size]


class TestFuzzTruncate:
    """Fuzz truncation combined with writes and merkle."""

    @pytest.mark.parametrize("seed", range(10))
    def test_truncate_and_rewrite(self, seed):
        """Truncate to various sizes then rewrite; data and merkle stay consistent."""
        rng = random.Random(seed)
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()
        ref = RefFile()

        with AegisRaf128L(
            storage, key, create=True, chunk_size=1024, merkle=True, merkle_max_chunks=128
        ) as f:
            # Initial write
            data = os.urandom(rng.randint(500, 5000))
            f.write(data)
            ref.write(data)

            for _ in range(15):
                op = rng.choice(["truncate", "write", "pwrite"])
                if op == "truncate":
                    new_size = rng.randint(0, ref.size + 500)
                    f.truncate(new_size)
                    ref.truncate(new_size)
                elif op == "write":
                    d = os.urandom(rng.randint(0, 2000))
                    f.write(d)
                    ref.write(d)
                elif op == "pwrite":
                    d = os.urandom(rng.randint(0, 1000))
                    off = rng.randint(0, max(1, ref.size))
                    f.pwrite(d, off)
                    ref.pwrite(d, off)

            assert f.size == ref.size
            if ref.size > 0:
                assert f.pread(ref.size, 0) == bytes(ref._data)

            root = f.root_hash

        # Reopen and verify
        with AegisRaf128L(storage, key, merkle=True, merkle_max_chunks=128) as f:
            f.merkle_rebuild()
            assert f.root_hash == root


class TestFuzzEmptyAndTiny:
    """Edge cases with empty files and tiny writes."""

    def test_empty_file_merkle(self):
        """Create empty file with merkle, root_hash is valid."""
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()

        with AegisRaf128L(storage, key, create=True, merkle=True) as f:
            root = f.root_hash
            assert root is not None
            assert len(root) == 32

    def test_single_byte_write_merkle(self):
        """Single byte write with merkle."""
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()

        with AegisRaf128L(storage, key, create=True, merkle=True) as f:
            f.write(b"\x42")
            root = f.root_hash

        with AegisRaf128L(storage, key, merkle=True) as f:
            f.merkle_rebuild()
            assert f.root_hash == root
            assert f.merkle_verify() is None
            assert f.pread(1, 0) == b"\x42"

    def test_write_then_truncate_to_zero(self):
        """Write data then truncate to zero; merkle should be consistent."""
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()

        with AegisRaf128L(
            storage, key, create=True, chunk_size=1024, merkle=True, merkle_max_chunks=64
        ) as f:
            f.write(os.urandom(3000))
            f.truncate(0)
            assert f.size == 0
            root = f.root_hash

        with AegisRaf128L(storage, key, merkle=True, merkle_max_chunks=64) as f:
            f.merkle_rebuild()
            assert f.root_hash == root

    @pytest.mark.parametrize("size", [1, 15, 16, 17, 1023, 1024, 1025])
    def test_exact_sizes_roundtrip(self, size):
        """Files of exact sizes (around alignment) round-trip correctly."""
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()
        data = os.urandom(size)

        with AegisRaf128L(storage, key, create=True, chunk_size=1024, merkle=True) as f:
            f.write(data)
            root = f.root_hash

        with AegisRaf128L(storage, key, merkle=True) as f:
            f.merkle_rebuild()
            assert f.root_hash == root
            assert f.pread(size, 0) == data


class TestFuzzMultipleReopenCycles:
    """Test repeated open/write/close/reopen cycles."""

    @pytest.mark.parametrize("seed", range(5))
    def test_multiple_reopen_append(self, seed):
        """Open/write/close/reopen cycle many times; data accumulates correctly."""
        rng = random.Random(seed)
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()
        ref = RefFile()

        # Initial create
        with AegisRaf128L(
            storage, key, create=True, chunk_size=1024, merkle=True, merkle_max_chunks=256
        ) as f:
            d = os.urandom(rng.randint(100, 500))
            f.write(d)
            ref.write(d)

        for _cycle in range(8):
            with AegisRaf128L(storage, key, merkle=True, merkle_max_chunks=256) as f:
                f.merkle_rebuild()
                # Sometimes append, sometimes overwrite
                if rng.random() < 0.6:
                    d = os.urandom(rng.randint(50, 300))
                    offset = f.size
                    f.pwrite(d, offset)
                    ref.pwrite(d, offset)
                else:
                    if f.size > 0:
                        offset = rng.randint(0, f.size - 1)
                        d = os.urandom(rng.randint(1, 200))
                        f.pwrite(d, offset)
                        ref.pwrite(d, offset)

        # Final verify
        with AegisRaf128L(storage, key, merkle=True, merkle_max_chunks=256) as f:
            f.merkle_rebuild()
            assert f.merkle_verify() is None
            assert f.pread(ref.size, 0) == bytes(ref._data)


class TestFuzzAllVariants:
    """Test all 6 AEGIS variants with random operations."""

    @pytest.mark.parametrize("cls", ALL_RAF_CLASSES, ids=lambda c: c.__name__)
    @pytest.mark.parametrize("seed", range(3))
    def test_variant_random_ops_merkle(self, cls, seed):
        """Each variant handles random ops + merkle correctly."""
        rng = random.Random(seed)
        storage = BytesIOStorage()
        key = cls.random_key()
        ref = RefFile()

        with cls(
            storage, key, create=True, chunk_size=1024, merkle=True, merkle_max_chunks=128
        ) as f:
            for _ in range(20):
                data = os.urandom(rng.randint(1, 2000))
                if rng.random() < 0.4 and ref.size > 0:
                    off = rng.randint(0, ref.size)
                    f.pwrite(data, off)
                    ref.pwrite(data, off)
                else:
                    f.write(data)
                    ref.write(data)
            root = f.root_hash

        with cls(storage, key, merkle=True, merkle_max_chunks=128) as f:
            f.merkle_rebuild()
            assert f.root_hash == root
            assert f.merkle_verify() is None
            if ref.size > 0:
                assert f.pread(ref.size, 0) == bytes(ref._data)


class TestFuzzCustomHasher:
    """Fuzz with custom Merkle hashers."""

    @pytest.mark.parametrize("seed", range(5))
    def test_blake2b_random_ops(self, seed):
        """Custom Blake2b hasher under random operations."""
        rng = random.Random(seed)
        hasher = Blake2bMerkleHasher()
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()
        ref = RefFile()

        with AegisRaf128L(
            storage, key, create=True, chunk_size=1024, merkle=hasher, merkle_max_chunks=128
        ) as f:
            for _ in range(25):
                data = os.urandom(rng.randint(1, 2000))
                f.write(data)
                ref.write(data)
            root = f.root_hash

        with AegisRaf128L(storage, key, merkle=hasher, merkle_max_chunks=128) as f:
            f.merkle_rebuild()
            assert f.root_hash == root
            assert f.merkle_verify() is None
            assert f.pread(ref.size, 0) == bytes(ref._data)

    def test_sha256_vs_blake2b_differ(self):
        """SHA256 and Blake2b hashers produce different roots for same data."""
        key = AegisRaf128L.random_key()
        data = os.urandom(2000)

        sha_storage = BytesIOStorage()
        with AegisRaf128L(sha_storage, key, create=True, chunk_size=1024, merkle=True) as f:
            f.write(data)
            sha_root = f.root_hash

        b2_storage = BytesIOStorage()
        with AegisRaf128L(
            b2_storage, key, create=True, chunk_size=1024, merkle=Blake2bMerkleHasher()
        ) as f:
            f.write(data)
            b2_root = f.root_hash

        assert sha_root != b2_root


class TestFuzzWrongKey:
    """Fuzz: opening files with wrong keys."""

    @pytest.mark.parametrize("seed", range(10))
    def test_wrong_key_rejected(self, seed):
        """Random data written, then reopened with wrong key fails."""
        rng = random.Random(seed)
        cls = rng.choice(ALL_RAF_CLASSES)
        storage = BytesIOStorage()
        key = cls.random_key()

        with cls(storage, key, create=True, chunk_size=1024) as f:
            f.write(os.urandom(rng.randint(100, 3000)))

        wrong_key = cls.random_key()
        assert wrong_key != key  # Negligible collision probability
        with pytest.raises(RAFAuthenticationError):
            cls(storage, wrong_key)


class TestFuzzFileStorage:
    """Fuzz test RAF with real file I/O."""

    @pytest.mark.parametrize("seed", range(5))
    def test_file_storage_random_ops(self, seed, tmp_path):
        """Random ops on file-backed storage produce correct results."""
        rng = random.Random(seed)
        path = tmp_path / f"fuzz_{seed}.aegis"
        key = AegisRaf128L.random_key()
        ref = RefFile()

        with (
            FileStorage(path, "w+b") as fs,
            AegisRaf128L(
                fs,
                key,
                create=True,
                chunk_size=1024,
                merkle=True,
                merkle_max_chunks=128,
            ) as f,
        ):
            for _ in range(20):
                data = os.urandom(rng.randint(1, 1500))
                if rng.random() < 0.3 and ref.size > 0:
                    off = rng.randint(0, ref.size)
                    f.pwrite(data, off)
                    ref.pwrite(data, off)
                else:
                    f.write(data)
                    ref.write(data)
            root = f.root_hash

        # Reopen from file and verify
        with (
            FileStorage(path, "r+b") as fs,
            AegisRaf128L(
                fs,
                key,
                merkle=True,
                merkle_max_chunks=128,
            ) as f,
        ):
            f.merkle_rebuild()
            assert f.root_hash == root
            assert f.merkle_verify() is None
            if ref.size > 0:
                assert f.pread(ref.size, 0) == bytes(ref._data)


class TestFuzzRafOpen:
    """Fuzz raf_open auto-detection with random data."""

    @pytest.mark.parametrize("cls", ALL_RAF_CLASSES, ids=lambda c: c.__name__)
    def test_raf_open_detects_variant(self, cls):
        """raf_open correctly detects each variant after random writes."""
        storage = BytesIOStorage()
        key = cls.random_key()
        data = os.urandom(random.randint(100, 3000))

        with cls(storage, key, create=True, chunk_size=1024, merkle=True) as f:
            f.write(data)
            root = f.root_hash

        with raf_open(storage, key, merkle=True) as f:
            assert isinstance(f, cls)
            f.verify_root(root)
            assert f.pread(len(data), 0) == data


class TestFuzzMerkleMaxChunks:
    """Test merkle_max_chunks boundary."""

    def test_write_exactly_max_chunks(self):
        """Writing exactly max_chunks chunks is OK."""
        chunk_size = 1024
        max_chunks = 4
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()

        with AegisRaf128L(
            storage,
            key,
            create=True,
            chunk_size=chunk_size,
            merkle=True,
            merkle_max_chunks=max_chunks,
        ) as f:
            # Write exactly max_chunks * chunk_size bytes
            data = os.urandom(chunk_size * max_chunks)
            f.write(data)
            assert f.root_hash is not None

    def test_write_exceeds_max_chunks(self):
        """Writing past max_chunks raises RAFConfigError."""
        chunk_size = 1024
        max_chunks = 4
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()

        with AegisRaf128L(
            storage,
            key,
            create=True,
            chunk_size=chunk_size,
            merkle=True,
            merkle_max_chunks=max_chunks,
        ) as f:
            data = os.urandom(chunk_size * (max_chunks + 1))
            with pytest.raises(RAFConfigError, match="merkle_max_chunks"):
                f.write(data)

    @pytest.mark.parametrize("max_chunks", [1, 2, 3, 8])
    def test_boundary_max_chunks(self, max_chunks):
        """Boundary test: fill exactly to max, verify merkle still works."""
        chunk_size = 1024
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()

        with AegisRaf128L(
            storage,
            key,
            create=True,
            chunk_size=chunk_size,
            merkle=True,
            merkle_max_chunks=max_chunks,
        ) as f:
            data = os.urandom(chunk_size * max_chunks)
            f.write(data)
            root = f.root_hash

        with AegisRaf128L(storage, key, merkle=True, merkle_max_chunks=max_chunks) as f:
            f.merkle_rebuild()
            assert f.root_hash == root
            assert f.merkle_verify() is None


class TestFuzzReadInto:
    """Fuzz test read_into with random patterns."""

    @pytest.mark.parametrize("seed", range(5))
    def test_read_into_matches_read(self, seed):
        """read_into produces same result as read for same offset/size."""
        rng = random.Random(seed)
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()
        data = os.urandom(rng.randint(500, 5000))

        with AegisRaf128L(storage, key, create=True, chunk_size=1024) as f:
            f.write(data)

            for _ in range(30):
                offset = rng.randint(0, len(data))
                size = rng.randint(0, len(data) - offset + 100)
                size = min(size, len(data))

                f.seek(offset)
                read_result = f.read(size)

                buf = bytearray(size)
                f.seek(offset)
                n = f.read_into(buf, offset)

                assert bytes(buf[:n]) == read_result


class TestFuzzSeekTell:
    """Fuzz seek/tell consistency."""

    @pytest.mark.parametrize("seed", range(5))
    def test_seek_tell_consistency(self, seed):
        """seek returns same value as subsequent tell."""
        rng = random.Random(seed)
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()

        with AegisRaf128L(storage, key, create=True, chunk_size=1024) as f:
            f.write(os.urandom(rng.randint(100, 3000)))

            for _ in range(50):
                whence = rng.choice([0, 1, 2])
                if whence == 0:
                    off = rng.randint(0, f.size + 100)
                elif whence == 1:
                    off = rng.randint(-f.tell(), f.size + 50)
                else:
                    off = rng.randint(-f.size, 50)

                pos = f.seek(off, whence)
                assert f.tell() == pos


class TestFuzzLargeFile:
    """Test with larger data sizes."""

    def test_large_sequential_writes_merkle(self):
        """100KB of data in sequential writes with merkle verification."""
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()
        total = 100 * 1024
        chunk_size = 4096
        ref = bytearray()

        with AegisRaf128L(
            storage, key, create=True, chunk_size=chunk_size, merkle=True, merkle_max_chunks=256
        ) as f:
            written = 0
            while written < total:
                piece = os.urandom(random.randint(1, 8192))
                f.write(piece)
                ref.extend(piece)
                written += len(piece)
            root = f.root_hash

        with AegisRaf128L(storage, key, merkle=True, merkle_max_chunks=256) as f:
            f.merkle_rebuild()
            assert f.root_hash == root
            assert f.merkle_verify() is None
            assert f.pread(len(ref), 0) == bytes(ref)

    def test_large_random_access_merkle(self):
        """Random reads/writes across 100KB file with merkle."""
        rng = random.Random(42)
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()
        chunk_size = 4096
        ref = RefFile()

        with AegisRaf128L(
            storage, key, create=True, chunk_size=chunk_size, merkle=True, merkle_max_chunks=256
        ) as f:
            # Initial fill
            initial = os.urandom(50 * 1024)
            f.write(initial)
            ref.write(initial)

            # Random overwrites
            for _ in range(100):
                off = rng.randint(0, ref.size - 1)
                d = os.urandom(rng.randint(1, 4096))
                f.pwrite(d, off)
                ref.pwrite(d, off)

            # Verify content
            assert f.size == ref.size
            # Read in chunks to verify
            for off in range(0, ref.size, chunk_size):
                size = min(chunk_size, ref.size - off)
                assert f.pread(size, off) == ref.pread(size, off)

            root = f.root_hash

        with AegisRaf128L(storage, key, merkle=True, merkle_max_chunks=256) as f:
            f.merkle_rebuild()
            assert f.root_hash == root
            assert f.merkle_verify() is None


class TestFuzzConcurrentStorageOps:
    """Test that storage state is consistent across RAF operations."""

    def test_probe_after_random_writes(self):
        """raf_probe returns consistent info after random writes."""
        storage = BytesIOStorage()
        key = AegisRaf128L.random_key()
        chunk_size = 2048

        with AegisRaf128L(storage, key, create=True, chunk_size=chunk_size) as f:
            for _ in range(10):
                f.write(os.urandom(random.randint(100, 3000)))
            expected_size = f.size

        _alg_id, probed_chunk, probed_size = raf_probe(storage)
        assert probed_chunk == chunk_size
        assert probed_size == expected_size


class Blake2bMerkleHasher:
    """Custom Merkle hasher using BLAKE2b for testing."""

    hash_len = 32

    def hash_leaf(self, chunk: bytes, chunk_len: int, chunk_idx: int) -> bytes:
        h = hashlib.blake2b(digest_size=32)
        h.update(b"\x00")
        h.update(chunk_idx.to_bytes(8, "little"))
        h.update(chunk[:chunk_len])
        return h.digest()

    def hash_parent(self, left: bytes, right: bytes, level: int, node_idx: int) -> bytes:
        h = hashlib.blake2b(digest_size=32)
        h.update(b"\x01")
        h.update(level.to_bytes(4, "little"))
        h.update(node_idx.to_bytes(8, "little"))
        h.update(left)
        h.update(right)
        return h.digest()

    def hash_empty(self, level: int, node_idx: int) -> bytes:
        h = hashlib.blake2b(digest_size=32)
        h.update(b"\x02")
        h.update(level.to_bytes(4, "little"))
        h.update(node_idx.to_bytes(8, "little"))
        return h.digest()

    def hash_commitment(self, structural_root: bytes, ctx: bytes, file_size: int) -> bytes:
        h = hashlib.blake2b(digest_size=32)
        h.update(b"\x03")
        h.update(structural_root)
        h.update(ctx)
        h.update(file_size.to_bytes(8, "little"))
        return h.digest()
