#!/usr/bin/env python3
"""Benchmark script for pyaegis RAF (Random Access Format) encrypted I/O."""

import os
import random
import sys
import time

from pyaegis import (
    AegisRaf128L,
    AegisRaf128X2,
    AegisRaf128X4,
    AegisRaf256,
    AegisRaf256X2,
    AegisRaf256X4,
    BytesIOStorage,
)


def format_throughput(bytes_processed, elapsed_time):
    """Format throughput in MB/s or GB/s."""
    mb_per_sec = (bytes_processed / (1024 * 1024)) / elapsed_time
    if mb_per_sec >= 1024:
        return f"{mb_per_sec / 1024:.2f} GB/s"
    return f"{mb_per_sec:.1f} MB/s"


def format_size(size):
    if size >= 1024 * 1024:
        return f"{size // (1024 * 1024)} MB"
    elif size >= 1024:
        return f"{size // 1024} KB"
    else:
        return f"{size} B"


def format_time(elapsed):
    if elapsed >= 1.0:
        return f"{elapsed:.2f} s"
    return f"{elapsed * 1000:.1f} ms"


def bench_sequential_write(raf_cls, file_size, chunk_size, merkle, iterations):
    """Write a file from scratch, measuring total throughput."""
    key = raf_cls.random_key()
    data = os.urandom(file_size)

    # Warm-up
    storage = BytesIOStorage()
    with raf_cls(storage, key, create=True, chunk_size=chunk_size, merkle=merkle) as f:
        f.write(data)

    elapsed_total = 0.0
    for _ in range(iterations):
        storage = BytesIOStorage()
        start = time.perf_counter()
        with raf_cls(storage, key, create=True, chunk_size=chunk_size, merkle=merkle) as f:
            f.write(data)
        elapsed_total += time.perf_counter() - start

    return format_throughput(file_size * iterations, elapsed_total)


def bench_sequential_read(raf_cls, file_size, chunk_size, merkle, iterations):
    """Read an entire file sequentially."""
    key = raf_cls.random_key()
    data = os.urandom(file_size)

    storage = BytesIOStorage()
    with raf_cls(storage, key, create=True, chunk_size=chunk_size, merkle=merkle) as f:
        f.write(data)

    # Warm-up
    with raf_cls(storage, key, merkle=merkle) as f:
        f.read()

    elapsed_total = 0.0
    for _ in range(iterations):
        start = time.perf_counter()
        with raf_cls(storage, key, merkle=merkle) as f:
            f.read()
        elapsed_total += time.perf_counter() - start

    return format_throughput(file_size * iterations, elapsed_total)


def bench_random_read(raf_cls, file_size, chunk_size, merkle, num_reads):
    """Random pread() calls across the file."""
    key = raf_cls.random_key()
    data = os.urandom(file_size)
    read_size = chunk_size

    storage = BytesIOStorage()
    with raf_cls(storage, key, create=True, chunk_size=chunk_size, merkle=merkle) as f:
        f.write(data)

    rng = random.Random(42)
    offsets = [rng.randint(0, max(0, file_size - read_size)) for _ in range(num_reads)]

    # Warm-up
    with raf_cls(storage, key, merkle=merkle) as f:
        for off in offsets[:10]:
            f.pread(read_size, off)

    with raf_cls(storage, key, merkle=merkle) as f:
        start = time.perf_counter()
        for off in offsets:
            f.pread(read_size, off)
        elapsed = time.perf_counter() - start

    return format_throughput(read_size * num_reads, elapsed)


def bench_random_write(raf_cls, file_size, chunk_size, merkle, num_writes):
    """Random pwrite() calls across an existing file."""
    key = raf_cls.random_key()
    data = os.urandom(file_size)
    write_data = os.urandom(chunk_size)

    storage = BytesIOStorage()
    with raf_cls(storage, key, create=True, chunk_size=chunk_size, merkle=merkle) as f:
        f.write(data)

    rng = random.Random(42)
    offsets = [rng.randint(0, max(0, file_size - chunk_size)) for _ in range(num_writes)]

    # Warm-up
    with raf_cls(storage, key, merkle=merkle) as f:
        for off in offsets[:10]:
            f.pwrite(write_data, off)

    with raf_cls(storage, key, merkle=merkle) as f:
        start = time.perf_counter()
        for off in offsets:
            f.pwrite(write_data, off)
        elapsed = time.perf_counter() - start

    return format_throughput(chunk_size * num_writes, elapsed)


def bench_merkle_rebuild(raf_cls, file_size, chunk_size):
    """Rebuild the merkle tree from scratch."""
    key = raf_cls.random_key()
    data = os.urandom(file_size)

    storage = BytesIOStorage()
    with raf_cls(storage, key, create=True, chunk_size=chunk_size, merkle=True) as f:
        f.write(data)

    with raf_cls(storage, key, merkle=True) as f:
        # Warm-up
        f.merkle_rebuild()

        start = time.perf_counter()
        f.merkle_rebuild()
        elapsed = time.perf_counter() - start

    return format_throughput(file_size, elapsed), format_time(elapsed)


def bench_merkle_verify(raf_cls, file_size, chunk_size):
    """Verify the merkle tree."""
    key = raf_cls.random_key()
    data = os.urandom(file_size)

    storage = BytesIOStorage()
    with raf_cls(storage, key, create=True, chunk_size=chunk_size, merkle=True) as f:
        f.write(data)

    with raf_cls(storage, key, merkle=True) as f:
        f.merkle_rebuild()

        # Warm-up
        f.merkle_verify()

        start = time.perf_counter()
        f.merkle_verify()
        elapsed = time.perf_counter() - start

    return format_throughput(file_size, elapsed), format_time(elapsed)


def run_io_benchmarks(raf_cls, variant_name, file_sizes, chunk_size=65536):
    """Run sequential and random I/O benchmarks for one variant."""
    print(f"\n{'=' * 90}")
    print(f"  {variant_name}  (chunk size: {format_size(chunk_size)})")
    print(f"{'=' * 90}")

    def pick_iters(size):
        if size <= 64 * 1024:
            return 50
        elif size <= 1024 * 1024:
            return 20
        elif size <= 10 * 1024 * 1024:
            return 5
        else:
            return 2

    def pick_random_ops(size):
        if size <= 64 * 1024:
            return 2000
        elif size <= 1024 * 1024:
            return 1000
        elif size <= 10 * 1024 * 1024:
            return 500
        else:
            return 200

    header = (
        f"{'File Size':<12} {'Seq Write':<14} {'Seq Read':<14} {'Rand Read':<14} {'Rand Write':<14}"
    )

    for merkle in [False, True]:
        merkle_label = "with Merkle" if merkle else "without Merkle"
        print(f"\n  {merkle_label}")
        print(f"\n{header}")
        print("-" * len(header))

        for file_size in file_sizes:
            iters = pick_iters(file_size)
            rand_ops = pick_random_ops(file_size)

            seq_w = bench_sequential_write(raf_cls, file_size, chunk_size, merkle, iters)
            seq_r = bench_sequential_read(raf_cls, file_size, chunk_size, merkle, iters)
            rnd_r = bench_random_read(raf_cls, file_size, chunk_size, merkle, rand_ops)
            rnd_w = bench_random_write(raf_cls, file_size, chunk_size, merkle, rand_ops)

            size_str = format_size(file_size)
            print(f"{size_str:<12} {seq_w:<14} {seq_r:<14} {rnd_r:<14} {rnd_w:<14}")


def run_merkle_benchmarks(raf_cls, variant_name, file_sizes, chunk_size=65536):
    """Run merkle-specific benchmarks (rebuild, verify) for one variant."""
    print(f"\n{'=' * 70}")
    print(f"  {variant_name} - Merkle Tree Operations  (chunk: {format_size(chunk_size)})")
    print(f"{'=' * 70}")

    header = f"{'File Size':<12} {'Chunks':<10} {'Rebuild':<14} {'(time)':<12} {'Verify':<14} {'(time)':<12}"
    print(f"\n{header}")
    print("-" * len(header))

    for file_size in file_sizes:
        num_chunks = (file_size + chunk_size - 1) // chunk_size
        rb_tp, rb_t = bench_merkle_rebuild(raf_cls, file_size, chunk_size)
        vf_tp, vf_t = bench_merkle_verify(raf_cls, file_size, chunk_size)

        size_str = format_size(file_size)
        print(f"{size_str:<12} {num_chunks:<10} {rb_tp:<14} {rb_t:<12} {vf_tp:<14} {vf_t:<12}")


def main():
    small_sizes = [64 * 1024, 256 * 1024]
    medium_sizes = [1 * 1024 * 1024, 10 * 1024 * 1024]
    large_sizes = [50 * 1024 * 1024, 100 * 1024 * 1024]
    all_sizes = small_sizes + medium_sizes + large_sizes

    variants = [
        (AegisRaf128L, "AEGIS-128L RAF"),
        (AegisRaf256, "AEGIS-256 RAF"),
        (AegisRaf128X2, "AEGIS-128X2 RAF"),
        (AegisRaf128X4, "AEGIS-128X4 RAF"),
        (AegisRaf256X2, "AEGIS-256X2 RAF"),
        (AegisRaf256X4, "AEGIS-256X4 RAF"),
    ]

    print("RAF Benchmark - Encrypted Random Access File I/O")
    print(f"File sizes: {', '.join(format_size(s) for s in all_sizes)}")
    print("Storage: in-memory (BytesIOStorage)")

    for raf_cls, name in variants:
        run_io_benchmarks(raf_cls, name, all_sizes)

    print("\n\n" + "Merkle Tree Benchmarks\n")

    for raf_cls, name in variants:
        run_merkle_benchmarks(raf_cls, name, all_sizes)

    print("\n" + "=" * 70)
    print("Benchmark complete!")
    print("=" * 70)
    print("\nNotes:")
    print("  - Throughput in MB/s (mebibytes per second)")
    print("  - Seq Write: create a new file and write all data")
    print("  - Seq Read: open and read entire file")
    print("  - Rand Read/Write: random-offset pread()/pwrite() of one chunk each")
    print("  - Merkle Rebuild: re-hash every chunk from scratch")
    print("  - Merkle Verify: compare tree against stored hashes")
    print("  - All I/O uses in-memory BytesIOStorage (no disk overhead)")
    print("  - Performance depends on CPU features (AES-NI, AVX2, AVX-512, NEON)")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nBenchmark interrupted by user.")
        sys.exit(1)
