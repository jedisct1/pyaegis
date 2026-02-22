#!/usr/bin/env python3
"""Benchmark script for pyaegis - AEGIS authenticated encryption."""

import sys
import time

from pyaegis import (
    Aegis128L,
    Aegis128X2,
    Aegis128X4,
    Aegis256,
    Aegis256X2,
    Aegis256X4,
    AegisMac128L,
    AegisMac128X2,
    AegisMac128X4,
    AegisMac256,
    AegisMac256X2,
    AegisMac256X4,
)


def format_throughput(bytes_processed, elapsed_time):
    """Format throughput in Mb/s (megabits per second) or Gb/s."""
    # Convert bytes to megabits: bytes * 8 / 1,000,000
    megabits_per_sec = (bytes_processed * 8 / 1_000_000) / elapsed_time
    if megabits_per_sec >= 1000:
        return f"{megabits_per_sec / 1000:.2f} Gb/s"
    return f"{megabits_per_sec:.2f} Mb/s"


def benchmark_variant(cipher, variant_name, message_sizes, iterations=1000):
    """Benchmark a specific AEGIS variant."""
    print(f"\n{'=' * 70}")
    print(f"Benchmarking {variant_name}")
    print(f"{'=' * 70}")

    key = cipher.random_key()
    nonce = cipher.random_nonce()

    results = []

    for size in message_sizes:
        message = b"x" * size

        # Warm-up
        for _ in range(10):
            buffer = bytearray(message)
            tag = cipher.encrypt_inplace(key, nonce, buffer)

        # Encryption benchmark
        start = time.perf_counter()
        for _ in range(iterations):
            buffer = bytearray(message)
            tag = cipher.encrypt_inplace(key, nonce, buffer)
        elapsed = time.perf_counter() - start

        enc_throughput = format_throughput(size * iterations, elapsed)

        # Prepare for decryption benchmark
        ciphertext_buffer = bytearray(message)
        tag = cipher.encrypt_inplace(key, nonce, ciphertext_buffer)

        # Decryption benchmark
        start = time.perf_counter()
        for _ in range(iterations):
            buffer = bytearray(ciphertext_buffer)
            cipher.decrypt_inplace(key, nonce, buffer, tag)
        elapsed = time.perf_counter() - start

        dec_throughput = format_throughput(size * iterations, elapsed)

        # Detached mode benchmark (if supported)
        try:
            start = time.perf_counter()
            for _ in range(iterations):
                ct, tag = cipher.encrypt_detached(key, nonce, message)
            elapsed = time.perf_counter() - start
            enc_detached_throughput = format_throughput(size * iterations, elapsed)

            start = time.perf_counter()
            for _ in range(iterations):
                plaintext = cipher.decrypt_detached(key, nonce, ct, tag)  # noqa: F841
            elapsed = time.perf_counter() - start
            dec_detached_throughput = format_throughput(size * iterations, elapsed)
        except AttributeError:
            enc_detached_throughput = "N/A"
            dec_detached_throughput = "N/A"

        results.append(
            {
                "size": size,
                "enc": enc_throughput,
                "dec": dec_throughput,
                "enc_det": enc_detached_throughput,
                "dec_det": dec_detached_throughput,
            }
        )

    # Print results table
    print(
        f"\n{'Message Size':<15} {'Encrypt':<15} {'Decrypt':<15} {'Enc (detached)':<15} {'Dec (detached)':<15}"
    )
    print("-" * 75)

    for r in results:
        size_str = format_size(r["size"])
        print(f"{size_str:<15} {r['enc']:<15} {r['dec']:<15} {r['enc_det']:<15} {r['dec_det']:<15}")


def format_size(size):
    """Format size in human-readable format."""
    if size >= 1024 * 1024:
        return f"{size // (1024 * 1024)} MB"
    elif size >= 1024:
        return f"{size // 1024} KB"
    else:
        return f"{size} B"


def benchmark_mac(mac_class, variant_name, message_sizes, iterations_list):
    """Benchmark a specific AEGIS MAC variant."""
    print(f"\n{'=' * 70}")
    print(f"Benchmarking {variant_name}")
    print(f"{'=' * 70}")

    key = mac_class.random_key()
    nonce = mac_class.random_nonce()

    results = []

    for size, iters in zip(message_sizes, iterations_list, strict=True):
        message = b"x" * size

        # Benchmark: single update + final (all-at-once)
        # Warm-up
        for _ in range(min(10, iters)):
            mac = mac_class(key, nonce)
            mac.update(message)
            tag = mac.final()

        start = time.perf_counter()
        for _ in range(iters):
            mac = mac_class(key, nonce)
            mac.update(message)
            tag = mac.final()
        elapsed = time.perf_counter() - start
        update_final_throughput = format_throughput(size * iters, elapsed)

        # Benchmark: verify operation
        start = time.perf_counter()
        for _ in range(iters):
            mac = mac_class(key, nonce)
            mac.update(message)
            mac.verify(tag)
        elapsed = time.perf_counter() - start
        verify_throughput = format_throughput(size * iters, elapsed)

        # Benchmark: streaming (multiple updates)
        # Process in 64KB chunks
        chunk_size = 64 * 1024
        chunks = [message[i : i + chunk_size] for i in range(0, len(message), chunk_size)]

        start = time.perf_counter()
        for _ in range(iters):
            mac = mac_class(key, nonce)
            for chunk in chunks:
                mac.update(chunk)
            tag = mac.final()
        elapsed = time.perf_counter() - start
        streaming_throughput = format_throughput(size * iters, elapsed)

        results.append(
            {
                "size": size,
                "iters": iters,
                "update_final": update_final_throughput,
                "verify": verify_throughput,
                "streaming": streaming_throughput,
            }
        )

    # Print results table
    print(
        f"\n{'Message Size':<15} {'Iterations':<12} {'Update+Final':<15} {'Verify':<15} {'Streaming':<15}"
    )
    print("-" * 82)

    for r in results:
        size_str = format_size(r["size"])
        print(
            f"{size_str:<15} {r['iters']:<12} {r['update_final']:<15} {r['verify']:<15} {r['streaming']:<15}"
        )


def run_all_benchmarks():
    """Run benchmarks for all AEGIS variants."""

    # Message sizes to test (up to 10 MB)
    small_sizes = [64, 256, 1024]  # More iterations for small messages
    medium_sizes = [8 * 1024, 64 * 1024]  # Medium iterations
    large_sizes = [
        256 * 1024,
        1024 * 1024,
        5 * 1024 * 1024,
        10 * 1024 * 1024,
    ]  # Fewer iterations for large messages

    variants = [
        (
            Aegis128L(),
            "AEGIS-128L",
            small_sizes + medium_sizes + large_sizes,
            [1000, 1000, 1000, 500, 100, 50, 20, 10, 10],
        ),
        (
            Aegis256(),
            "AEGIS-256",
            small_sizes + medium_sizes + large_sizes,
            [1000, 1000, 1000, 500, 100, 50, 20, 10, 10],
        ),
        (
            Aegis128X2(),
            "AEGIS-128X2",
            small_sizes + medium_sizes + large_sizes,
            [1000, 1000, 1000, 500, 100, 50, 20, 10, 10],
        ),
        (
            Aegis128X4(),
            "AEGIS-128X4",
            small_sizes + medium_sizes + large_sizes,
            [1000, 1000, 1000, 500, 100, 50, 20, 10, 10],
        ),
        (
            Aegis256X2(),
            "AEGIS-256X2",
            small_sizes + medium_sizes + large_sizes,
            [1000, 1000, 1000, 500, 100, 50, 20, 10, 10],
        ),
        (
            Aegis256X4(),
            "AEGIS-256X4",
            small_sizes + medium_sizes + large_sizes,
            [1000, 1000, 1000, 500, 100, 50, 20, 10, 10],
        ),
    ]

    for cipher, name, sizes, iterations_list in variants:
        # Run benchmark with varying iterations based on message size
        print(f"\n{'=' * 70}")
        print(f"Benchmarking {name}")
        print(f"{'=' * 70}")

        key = cipher.random_key()
        nonce = cipher.random_nonce()

        results = []

        for size, iters in zip(sizes, iterations_list, strict=True):
            message = b"x" * size

            # Warm-up
            for _ in range(min(10, iters)):
                buffer = bytearray(message)
                tag = cipher.encrypt_inplace(key, nonce, buffer)

            # Encryption benchmark
            start = time.perf_counter()
            for _ in range(iters):
                buffer = bytearray(message)
                tag = cipher.encrypt_inplace(key, nonce, buffer)
            elapsed = time.perf_counter() - start

            enc_throughput = format_throughput(size * iters, elapsed)

            # Prepare for decryption benchmark
            ciphertext_buffer = bytearray(message)
            tag = cipher.encrypt_inplace(key, nonce, ciphertext_buffer)

            # Decryption benchmark
            start = time.perf_counter()
            for _ in range(iters):
                buffer = bytearray(ciphertext_buffer)
                cipher.decrypt_inplace(key, nonce, buffer, tag)
            elapsed = time.perf_counter() - start

            dec_throughput = format_throughput(size * iters, elapsed)

            # Detached mode benchmark (if supported)
            if hasattr(cipher, "encrypt_detached") and hasattr(cipher, "decrypt_detached"):
                start = time.perf_counter()
                for _ in range(iters):
                    ct, tag = cipher.encrypt_detached(key, nonce, message)
                elapsed = time.perf_counter() - start
                enc_detached_throughput = format_throughput(size * iters, elapsed)

                start = time.perf_counter()
                for _ in range(iters):
                    plaintext = cipher.decrypt_detached(key, nonce, ct, tag)  # noqa: F841
                elapsed = time.perf_counter() - start
                dec_detached_throughput = format_throughput(size * iters, elapsed)
            else:
                enc_detached_throughput = "N/A"
                dec_detached_throughput = "N/A"

            results.append(
                {
                    "size": size,
                    "iters": iters,
                    "enc": enc_throughput,
                    "dec": dec_throughput,
                    "enc_det": enc_detached_throughput,
                    "dec_det": dec_detached_throughput,
                }
            )

        # Print results table
        print(
            f"\n{'Message Size':<15} {'Iterations':<12} {'Encrypt':<15} {'Decrypt':<15} {'Enc (det)':<15} {'Dec (det)':<15}"
        )
        print("-" * 97)

        for r in results:
            size_str = format_size(r["size"])
            print(
                f"{size_str:<15} {r['iters']:<12} {r['enc']:<15} {r['dec']:<15} {r['enc_det']:<15} {r['dec_det']:<15}"
            )

    # MAC benchmarks
    print("\n\n" + "MAC Benchmarks\n\n")

    mac_variants = [
        (AegisMac128L, "AEGIS-128L MAC"),
        (AegisMac256, "AEGIS-256 MAC"),
        (AegisMac128X2, "AEGIS-128X2 MAC"),
        (AegisMac128X4, "AEGIS-128X4 MAC"),
        (AegisMac256X2, "AEGIS-256X2 MAC"),
        (AegisMac256X4, "AEGIS-256X4 MAC"),
    ]

    for mac_class, name in mac_variants:
        benchmark_mac(mac_class, name, sizes, iterations_list)

    print("\n" + "=" * 70)
    print("Benchmark complete!")
    print("=" * 70)
    print("\nNotes:")
    print("  - Throughput shown in Mb/s (megabits per second)")
    print("  - Higher throughput = better performance")
    print("  - X2/X4 variants use multi-lane SIMD for higher throughput")
    print("  - Performance depends on CPU features (AES-NI, AVX2, AVX-512, NEON)")
    print("  - Results may vary based on system load and CPU frequency scaling")
    print("  - Each test performs multiple rounds (iterations shown in table)")
    print("\nMAC Benchmarks:")
    print("  - Update+Final: Single update() call followed by final()")
    print("  - Verify: Single update() call followed by verify()")
    print("  - Streaming: Multiple 64KB update() calls followed by final()")


if __name__ == "__main__":
    try:
        run_all_benchmarks()
    except KeyboardInterrupt:
        print("\n\nBenchmark interrupted by user.")
        sys.exit(1)
