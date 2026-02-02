"""CFFI build script for pyaegis."""

import os
import platform
import shutil
from pathlib import Path

from cffi import FFI


def setup_preferred_compiler():
    """Try to use Clang if available, otherwise fall back to system default."""
    # Only set compiler if not already explicitly set by user
    if "CC" in os.environ:
        return  # Respect user's explicit choice

    # Check if clang is available
    if shutil.which("clang") is not None:
        os.environ["CC"] = "clang"
        print("Using clang as the C compiler")
    else:
        print("Clang not found, using default system compiler")


def build_ffi():
    """Build the CFFI FFI builder."""
    # Set up compiler preference (Clang if available)
    setup_preferred_compiler()

    ffibuilder = FFI()

    # Define the C declarations for the Python interface
    ffibuilder.cdef("""
        // Common functions
        int aegis_init(void);
        int aegis_verify_16(const uint8_t *x, const uint8_t *y);
        int aegis_verify_32(const uint8_t *x, const uint8_t *y);

        // AEGIS-128L
        size_t aegis128l_keybytes(void);
        size_t aegis128l_npubbytes(void);
        size_t aegis128l_abytes_min(void);
        size_t aegis128l_abytes_max(void);
        size_t aegis128l_tailbytes_max(void);

        int aegis128l_encrypt_detached(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m,
                                       size_t mlen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                       const uint8_t *k);
        int aegis128l_decrypt_detached(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *mac,
                                       size_t maclen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                       const uint8_t *k);
        int aegis128l_encrypt(uint8_t *c, size_t maclen, const uint8_t *m, size_t mlen, const uint8_t *ad,
                              size_t adlen, const uint8_t *npub, const uint8_t *k);
        int aegis128l_decrypt(uint8_t *m, const uint8_t *c, size_t clen, size_t maclen, const uint8_t *ad,
                              size_t adlen, const uint8_t *npub, const uint8_t *k);
        void aegis128l_stream(uint8_t *out, size_t len, const uint8_t *npub, const uint8_t *k);

        typedef struct { uint8_t opaque[256]; ...; } aegis128l_state;
        void aegis128l_state_init(aegis128l_state *st_, const uint8_t *ad, size_t adlen,
                                  const uint8_t *npub, const uint8_t *k);
        int aegis128l_state_encrypt_update(aegis128l_state *st_, uint8_t *c, const uint8_t *m, size_t mlen);
        int aegis128l_state_encrypt_final(aegis128l_state *st_, uint8_t *mac, size_t maclen);
        int aegis128l_state_decrypt_update(aegis128l_state *st_, uint8_t *m, const uint8_t *c, size_t clen);
        int aegis128l_state_decrypt_final(aegis128l_state *st_, const uint8_t *mac, size_t maclen);

        typedef struct { uint8_t opaque[384]; ...; } aegis128l_mac_state;
        void aegis128l_mac_init(aegis128l_mac_state *st_, const uint8_t *k, const uint8_t *npub);
        int aegis128l_mac_update(aegis128l_mac_state *st_, const uint8_t *m, size_t mlen);
        int aegis128l_mac_final(aegis128l_mac_state *st_, uint8_t *mac, size_t maclen);
        int aegis128l_mac_verify(aegis128l_mac_state *st_, const uint8_t *mac, size_t maclen);
        void aegis128l_mac_reset(aegis128l_mac_state *st_);
        void aegis128l_mac_state_clone(aegis128l_mac_state *dst, const aegis128l_mac_state *src);

        // AEGIS-256
        size_t aegis256_keybytes(void);
        size_t aegis256_npubbytes(void);
        size_t aegis256_abytes_min(void);
        size_t aegis256_abytes_max(void);
        size_t aegis256_tailbytes_max(void);

        int aegis256_encrypt_detached(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m,
                                      size_t mlen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                      const uint8_t *k);
        int aegis256_decrypt_detached(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *mac,
                                      size_t maclen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                      const uint8_t *k);
        int aegis256_encrypt(uint8_t *c, size_t maclen, const uint8_t *m, size_t mlen, const uint8_t *ad,
                             size_t adlen, const uint8_t *npub, const uint8_t *k);
        int aegis256_decrypt(uint8_t *m, const uint8_t *c, size_t clen, size_t maclen, const uint8_t *ad,
                             size_t adlen, const uint8_t *npub, const uint8_t *k);
        void aegis256_stream(uint8_t *out, size_t len, const uint8_t *npub, const uint8_t *k);

        typedef struct { uint8_t opaque[192]; ...; } aegis256_state;
        void aegis256_state_init(aegis256_state *st_, const uint8_t *ad, size_t adlen,
                                const uint8_t *npub, const uint8_t *k);
        int aegis256_state_encrypt_update(aegis256_state *st_, uint8_t *c, const uint8_t *m, size_t mlen);
        int aegis256_state_encrypt_final(aegis256_state *st_, uint8_t *mac, size_t maclen);
        int aegis256_state_decrypt_update(aegis256_state *st_, uint8_t *m, const uint8_t *c, size_t clen);
        int aegis256_state_decrypt_final(aegis256_state *st_, const uint8_t *mac, size_t maclen);

        typedef struct { uint8_t opaque[288]; ...; } aegis256_mac_state;
        void aegis256_mac_init(aegis256_mac_state *st_, const uint8_t *k, const uint8_t *npub);
        int aegis256_mac_update(aegis256_mac_state *st_, const uint8_t *m, size_t mlen);
        int aegis256_mac_final(aegis256_mac_state *st_, uint8_t *mac, size_t maclen);
        int aegis256_mac_verify(aegis256_mac_state *st_, const uint8_t *mac, size_t maclen);
        void aegis256_mac_reset(aegis256_mac_state *st_);
        void aegis256_mac_state_clone(aegis256_mac_state *dst, const aegis256_mac_state *src);

        // AEGIS-128X2
        size_t aegis128x2_keybytes(void);
        size_t aegis128x2_npubbytes(void);
        size_t aegis128x2_abytes_min(void);
        size_t aegis128x2_abytes_max(void);
        size_t aegis128x2_tailbytes_max(void);

        int aegis128x2_encrypt_detached(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m,
                                        size_t mlen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                        const uint8_t *k);
        int aegis128x2_decrypt_detached(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *mac,
                                        size_t maclen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                        const uint8_t *k);
        int aegis128x2_encrypt(uint8_t *c, size_t maclen, const uint8_t *m, size_t mlen, const uint8_t *ad,
                               size_t adlen, const uint8_t *npub, const uint8_t *k);
        int aegis128x2_decrypt(uint8_t *m, const uint8_t *c, size_t clen, size_t maclen, const uint8_t *ad,
                               size_t adlen, const uint8_t *npub, const uint8_t *k);
        void aegis128x2_stream(uint8_t *out, size_t len, const uint8_t *npub, const uint8_t *k);

        typedef struct { uint8_t opaque[448]; ...; } aegis128x2_state;
        void aegis128x2_state_init(aegis128x2_state *st_, const uint8_t *ad, size_t adlen,
                                   const uint8_t *npub, const uint8_t *k);
        int aegis128x2_state_encrypt_update(aegis128x2_state *st_, uint8_t *c, const uint8_t *m, size_t mlen);
        int aegis128x2_state_encrypt_final(aegis128x2_state *st_, uint8_t *mac, size_t maclen);
        int aegis128x2_state_decrypt_update(aegis128x2_state *st_, uint8_t *m, const uint8_t *c, size_t clen);
        int aegis128x2_state_decrypt_final(aegis128x2_state *st_, const uint8_t *mac, size_t maclen);

        typedef struct { uint8_t opaque[704]; ...; } aegis128x2_mac_state;
        void aegis128x2_mac_init(aegis128x2_mac_state *st_, const uint8_t *k, const uint8_t *npub);
        int aegis128x2_mac_update(aegis128x2_mac_state *st_, const uint8_t *m, size_t mlen);
        int aegis128x2_mac_final(aegis128x2_mac_state *st_, uint8_t *mac, size_t maclen);
        int aegis128x2_mac_verify(aegis128x2_mac_state *st_, const uint8_t *mac, size_t maclen);
        void aegis128x2_mac_reset(aegis128x2_mac_state *st_);
        void aegis128x2_mac_state_clone(aegis128x2_mac_state *dst, const aegis128x2_mac_state *src);

        // AEGIS-128X4
        size_t aegis128x4_keybytes(void);
        size_t aegis128x4_npubbytes(void);
        size_t aegis128x4_abytes_min(void);
        size_t aegis128x4_abytes_max(void);
        size_t aegis128x4_tailbytes_max(void);

        int aegis128x4_encrypt_detached(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m,
                                        size_t mlen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                        const uint8_t *k);
        int aegis128x4_decrypt_detached(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *mac,
                                        size_t maclen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                        const uint8_t *k);
        int aegis128x4_encrypt(uint8_t *c, size_t maclen, const uint8_t *m, size_t mlen, const uint8_t *ad,
                               size_t adlen, const uint8_t *npub, const uint8_t *k);
        int aegis128x4_decrypt(uint8_t *m, const uint8_t *c, size_t clen, size_t maclen, const uint8_t *ad,
                               size_t adlen, const uint8_t *npub, const uint8_t *k);
        void aegis128x4_stream(uint8_t *out, size_t len, const uint8_t *npub, const uint8_t *k);

        typedef struct { uint8_t opaque[832]; ...; } aegis128x4_state;
        void aegis128x4_state_init(aegis128x4_state *st_, const uint8_t *ad, size_t adlen,
                                   const uint8_t *npub, const uint8_t *k);
        int aegis128x4_state_encrypt_update(aegis128x4_state *st_, uint8_t *c, const uint8_t *m, size_t mlen);
        int aegis128x4_state_encrypt_final(aegis128x4_state *st_, uint8_t *mac, size_t maclen);
        int aegis128x4_state_decrypt_update(aegis128x4_state *st_, uint8_t *m, const uint8_t *c, size_t clen);
        int aegis128x4_state_decrypt_final(aegis128x4_state *st_, const uint8_t *mac, size_t maclen);

        typedef struct { uint8_t opaque[1344]; ...; } aegis128x4_mac_state;
        void aegis128x4_mac_init(aegis128x4_mac_state *st_, const uint8_t *k, const uint8_t *npub);
        int aegis128x4_mac_update(aegis128x4_mac_state *st_, const uint8_t *m, size_t mlen);
        int aegis128x4_mac_final(aegis128x4_mac_state *st_, uint8_t *mac, size_t maclen);
        int aegis128x4_mac_verify(aegis128x4_mac_state *st_, const uint8_t *mac, size_t maclen);
        void aegis128x4_mac_reset(aegis128x4_mac_state *st_);
        void aegis128x4_mac_state_clone(aegis128x4_mac_state *dst, const aegis128x4_mac_state *src);

        // AEGIS-256X2
        size_t aegis256x2_keybytes(void);
        size_t aegis256x2_npubbytes(void);
        size_t aegis256x2_abytes_min(void);
        size_t aegis256x2_abytes_max(void);
        size_t aegis256x2_tailbytes_max(void);

        int aegis256x2_encrypt_detached(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m,
                                        size_t mlen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                        const uint8_t *k);
        int aegis256x2_decrypt_detached(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *mac,
                                        size_t maclen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                        const uint8_t *k);
        int aegis256x2_encrypt(uint8_t *c, size_t maclen, const uint8_t *m, size_t mlen, const uint8_t *ad,
                               size_t adlen, const uint8_t *npub, const uint8_t *k);
        int aegis256x2_decrypt(uint8_t *m, const uint8_t *c, size_t clen, size_t maclen, const uint8_t *ad,
                               size_t adlen, const uint8_t *npub, const uint8_t *k);
        void aegis256x2_stream(uint8_t *out, size_t len, const uint8_t *npub, const uint8_t *k);

        typedef struct { uint8_t opaque[320]; ...; } aegis256x2_state;
        void aegis256x2_state_init(aegis256x2_state *st_, const uint8_t *ad, size_t adlen,
                                   const uint8_t *npub, const uint8_t *k);
        int aegis256x2_state_encrypt_update(aegis256x2_state *st_, uint8_t *c, const uint8_t *m, size_t mlen);
        int aegis256x2_state_encrypt_final(aegis256x2_state *st_, uint8_t *mac, size_t maclen);
        int aegis256x2_state_decrypt_update(aegis256x2_state *st_, uint8_t *m, const uint8_t *c, size_t clen);
        int aegis256x2_state_decrypt_final(aegis256x2_state *st_, const uint8_t *mac, size_t maclen);

        typedef struct { uint8_t opaque[512]; ...; } aegis256x2_mac_state;
        void aegis256x2_mac_init(aegis256x2_mac_state *st_, const uint8_t *k, const uint8_t *npub);
        int aegis256x2_mac_update(aegis256x2_mac_state *st_, const uint8_t *m, size_t mlen);
        int aegis256x2_mac_final(aegis256x2_mac_state *st_, uint8_t *mac, size_t maclen);
        int aegis256x2_mac_verify(aegis256x2_mac_state *st_, const uint8_t *mac, size_t maclen);
        void aegis256x2_mac_reset(aegis256x2_mac_state *st_);
        void aegis256x2_mac_state_clone(aegis256x2_mac_state *dst, const aegis256x2_mac_state *src);

        // AEGIS-256X4
        size_t aegis256x4_keybytes(void);
        size_t aegis256x4_npubbytes(void);
        size_t aegis256x4_abytes_min(void);
        size_t aegis256x4_abytes_max(void);
        size_t aegis256x4_tailbytes_max(void);

        int aegis256x4_encrypt_detached(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m,
                                        size_t mlen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                        const uint8_t *k);
        int aegis256x4_decrypt_detached(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *mac,
                                        size_t maclen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                        const uint8_t *k);
        int aegis256x4_encrypt(uint8_t *c, size_t maclen, const uint8_t *m, size_t mlen, const uint8_t *ad,
                               size_t adlen, const uint8_t *npub, const uint8_t *k);
        int aegis256x4_decrypt(uint8_t *m, const uint8_t *c, size_t clen, size_t maclen, const uint8_t *ad,
                               size_t adlen, const uint8_t *npub, const uint8_t *k);
        void aegis256x4_stream(uint8_t *out, size_t len, const uint8_t *npub, const uint8_t *k);

        typedef struct { uint8_t opaque[576]; ...; } aegis256x4_state;
        void aegis256x4_state_init(aegis256x4_state *st_, const uint8_t *ad, size_t adlen,
                                   const uint8_t *npub, const uint8_t *k);
        int aegis256x4_state_encrypt_update(aegis256x4_state *st_, uint8_t *c, const uint8_t *m, size_t mlen);
        int aegis256x4_state_encrypt_final(aegis256x4_state *st_, uint8_t *mac, size_t maclen);
        int aegis256x4_state_decrypt_update(aegis256x4_state *st_, uint8_t *m, const uint8_t *c, size_t clen);
        int aegis256x4_state_decrypt_final(aegis256x4_state *st_, const uint8_t *mac, size_t maclen);

        typedef struct { uint8_t opaque[960]; ...; } aegis256x4_mac_state;
        void aegis256x4_mac_init(aegis256x4_mac_state *st_, const uint8_t *k, const uint8_t *npub);
        int aegis256x4_mac_update(aegis256x4_mac_state *st_, const uint8_t *m, size_t mlen);
        int aegis256x4_mac_final(aegis256x4_mac_state *st_, uint8_t *mac, size_t maclen);
        int aegis256x4_mac_verify(aegis256x4_mac_state *st_, const uint8_t *mac, size_t maclen);
        void aegis256x4_mac_reset(aegis256x4_mac_state *st_);
        void aegis256x4_mac_state_clone(aegis256x4_mac_state *dst, const aegis256x4_mac_state *src);
    """)

    # Get source files
    local_src_dir = Path(__file__).parent / "c_src"
    if local_src_dir.exists():
        src_dir = local_src_dir
    else:
        # Fall back to parent directory (for development)
        repo_root = Path(__file__).parent.parent.resolve()
        src_dir = repo_root / "src"

    # Collect all C source files
    source_patterns = [
        "aegis128l/*.c",
        "aegis128x2/*.c",
        "aegis128x4/*.c",
        "aegis256/*.c",
        "aegis256x2/*.c",
        "aegis256x4/*.c",
        "common/*.c",
    ]

    c_sources = []
    for pattern in source_patterns:
        c_sources.extend(str(f) for f in src_dir.glob(pattern))

    # Get include directory
    local_include_dir = Path(__file__).parent / "c_src" / "include"
    if local_include_dir.exists():
        include_dir = local_include_dir
    else:
        repo_root = Path(__file__).parent.parent.resolve()
        include_dir = repo_root / "src" / "include"

    # Platform-specific compiler flags
    extra_compile_args = []
    if platform.system() != "Windows":
        # Enable optimizations and warnings
        extra_compile_args.extend(["-O3", "-Wall", "-Wextra"])

    # Set the source - this will compile all C files into the extension
    ffibuilder.set_source(
        "pyaegis._aegis_ffi",
        """
        #include <aegis.h>
        #include <aegis128l.h>
        #include <aegis128x2.h>
        #include <aegis128x4.h>
        #include <aegis256.h>
        #include <aegis256x2.h>
        #include <aegis256x4.h>
        """,
        sources=c_sources,
        include_dirs=[str(include_dir)],
        extra_compile_args=extra_compile_args,
    )

    return ffibuilder


ffibuilder = build_ffi()

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
