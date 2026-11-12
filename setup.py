"""Setup script for pyaegis - Python bindings for libaegis."""

import os
import platform
import shutil
from pathlib import Path

from setuptools import find_packages, setup
from setuptools.command.build_ext import build_ext


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


def get_c_sources():
    """Get all C source files from the c_src directory or parent directory."""
    # First try local c_src directory (for source distributions)
    local_src_dir = Path(__file__).parent / "c_src"
    if local_src_dir.exists():
        src_dir = local_src_dir
    else:
        # Fall back to parent directory (for development)
        repo_root = Path(__file__).parent.parent.resolve()
        src_dir = repo_root / "src"

    # All C source files needed for the library
    source_patterns = [
        "aegis128l/*.c",
        "aegis128x2/*.c",
        "aegis128x4/*.c",
        "aegis256/*.c",
        "aegis256x2/*.c",
        "aegis256x4/*.c",
        "common/*.c",
    ]

    sources = []
    for pattern in source_patterns:
        sources.extend(str(f) for f in (src_dir).glob(pattern))

    return sources


def build_cffi_extension():
    """Build the CFFI extension with all C sources compiled in."""
    from cffi import FFI

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

        // AEGIS-128X2
        size_t aegis128x2_keybytes(void);
        size_t aegis128x2_npubbytes(void);
        size_t aegis128x2_abytes_min(void);
        size_t aegis128x2_abytes_max(void);

        int aegis128x2_encrypt_detached(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m,
                                        size_t mlen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                        const uint8_t *k);
        int aegis128x2_decrypt_detached(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *mac,
                                        size_t maclen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                        const uint8_t *k);

        // AEGIS-128X4
        size_t aegis128x4_keybytes(void);
        size_t aegis128x4_npubbytes(void);
        size_t aegis128x4_abytes_min(void);
        size_t aegis128x4_abytes_max(void);

        int aegis128x4_encrypt_detached(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m,
                                        size_t mlen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                        const uint8_t *k);
        int aegis128x4_decrypt_detached(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *mac,
                                        size_t maclen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                        const uint8_t *k);

        // AEGIS-256X2
        size_t aegis256x2_keybytes(void);
        size_t aegis256x2_npubbytes(void);
        size_t aegis256x2_abytes_min(void);
        size_t aegis256x2_abytes_max(void);

        int aegis256x2_encrypt_detached(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m,
                                        size_t mlen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                        const uint8_t *k);
        int aegis256x2_decrypt_detached(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *mac,
                                        size_t maclen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                        const uint8_t *k);

        // AEGIS-256X4
        size_t aegis256x4_keybytes(void);
        size_t aegis256x4_npubbytes(void);
        size_t aegis256x4_abytes_min(void);
        size_t aegis256x4_abytes_max(void);

        int aegis256x4_encrypt_detached(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m,
                                        size_t mlen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                        const uint8_t *k);
        int aegis256x4_decrypt_detached(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *mac,
                                        size_t maclen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                        const uint8_t *k);
    """)

    # Get include directory (try local c_src first, then parent)
    local_include_dir = Path(__file__).parent / "c_src" / "include"
    if local_include_dir.exists():
        include_dir = local_include_dir
    else:
        repo_root = Path(__file__).parent.parent.resolve()
        include_dir = repo_root / "src" / "include"

    # Get all C source files
    c_sources = get_c_sources()

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


class CustomBuildExt(build_ext):
    """Custom build_ext command to build CFFI extension."""

    def run(self):
        # Build the CFFI extension
        ffibuilder = build_cffi_extension()
        ffibuilder.compile(verbose=True, tmpdir=self.build_temp)
        super().run()


setup(
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    # Build CFFI extension as part of setup
    setup_requires=["cffi>=2.1.1"],
    cffi_modules=["build_cffi.py:ffibuilder"],
    # Ensure the C sources are included in source distributions
    include_package_data=True,
    zip_safe=False,
)
