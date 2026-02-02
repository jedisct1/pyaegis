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

        // Random Access File (RAF) API

        // RAF constants
        #define AEGIS_RAF_ALG_128L  1
        #define AEGIS_RAF_ALG_128X2 2
        #define AEGIS_RAF_ALG_128X4 3
        #define AEGIS_RAF_ALG_256   4
        #define AEGIS_RAF_ALG_256X2 5
        #define AEGIS_RAF_ALG_256X4 6

        #define AEGIS_RAF_CREATE   0x01
        #define AEGIS_RAF_TRUNCATE 0x02

        #define AEGIS_RAF_CHUNK_MIN 1024
        #define AEGIS_RAF_CHUNK_MAX ...

        #define AEGIS_RAF_HEADER_SIZE   92
        #define AEGIS_RAF_FILE_ID_BYTES 32
        #define AEGIS_RAF_TAG_BYTES     16
        #define AEGIS_RAF_SCRATCH_ALIGN 64

        // RAF types
        typedef struct aegis_raf_scratch {
            uint8_t *buf;
            size_t   len;
        } aegis_raf_scratch;

        typedef struct aegis_raf_io {
            void *user;
            int (*read_at)(void *user, uint8_t *buf, size_t len, uint64_t off);
            int (*write_at)(void *user, const uint8_t *buf, size_t len, uint64_t off);
            int (*get_size)(void *user, uint64_t *size);
            int (*set_size)(void *user, uint64_t size);
            int (*sync)(void *user);
        } aegis_raf_io;

        typedef struct aegis_raf_rng {
            void *user;
            int (*random)(void *user, uint8_t *out, size_t len);
        } aegis_raf_rng;

        typedef struct aegis_raf_config {
            const aegis_raf_scratch *scratch;
            uint32_t                 chunk_size;
            uint8_t                  flags;
        } aegis_raf_config;

        typedef struct aegis_raf_info {
            uint16_t alg_id;
            uint32_t chunk_size;
            uint64_t file_size;
        } aegis_raf_info;

        // RAF helper functions
        size_t aegis_raf_chunk_min(void);
        size_t aegis_raf_chunk_max(void);
        size_t aegis_raf_header_size(void);
        size_t aegis_raf_scratch_align(void);
        int aegis_raf_probe(const aegis_raf_io *io, aegis_raf_info *info);

        // AEGIS-128L RAF
        typedef struct { uint8_t opaque[256]; ...; } aegis128l_raf_ctx;
        size_t aegis128l_raf_scratch_size(uint32_t chunk_size);
        int aegis128l_raf_scratch_validate(const aegis_raf_scratch *scratch, uint32_t chunk_size);
        int aegis128l_raf_create(aegis128l_raf_ctx *ctx, const aegis_raf_io *io, const aegis_raf_rng *rng,
                                 const aegis_raf_config *cfg, const uint8_t *master_key);
        int aegis128l_raf_open(aegis128l_raf_ctx *ctx, const aegis_raf_io *io, const aegis_raf_rng *rng,
                               const aegis_raf_config *cfg, const uint8_t *master_key);
        int aegis128l_raf_read(aegis128l_raf_ctx *ctx, uint8_t *out, size_t *bytes_read, size_t len,
                               uint64_t offset);
        int aegis128l_raf_write(aegis128l_raf_ctx *ctx, size_t *bytes_written, const uint8_t *in,
                                size_t len, uint64_t offset);
        int aegis128l_raf_truncate(aegis128l_raf_ctx *ctx, uint64_t size);
        int aegis128l_raf_get_size(const aegis128l_raf_ctx *ctx, uint64_t *size);
        int aegis128l_raf_sync(aegis128l_raf_ctx *ctx);
        void aegis128l_raf_close(aegis128l_raf_ctx *ctx);

        // AEGIS-128X2 RAF
        typedef struct { uint8_t opaque[256]; ...; } aegis128x2_raf_ctx;
        size_t aegis128x2_raf_scratch_size(uint32_t chunk_size);
        int aegis128x2_raf_scratch_validate(const aegis_raf_scratch *scratch, uint32_t chunk_size);
        int aegis128x2_raf_create(aegis128x2_raf_ctx *ctx, const aegis_raf_io *io, const aegis_raf_rng *rng,
                                  const aegis_raf_config *cfg, const uint8_t *master_key);
        int aegis128x2_raf_open(aegis128x2_raf_ctx *ctx, const aegis_raf_io *io, const aegis_raf_rng *rng,
                                const aegis_raf_config *cfg, const uint8_t *master_key);
        int aegis128x2_raf_read(aegis128x2_raf_ctx *ctx, uint8_t *out, size_t *bytes_read, size_t len,
                                uint64_t offset);
        int aegis128x2_raf_write(aegis128x2_raf_ctx *ctx, size_t *bytes_written, const uint8_t *in,
                                 size_t len, uint64_t offset);
        int aegis128x2_raf_truncate(aegis128x2_raf_ctx *ctx, uint64_t size);
        int aegis128x2_raf_get_size(const aegis128x2_raf_ctx *ctx, uint64_t *size);
        int aegis128x2_raf_sync(aegis128x2_raf_ctx *ctx);
        void aegis128x2_raf_close(aegis128x2_raf_ctx *ctx);

        // AEGIS-128X4 RAF
        typedef struct { uint8_t opaque[256]; ...; } aegis128x4_raf_ctx;
        size_t aegis128x4_raf_scratch_size(uint32_t chunk_size);
        int aegis128x4_raf_scratch_validate(const aegis_raf_scratch *scratch, uint32_t chunk_size);
        int aegis128x4_raf_create(aegis128x4_raf_ctx *ctx, const aegis_raf_io *io, const aegis_raf_rng *rng,
                                  const aegis_raf_config *cfg, const uint8_t *master_key);
        int aegis128x4_raf_open(aegis128x4_raf_ctx *ctx, const aegis_raf_io *io, const aegis_raf_rng *rng,
                                const aegis_raf_config *cfg, const uint8_t *master_key);
        int aegis128x4_raf_read(aegis128x4_raf_ctx *ctx, uint8_t *out, size_t *bytes_read, size_t len,
                                uint64_t offset);
        int aegis128x4_raf_write(aegis128x4_raf_ctx *ctx, size_t *bytes_written, const uint8_t *in,
                                 size_t len, uint64_t offset);
        int aegis128x4_raf_truncate(aegis128x4_raf_ctx *ctx, uint64_t size);
        int aegis128x4_raf_get_size(const aegis128x4_raf_ctx *ctx, uint64_t *size);
        int aegis128x4_raf_sync(aegis128x4_raf_ctx *ctx);
        void aegis128x4_raf_close(aegis128x4_raf_ctx *ctx);

        // AEGIS-256 RAF
        typedef struct { uint8_t opaque[256]; ...; } aegis256_raf_ctx;
        size_t aegis256_raf_scratch_size(uint32_t chunk_size);
        int aegis256_raf_scratch_validate(const aegis_raf_scratch *scratch, uint32_t chunk_size);
        int aegis256_raf_create(aegis256_raf_ctx *ctx, const aegis_raf_io *io, const aegis_raf_rng *rng,
                                const aegis_raf_config *cfg, const uint8_t *master_key);
        int aegis256_raf_open(aegis256_raf_ctx *ctx, const aegis_raf_io *io, const aegis_raf_rng *rng,
                              const aegis_raf_config *cfg, const uint8_t *master_key);
        int aegis256_raf_read(aegis256_raf_ctx *ctx, uint8_t *out, size_t *bytes_read, size_t len,
                              uint64_t offset);
        int aegis256_raf_write(aegis256_raf_ctx *ctx, size_t *bytes_written, const uint8_t *in,
                               size_t len, uint64_t offset);
        int aegis256_raf_truncate(aegis256_raf_ctx *ctx, uint64_t size);
        int aegis256_raf_get_size(const aegis256_raf_ctx *ctx, uint64_t *size);
        int aegis256_raf_sync(aegis256_raf_ctx *ctx);
        void aegis256_raf_close(aegis256_raf_ctx *ctx);

        // AEGIS-256X2 RAF
        typedef struct { uint8_t opaque[256]; ...; } aegis256x2_raf_ctx;
        size_t aegis256x2_raf_scratch_size(uint32_t chunk_size);
        int aegis256x2_raf_scratch_validate(const aegis_raf_scratch *scratch, uint32_t chunk_size);
        int aegis256x2_raf_create(aegis256x2_raf_ctx *ctx, const aegis_raf_io *io, const aegis_raf_rng *rng,
                                  const aegis_raf_config *cfg, const uint8_t *master_key);
        int aegis256x2_raf_open(aegis256x2_raf_ctx *ctx, const aegis_raf_io *io, const aegis_raf_rng *rng,
                                const aegis_raf_config *cfg, const uint8_t *master_key);
        int aegis256x2_raf_read(aegis256x2_raf_ctx *ctx, uint8_t *out, size_t *bytes_read, size_t len,
                                uint64_t offset);
        int aegis256x2_raf_write(aegis256x2_raf_ctx *ctx, size_t *bytes_written, const uint8_t *in,
                                 size_t len, uint64_t offset);
        int aegis256x2_raf_truncate(aegis256x2_raf_ctx *ctx, uint64_t size);
        int aegis256x2_raf_get_size(const aegis256x2_raf_ctx *ctx, uint64_t *size);
        int aegis256x2_raf_sync(aegis256x2_raf_ctx *ctx);
        void aegis256x2_raf_close(aegis256x2_raf_ctx *ctx);

        // AEGIS-256X4 RAF
        typedef struct { uint8_t opaque[256]; ...; } aegis256x4_raf_ctx;
        size_t aegis256x4_raf_scratch_size(uint32_t chunk_size);
        int aegis256x4_raf_scratch_validate(const aegis_raf_scratch *scratch, uint32_t chunk_size);
        int aegis256x4_raf_create(aegis256x4_raf_ctx *ctx, const aegis_raf_io *io, const aegis_raf_rng *rng,
                                  const aegis_raf_config *cfg, const uint8_t *master_key);
        int aegis256x4_raf_open(aegis256x4_raf_ctx *ctx, const aegis_raf_io *io, const aegis_raf_rng *rng,
                                const aegis_raf_config *cfg, const uint8_t *master_key);
        int aegis256x4_raf_read(aegis256x4_raf_ctx *ctx, uint8_t *out, size_t *bytes_read, size_t len,
                                uint64_t offset);
        int aegis256x4_raf_write(aegis256x4_raf_ctx *ctx, size_t *bytes_written, const uint8_t *in,
                                 size_t len, uint64_t offset);
        int aegis256x4_raf_truncate(aegis256x4_raf_ctx *ctx, uint64_t size);
        int aegis256x4_raf_get_size(const aegis256x4_raf_ctx *ctx, uint64_t *size);
        int aegis256x4_raf_sync(aegis256x4_raf_ctx *ctx);
        void aegis256x4_raf_close(aegis256x4_raf_ctx *ctx);
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
        "raf/*.c",
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
