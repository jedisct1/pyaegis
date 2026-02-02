#include <stddef.h>
#include <stdint.h>

#include "raf_internal.h"

size_t
aegis_raf_chunk_min(void)
{
    return AEGIS_RAF_CHUNK_MIN;
}

size_t
aegis_raf_chunk_max(void)
{
    return AEGIS_RAF_CHUNK_MAX;
}

size_t
aegis_raf_header_size(void)
{
    return AEGIS_RAF_HEADER_SIZE;
}

size_t
aegis_raf_scratch_align(void)
{
    return AEGIS_RAF_SCRATCH_ALIGN;
}

int
aegis_raf_probe(const aegis_raf_io *io, aegis_raf_info *info)
{
    uint8_t  hdr[AEGIS_RAF_HEADER_SIZE];
    uint16_t version;
    uint16_t header_size;
    uint32_t chunk_size;
    uint16_t mac_len;
    uint16_t alg_id;

    if (io == NULL || info == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (io->read_at == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (io->read_at(io->user, hdr, AEGIS_RAF_HEADER_SIZE, 0) != 0) {
        return -1;
    }

    if (memcmp(hdr, AEGIS_RAF_MAGIC, 8) != 0) {
        errno = EINVAL;
        return -1;
    }

    version = LOAD16_LE(hdr + 8);
    if (version != AEGIS_RAF_VERSION) {
        errno = EINVAL;
        return -1;
    }

    header_size = LOAD16_LE(hdr + 10);
    if (header_size != AEGIS_RAF_HEADER_SIZE) {
        errno = EINVAL;
        return -1;
    }

    chunk_size = LOAD32_LE(hdr + 12);
    if (chunk_size < AEGIS_RAF_CHUNK_MIN || chunk_size > AEGIS_RAF_CHUNK_MAX ||
        (chunk_size % 16) != 0) {
        errno = EINVAL;
        return -1;
    }

    mac_len = LOAD16_LE(hdr + 16);
    if (mac_len != AEGIS_RAF_MAC_LEN) {
        errno = EINVAL;
        return -1;
    }

    alg_id = LOAD16_LE(hdr + 18);
    if (alg_id < AEGIS_RAF_ALG_128L || alg_id > AEGIS_RAF_ALG_256X4) {
        errno = EINVAL;
        return -1;
    }

    {
        size_t i;
        for (i = 0; i < AEGIS_RAF_RESERVED_BYTES; i++) {
            if (hdr[60 + i] != 0) {
                errno = EINVAL;
                return -1;
            }
        }
    }

    info->alg_id     = alg_id;
    info->chunk_size = chunk_size;
    info->file_size  = LOAD64_LE(hdr + 20);

    return 0;
}
