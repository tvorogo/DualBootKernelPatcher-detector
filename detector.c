// super duper mega small detector
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
// made by github.com/tvorogo
static inline uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static inline int64_t sign28(int32_t v) {
    return (v & (1 << 27)) ? (v | ~((1 << 28) - 1)) : v;
}

static int is_dbkp_kernel(const uint8_t *buf, size_t len) {
    if (len < 0x80) return 0;
    size_t base = 0;
    if (len >= 0x40 && memcmp(buf, "UNCOMPRESSED_IMG", 16) == 0) {
        base = 0x14;
        if (len < base + 0x80) return 0;
    }

    uint32_t insn1 = rd32(buf + base);
    uint32_t insn2 = rd32(buf + base + 4);

    if ((insn1 & 0xFC000000) != 0x14000000) return 0;
    if ((insn2 & 0xFC000000) != 0x14000000) return 0;
    int64_t t1 = base + sign28((insn1 & 0x03FFFFFF) << 2);
    int64_t t2 = base + 4 + sign28((insn2 & 0x03FFFFFF) << 2);
    if (t1 < 0 || t1 >= (int64_t)len) return 0;
    if (t2 < 0 || t2 >= (int64_t)len) return 0;

    return 1;
}

static int extract_kernel(const char *path, uint8_t **out, size_t *out_len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;

    uint8_t hdr[0x40];
    if (read(fd, hdr, 0x40) != 0x40) { close(fd); return 0; }
    if (memcmp(hdr, "ANDROID!", 8) != 0) { close(fd); return 0; }
    uint32_t kernel_size = rd32(hdr + 0x08);
    uint32_t page_size   = rd32(hdr + 0x24);
    uint32_t ver         = rd32(hdr + 0x28);
    uint32_t hdr_size    = rd32(hdr + 0x2C);
    if (!page_size) page_size = 0x1000;
    uint32_t off = (ver >= 3 && hdr_size) ? hdr_size : page_size;

    uint8_t *buf = malloc(kernel_size);
    if (!buf) { close(fd); return 0; }
    if (lseek(fd, off, SEEK_SET) < 0) {
        free(buf);
        close(fd);
        return 0;
    }
    if (read(fd, buf, kernel_size) != (ssize_t)kernel_size) {
        free(buf);
        close(fd);
        return 0;
    }

    close(fd);
    *out = buf;
    *out_len = kernel_size;
    return 1;
}
int main(int argc, char **argv) {
    if (argc < 2) {
        write(1, "Usage: ./detector <boot.img>\n", 30);
        return 1;
    }

    uint8_t *kernel = NULL;
    size_t klen = 0;

    if (!extract_kernel(argv[1], &kernel, &klen)) {
        write(1, "Invalid boot.img\n", 17);
        return 1;
    }

    int patched = is_dbkp_kernel(kernel, klen);
    free(kernel);

    if (patched)
        write(1, "DBKP patch detected\n", 20);
    else
        write(1, "Boot image is clean\n", 20);

    return 0;
}
