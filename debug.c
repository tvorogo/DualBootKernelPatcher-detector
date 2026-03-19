#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
static inline void out(const char *s) {
    write(1, s, strlen(s));
}
static inline uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}
static inline int64_t sign28(int32_t v) {
    return (v & (1 << 27)) ? (v | ~((1 << 28) - 1)) : v;
}
static void dump_hex(const uint8_t *buf, size_t len) {
    char tmp[64];
    size_t n = len < 64 ? len : 64;
    for (size_t i = 0; i < n; i++) {
        int l = snprintf(tmp, sizeof(tmp), "%02X ", buf[i]);
        write(1, tmp, l);
        if ((i % 16) == 15) write(1, "\n", 1);
    }
    write(1, "\n", 1);
}
static int is_dbkp_kernel(const uint8_t *buf, size_t len) {
    char t[128];

    snprintf(t, sizeof(t), "kernel length = %zu\n", len);
    out(t);

    if (len < 0x80) {
        out("kernel too small\n");
        return 0;
    }
    size_t base = 0;
    if (len >= 0x40 && memcmp(buf, "UNCOMPRESSED_IMG", 16) == 0) {
        out("UNCOMPRESSED_IMG detected\n");
        base = 0x14;
    } else {
        out("Normal kernel\n");
    }
    snprintf(t, sizeof(t), "base = 0x%zx\n", base);
    out(t);
    uint32_t insn1 = rd32(buf + base);
    uint32_t insn2 = rd32(buf + base + 4);
    snprintf(t, sizeof(t), "insn1 = 0x%08X\n", insn1);
    out(t);
    snprintf(t, sizeof(t), "insn2 = 0x%08X\n", insn2);
    out(t);
    if ((insn1 & 0xFC000000) != 0x14000000) {
        out("insn1 is NOT B imm26\n");
        return 0;
    }
    if ((insn2 & 0xFC000000) != 0x14000000) {
        out("insn2 is NOT B imm26\n");
        return 0;
    }
    int64_t off1 = sign28((insn1 & 0x03FFFFFF) << 2);
    int64_t off2 = sign28((insn2 & 0x03FFFFFF) << 2);
    int64_t t1 = base + off1;
    int64_t t2 = base + 4 + off2;
    snprintf(t, sizeof(t), "off1=%lld target1=%lld\n", (long long)off1, (long long)t1);
    out(t);
    snprintf(t, sizeof(t), "off2=%lld target2=%lld\n", (long long)off2, (long long)t2);
    out(t);
    if (t1 < 0 || t1 >= (int64_t)len) {
        out("target1 out of range\n");
        return 0;
    }
    if (t2 < 0 || t2 >= (int64_t)len) {
        out("target2 out of range\n");
        return 0;
    }

    out("DBKP signature matched\n");
    return 1;
}
static int extract_kernel(const char *path, uint8_t **outbuf, size_t *outlen) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    uint8_t hdr[0x40];
    if (read(fd, hdr, 0x40) != 0x40) { close(fd); return 0; }
    if (memcmp(hdr, "ANDROID!", 8) != 0) {
        out("ANDROID! header not found\n");
        close(fd);
        return 0;
    }
    uint32_t kernel_size = rd32(hdr + 0x08);
    uint32_t page_size   = rd32(hdr + 0x24);
    uint32_t ver         = rd32(hdr + 0x28);
    uint32_t hdr_size    = rd32(hdr + 0x2C);
    char t[128];
    snprintf(t, sizeof(t),
        "kernel_size=%u page_size=%u ver=%u hdr_size=%u\n",
        kernel_size, page_size, ver, hdr_size);
    out(t);
    if (!page_size) page_size = 0x1000;
    uint32_t off = (ver >= 3 && hdr_size) ? hdr_size : page_size;
    snprintf(t, sizeof(t), "kernel offset = %u\n", off);
    out(t);
    uint8_t *buf = malloc(kernel_size);
    if (!buf) { close(fd); return 0; }
    lseek(fd, off, SEEK_SET);
    if (read(fd, buf, kernel_size) != (ssize_t)kernel_size) {
        free(buf);
        close(fd);
        return 0;
    }
    close(fd);
    out("first 64 bytes of kernel:\n");
    dump_hex(buf, kernel_size);
    *outbuf = buf;
    *outlen = kernel_size;
    return 1;
}
int main(int argc, char **argv) {
    if (argc < 2) {
        out("Usage: ./detetor boot.img\n");
        return 1;
    }
    uint8_t *kernel = NULL;
    size_t klen = 0;
    if (!extract_kernel(argv[1], &kernel, &klen)) {
        out("Extraction failed\n");
        return 1;
    }
    int patched = is_dbkp_kernel(kernel, klen);
    free(kernel);
    if (patched)
        out("\n===DBKP patch detected ===\n");
    else
        out("\n===Boot image is clean ===\n");
    return 0;
}
