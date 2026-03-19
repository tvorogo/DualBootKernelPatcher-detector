#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

// Made by github.com/tvorogo

static inline uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}
static inline uint64_t rd64(const uint8_t *p) {
    return (uint64_t)p[0]
         | ((uint64_t)p[1] << 8)
         | ((uint64_t)p[2] << 16)
         | ((uint64_t)p[3] << 24)
         | ((uint64_t)p[4] << 32)
         | ((uint64_t)p[5] << 40)
         | ((uint64_t)p[6] << 48)
         | ((uint64_t)p[7] << 56);
}
static inline int64_t sign28(int32_t v) {
    return (v & (1 << 27)) ? (v | ~((1 << 28) - 1)) : v;
}
static void dump_hex(const uint8_t *buf, size_t len) {
    size_t n = len < 64 ? len : 64;
    printf("First %zu bytes of kernel:\n", n);
    for (size_t i = 0; i < n; i++) {
        printf("%02X ", buf[i]);
        if ((i % 16) == 15) printf("\n");
    }
    printf("\n");
}
static bool is_dbkp_kernel(const uint8_t *buf, size_t len) {
    printf("kernel length = %zu\n", len);
    if (len < 0x80) {
        printf("kernel too small (<0x80)\n");
        return false;
    }
    size_t base = 0;

    if (len >= 0x40 && memcmp(buf, "UNCOMPRESSED_IMG", 16) == 0) {
        printf("Detected UNCOMPRESSED_IMG header\n");
        base = 0x14;
    } else {
        printf("Normal kernel (no UNCOMPRESSED_IMG)\n");
    }
    printf("base = 0x%zx\n", base);
    uint32_t insn1 = rd32(buf + base);
    uint32_t insn2 = rd32(buf + base + 4);
    printf("insn1 = 0x%08X\n", insn1);
    printf("insn2 = 0x%08X\n", insn2);
    if ((insn1 & 0xFC000000) != 0x14000000) {
        printf("insn1 is NOT a B imm26 instruction\n");
        return false;
    }
    if ((insn2 & 0xFC000000) != 0x14000000) {
        printf("insn2 is NOT a B imm26 instruction\n");
        return false;
    }
    int32_t imm1 = (insn1 & 0x03FFFFFF);
    int32_t imm2 = (insn2 & 0x03FFFFFF);
    int64_t off1 = sign28(imm1 << 2);
    int64_t off2 = sign28(imm2 << 2);
    int64_t t1 = base + off1;
    int64_t t2 = base + 4 + off2;
    printf("off1 = %lld, target1 = %lld\n", (long long)off1, (long long)t1);
    printf("off2 = %lld, target2 = %lld\n", (long long)off2, (long long)t2);
    if (t1 < 0 || t1 >= (int64_t)len) {
        printf("target1 out of range\n");
        return false;
    }
    if (t2 < 0 || t2 >= (int64_t)len) {
        printf("target2 out of range\n");
        return false;
    }
    printf("DBKP signature matched\n");
    return true;
}
static bool extract_kernel(const char *path, uint8_t **out, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror("fopen");
        return false;
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    printf("boot.img size = %ld\n", fsize);

    if (fsize < 0x40) {
        printf("boot.img too small\n");
        fclose(f);
        return false;
    }
    rewind(f);
    uint8_t hdr[0x40];
    fread(hdr, 1, 0x40, f);
    if (memcmp(hdr, "ANDROID!", 8) != 0) {
        printf("ANDROID! header not found\n");
        fclose(f);
        return false;
    }
    uint32_t kernel_size = rd32(hdr + 0x08);
    uint32_t page_size   = rd32(hdr + 0x24);
    uint32_t ver         = rd32(hdr + 0x28);
    uint32_t hdr_size    = rd32(hdr + 0x2C);
    printf("kernel_size = %u\n", kernel_size);
    printf("page_size   = %u\n", page_size);
    printf("header_ver  = %u\n", ver);
    printf("header_size = %u\n", hdr_size);
    if (!page_size) page_size = 0x1000;
    uint32_t off = (ver >= 3 && hdr_size) ? hdr_size : page_size;
    printf("kernel offset = %u\n", off);

    if ((uint64_t)off + kernel_size > (uint64_t)fsize) {
        printf("kernel_size + offset > file size\n");
        fclose(f);
        return false;
    }
    fseek(f, off, SEEK_SET);
    uint8_t *buf = malloc(kernel_size);
    fread(buf, 1, kernel_size, f);
    fclose(f);
    *out = buf;
    *out_len = kernel_size;
    printf("kernel extracted successfully\n");
    dump_hex(buf, kernel_size);

    return true;
}
int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <boot.img>\n", argv[0]);
        return 0;
    }
    uint8_t *kernel = NULL;
    size_t klen = 0;
    if (!extract_kernel(argv[1], &kernel, &klen)) {
        printf("Extraction failed\n");
        return 1;
    }
    bool patched = is_dbkp_kernel(kernel, klen);
    free(kernel);
    printf("\n=== RESULT: %s ===\n",
           patched ? "DBKP patch detected" : "Boot image is clean");
    return 0;
}
