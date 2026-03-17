#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
// made by github.com/tvorogo
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
static bool is_dbkp_kernel(const uint8_t *buf, size_t len) {
    if (len < 0x80) return false;
    size_t base = 0;
    if (len >= 0x40 && memcmp(buf, "UNCOMPRESSED_IMG", 16) == 0) {
        base = 0x14;
        if (len < base + 0x80) return false;
    }
    
    uint32_t insn1 = rd32(buf + base);
    uint32_t insn2 = rd32(buf + base + 4);
    if ((insn1 & 0xFC000000) != 0x14000000) return false;
    if ((insn2 & 0xFC000000) != 0x14000000) return false;
    int64_t t1 = base + sign28((insn1 & 0x03FFFFFF) << 2);
    int64_t t2 = base + 4 + sign28((insn2 & 0x03FFFFFF) << 2);
    if (t1 < 0 || t1 >= (int64_t)len) return false;
    if (t2 < 0 || t2 >= (int64_t)len) return false;
    return true;
}

static bool extract_kernel(const char *path, uint8_t **out, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    if (fsize < 0x40) { fclose(f); return false; }
    rewind(f);
    uint8_t hdr[0x40];
    if (fread(hdr, 1, 0x40, f) != 0x40) { fclose(f); return false; }
    if (memcmp(hdr, "ANDROID!", 8) != 0) { fclose(f); return false; }
    uint32_t kernel_size = rd32(hdr + 0x08);
    uint32_t page_size   = rd32(hdr + 0x24);
    uint32_t ver         = rd32(hdr + 0x28);
    uint32_t hdr_size    = rd32(hdr + 0x2C);
    if (!page_size) page_size = 0x1000;
    uint32_t off = (ver >= 3 && hdr_size) ? hdr_size : page_size;
    if ((uint64_t)off + kernel_size > (uint64_t)fsize) {
        fclose(f);
        return false;
    }
    if (fseek(f, off, SEEK_SET) != 0) { fclose(f); return false; }
    uint8_t *buf = malloc(kernel_size);
    if (!buf) { fclose(f); return false; }
    if (fread(buf, 1, kernel_size, f) != kernel_size) {
        free(buf);
        fclose(f);
        return false;
    }
    fclose(f);
    *out = buf;
    *out_len = kernel_size;
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
        printf("Not a valid boot.img or kernel extraction failed\n");
        return 1;
    }
    bool patched = is_dbkp_kernel(kernel, klen);
    free(kernel);
    printf(patched ? "DBKP patch detected\n" : "Boot image is clean\n");
    return 0;
}
