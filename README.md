# DBKP Detector

A small command‑line tool that checks whether a boot image has been modified by  
**DualBootKernelPatcher (DBKP)**.

The program scans the boot image for DBKP‑specific artifacts and prints one of two results:

- `DBKP found`
- `Boot image clean`

---

## Usage

```bash
./detector <boot.img>
```
Example:

```bash
./detector boot.img
```
Output:
- `DBKP found`
> or
- `Boot image clean`
## Build (Linux x86_64)
```bash
gcc detectoror.c -O2 -o detector_x86
```
## Build (Linux ARM64 / aarch64)
```bash
aarch64-linux-gnu-gcc detector.c -O2 -o detector_arm64
```


License
MIT License.
