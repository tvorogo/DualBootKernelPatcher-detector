> [!WARNING]
> TEST BRANCH MAY CAN NOT WORK

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
x86_64-linux-musl-cross/bin/x86_64-linux-musl-gcc detector.c -static -Os -o detector_x86
```
## Build (Linux ARM64 / aarch64)
```bash
aarch64-linux-musl-gcc detector.c -static -Os -o detector_arm64
```
> [!TIP]
> For Build debug ver:

## Build (Linux x86_64)
```bash
x86_64-linux-musl-cross/bin/x86_64-linux-musl-gcc debug.c -static -Os -o debug_x86
```
## Build (Linux ARM64 / aarch64)
```bash
aarch64-linux-musl-gcc debug.c -static -Os -o debug
```

## Thanks for
- [Project-Aloha](https://github.com/Project-Aloha) for its [DBKP](https://github.com/Project-Aloha/DualBootKernelPatcher)
- [Woa-Project](https://github.com/WOA-Project) for its [SDDBKIP](https://github.com/WOA-Project/SurfaceDuoDualBootKernelImagePatcher)
- [Remtrik](github.com/Remtrik) for the tip on how this can be implemented
- [Daniel](https://github.com/Daniel224455) for one tip
- [WoA Helper](https://github.com/n00b69/woa-helper/) for the opportunity to test my abilities


License
MIT License.
