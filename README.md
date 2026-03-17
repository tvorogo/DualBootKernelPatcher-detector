## BETA BRANCH IS USED ONLY FOR TESTING THE DETECTOR ON LG DEVICES

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
gcc detector.c -o detector_x86 -lz
```
## Build (Linux ARM64 / aarch64)
```bash
aarch64-linux-gnu-gcc detector.c -static -O2 -o detector_arm64 
```

## Thanks for
- [Project-Aloha](https://github.com/Project-Aloha) for its [DBKP](https://github.com/Project-Aloha/DualBootKernelPatcher)
- [Woa-Project](https://github.com/WOA-Project) for its [SDDBKIP](https://github.com/WOA-Project/SurfaceDuoDualBootKernelImagePatcher)
- [Remtrik](github.com/Remtrik) for the tip on how this can be implemented
- [Daniel](https://github.com/Daniel224455) for one tip
- [WoA Helper](https://github.com/n00b69/woa-helper/) for the opportunity to test my abilities


License
MIT License.
