# a07-A075FXXS5BZD2

Target profile for the Samsung Galaxy A07 (SM-A075F), firmware
`A075FXXS5BZD2`:

```text
model: SM-A075F
device: a075fxx
firmware: A075FXXS5BZD2
kernel: 6.12.23-android16-5-abA075FXXS5BZD2-4k
vermagic: 6.12.23-android16-5-abA075FXXS5BZD2-4k SMP preempt mod_unload modversions aarch64
platform: MediaTek MT6789 (Helio G99), Samsung little-kernel
page size: 4096
CONFIG_ARM64_VA_BITS_39=y, CONFIG_ARM64_4K_PAGES=y, CONFIG_RELOCATABLE=y,
CONFIG_RANDOMIZE_BASE=y
```

Every offset in `target.h` and every row of `p0_fingerprint.h` is derived from the
exact `A075FXXS5BZD2` boot kernel Image (`0x2700100` bytes) and its recovered BTF.
No value was taken from another device.

The kernel image uses `KIMAGE_TEXT_BASE = 0xffffffc080000000`; an image offset is
always `vaddr - KIMAGE_TEXT_BASE`.

Generate the 32-row fingerprint table from the raw kernel Image with:

```sh
tools/generate_p0_fingerprint.pl Image 0x1f0000 p0_fingerprint.h
```

Build with Android NDK r29:

```sh
make TARGET=a07-A075FXXS5BZD2 ANDROID_NDK_HOME=/path/to/android-ndk release
```

Derivations, cross-checks and the remaining hardware validation steps are
recorded in [`docs/A07-A075FXXS5BZD2.md`](../../../docs/A07-A075FXXS5BZD2.md).
