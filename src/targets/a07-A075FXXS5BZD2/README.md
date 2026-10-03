# a07-A075FXXS5BZD2 — Samsung Galaxy A07 4G (SM-A075F)

| | |
| --- | --- |
| model | `SM-A075F` |
| device | `a075fxx` |
| chipset | MediaTek MT6789 (Helio G99), aarch64, 4K pages |
| firmware | `A075FXXS5BZD2` (release tag `1` of this repository) |
| kernel | `6.12.23-android16-5-abA075FXXS5BZD2-4k` (6.12 GKI, Android 16) |
| KIMAGE_TEXT_BASE | `0xffffffc080000000` |
| vermagic | `6.12.23-android16-5-abA075FXXS5BZD2-4k SMP preempt mod_unload modversions aarch64` |
| fingerprint | `samsung/a075fxx/a075f:16/BP4A.260406.019/A075FXXS5BZD2:user/release-keys` |

Files in this directory:

- `target.h` — every firmware-dependent constant for the exploit payload.
  Value-by-value verified against the exact firmware kernel Image by
  `tools/derive_a075f_target.py` in CI (see below). Derivation record:
  [`docs/A07-A075FXXS5BZD2.md`](../../docs/A07-A075FXXS5BZD2.md).
- `p0_fingerprint.h` — 32 slide rows / 256 source qwords at probe
  `0x1f0000`, generated from the exact raw Image and read-back verified by
  `tools/generate_p0_fingerprint.pl`.
- `kernel.config` — the exact `.config` of the target kernel, extracted
  from the IKCONFIG blob embedded in the Image (`CONFIG_IKCONFIG_PROC=y`).
  It is the configuration the KernelSU CI build feeds to `make`, so the
  module's `__versions` CRCs are produced against the exact target config.

## Build

The payload is built by CI (`.github/workflows/port-a075f.yml`), which
fetches the release assets, verifies every value in `target.h`, and
compiles with Android NDK r29:

```sh
# local equivalent
export ANDROID_NDK_HOME=/path/to/android-ndk-r29
make TARGET=a07-A075FXXS5BZD2 release
# -> build/a07-A075FXXS5BZD2/cve-2026-43499-app.release.so (104128 bytes),
#    copied by CI to artifacts/a07-A075FXXS5BZD2/cve-2026-43499-app.so
```

The matching KernelSU late-load pair (built from the exact Samsung
opensource tree + `kernel.config`, KernelSU v3.2.5 `b0bc817`):

```text
kernelsu/android16-6.12_kernelsu-A075FXXS5BZD2-kdp.ko
kernelsu/ksud-A075FXXS5BZD2-kdp
```

## Status

- Offline verification: complete (BTF/symbols/disassembly, CI-enforced).
- Hardware verification: **pending** — see
  [`docs/A07-A075FXXS5BZD2.md`](../../docs/A07-A075FXXS5BZD2.md) §9 for
  the exact on-device checks (trace event id `110`, `P0_KERNEL_PHYS_LOAD`
  via `/proc/iomem`, full exploit run, `ksud late-load` under DEFEX).
