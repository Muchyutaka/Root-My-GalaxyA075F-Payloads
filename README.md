# Root My Galaxy Payloads

This repository contains the device-specific native side of
[Root My Galaxy](https://github.com/BuSung-dev/Root-My-Galaxy):

- exact firmware profiles and offsets;
- the app-domain CVE-2026-43499 exploit source and compiled payload;
- the app bootstrap helper source;
- the verified KernelSU late-load build artifacts;
- the support feed consumed by the application.

It intentionally does not contain Android application source code.

## Supported payloads

| Payload | Compatible models | Kernel version | Status |
| --- | --- | --- | --- |
| `galaxy-s25-series-2026-06-07` | Galaxy S25, S25+, S25 Edge, and S25 Ultra regional models | `6.6.98` | Device-tested |
| `pa3q-S938NKSUCDZIF-ksu330` | Galaxy S25 Ultra `SM-S938N` | `6.6.127` | Device-tested |
| `pa3q-S938NKSUCDZIF-ksu325` | Galaxy S25 Ultra `SM-S938N` | `6.6.127` | Device-tested |
| `pa3q-S938NKSUCDZIF-ksun340` | Galaxy S25 Ultra `SM-S938N` | `6.6.127` | Device-tested |
| `pa3q-S938NKSUCDZIF-ksun330` | Galaxy S25 Ultra `SM-S938N` | `6.6.127` | Device-tested |
| `pa3q-S938NKSUCDZIF-rsksu420` | Galaxy S25 Ultra `SM-S938N` | `6.6.127` | Device-tested |
| `pa3q-S938NKSUCDZIF-rsksu420-rc2` | Galaxy S25 Ultra `SM-S938N` | `6.6.127` | Device-tested |
| `e3q-S928BXXS6DZI1-ksun340` | Galaxy S24 Ultra `SM-S928B` | `6.1.145` | Build verified; device test pending |
| `e3q-S928USQS6DZF2` | Galaxy S24 Ultra `SM-S928U1` | `6.1.145` | Device-tested |
| `e3q-S9280ZCS6DZF2` | Galaxy S24 Ultra China `SM-S9280` | `6.1.145` | Device-tested |
| `e2s-S926BXXUEDZDR` | Galaxy S24+ `SM-S926B` | `6.1.157` | Device-tested |
| `essi-A566EXXSCCZG6` | Galaxy A56 5G `SM-A566E` | `6.6.102` | Device-tested |
| `a36xq-A366WVLS3AYG1` | Galaxy A36 5G `SM-A366W` | `6.6.46` | Device-tested |
| `a53x-A536EXXSNGZG3` | Galaxy A53 5G `SM-A536E` | `5.10.237` | Device-tested |
| `dm3q-S9180ZHS8FZF5` | Galaxy S23 Ultra `SM-S9180` | `5.15.189` | Test in progress |
| `q4q-F9360ZCSAIZF1` | Galaxy Z Fold4 `SM-F9360` | `5.10.236` | Device-tested |
| `dm2q-S916BXXSAFZG1` | Galaxy S23+ `SM-S916B` | `5.15.189` | Experimental: hardware root from ADB shell; not in app feed |
| `dm3q-S918BXXSAFZF5` | Galaxy S23 Ultra `SM-S918B` | `5.15.189` | Confirmed working: full chain through the app (Shizuku mode) incl. KernelSU late-load and granted `su` |

The S928B DZI1 firmware-derived profile is available in the app feed as `e3q-S928BXXS6DZI1-ksun340`. Its app payload and KernelSU-Next 3.4.0 module/daemon passed the GitHub Actions build and pairing checks. The profile is firmware-derived and still awaits testing on an SM-S928B running the exact DZI1 release; it is marked `(test)` in the feed. See [`docs/SM-S928B-S928BXXS6DZI1.md`](docs/SM-S928B-S928BXXS6DZI1.md).

The S916B FZG1 profile is shell-only today. Its exact tracefs route works from `adb shell`, but direct app-domain execution is not supported. Root My Galaxy would need to delegate the native runner through an authorized shell bridge such as Shizuku. See [`artifacts/dm2q-S916BXXSAFZG1/README.md`](artifacts/dm2q-S916BXXSAFZG1/README.md).

The S918B FZF5 profile is hardware-verified through the app's Shizuku mode (exploit, KernelSU late-load, granted `su` under enforcing). Its physical-P0 fallback also engages in unprivileged app-domain execution, but rooting without Shizuku is not yet hardware-confirmed. See [`docs/SM-S918B-S918BXXSAFZF5.md`](docs/SM-S918B-S918BXXSAFZF5.md).
