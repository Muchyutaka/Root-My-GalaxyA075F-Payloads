# Root My Galaxy payload: SM-S938N / S938NKSUCDZIF

Device-specific release payload built for Samsung Galaxy S25 Ultra (SM-S938N).

- Firmware: `S938NKSUCDZIF`
- Kernel: `6.6.127-android15-8-p33f4ffe-abogki`
- Artifact: `cve-2026-43499-app.release.so`
- Format: AArch64 ELF shared object
- Size: 104,128 bytes
- SHA-256: `310D1E93139572D4FE040BDE8E224D59139D09944C7E0186CFF6D64AAE3DA8C3`

Built from the supplied boot image and the `rushiranpise/Root-My-Galaxy-Payloads` source at commit `e9848975fe2401f2b8ba63c1091a11a31864b90e`. The target profile was derived from the supplied firmware images. `target.h` and `p0_fingerprint.h` record the generated profile. It has not been exercised on an SM-S938N device. The inherited physical kernel-load assumption and device-side trace event behavior still require on-device confirmation; this is an engineering candidate, not a verified rooting result.

See `LICENSE` for the upstream Apache-2.0 license.
