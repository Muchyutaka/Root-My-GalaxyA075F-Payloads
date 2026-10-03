# Root My Galaxy payload: SM-S938N / S938NKSUCDZIF

Device-specific release payload built for Samsung Galaxy S25 Ultra (SM-S938N).

- Firmware: `S938NKSUCDZIF`
- Kernel: `6.6.127-android15-8-p33f4ffe-abogki`
- Artifact: `artifacts/pa3q-S938NKSUCDZIF/cve-2026-43499-app.release.so`
- Artifact format: AArch64 ELF shared object
- Artifact size: 104,128 bytes
- SHA-256: `310D1E93139572D4FE040BDE8E224D59139D09944C7E0186CFF6D64AAE3DA8C3`

## Build basis

The target profile was derived from the supplied `boot.img.lz4` and bootloader files for firmware `S938NKSUCDZIF`. The decompressed boot image SHA-256 is `b34704a033512bec67f1a79fd2eabcf33a77e0c50262a693599daf69ed810c06`; the extracted kernel SHA-256 is `225a068d7b9293ffe560611ca9e2bc4ce7aa2f47e78452770f6d139faedcba1e`. The payload source base is `rushiranpise/Root-My-Galaxy-Payloads` commit `e9848975fe2401f2b8ba63c1091a11a31864b90e`.

The generated P0 fingerprint and target offsets are included under `targets/`. They were not validated by running this payload on an SM-S938N device. In particular, the inherited physical kernel-load assumption and device-side trace event behavior still need on-device confirmation. Treat this build as an engineering candidate, not a verified rooting result.

## License

The upstream payload project is licensed under Apache-2.0; see `LICENSE`.
