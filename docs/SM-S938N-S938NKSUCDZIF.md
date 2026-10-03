# SM-S938N / S938NKSUCDZIF (experimental)

- Model: `SM-S938N` (Galaxy S25 Ultra, Korea)
- Firmware: `S938NKSUCDZIF`
- Kernel: `6.6.127-android15-8-p33f4ffe-abogkiS938NKSUCDZIF-4k`
- Extracted boot image SHA-256: `b34704a033512bec67f1a79fd2eabcf33a77e0c50262a693599daf69ed810c06`
- Extracted kernel SHA-256: `225a068d7b9293ffe560611ca9e2bc4ce7aa2f47e78452770f6d139faedcba1e`
- App payload SHA-256: `328514c90fe8cbc0d43225abcaef7a1cdb211a124dd4dc8c88078ea0080c8470`

The profile and P0 fingerprint were derived from the supplied firmware image. The release payload compiles as an AArch64 ELF shared object and meets the app feed's 104,128-byte size requirement. The physical kernel-load assumption and trace-event behavior are inherited/derived but have not been confirmed on the device. This target has not completed a hardware run; keep it experimental until that evidence exists.

## Separate on-device observation

The supplied device log is for DirtyFrag CVE-2026-43284, not this profile's CVE-2026-43499 payload. In that run, the DirtyFrag patch steps landed and its daemon started, but the app could not verify root, and KernelSU refused the soft restart because Root My Galaxy Next had no `su` permission (or Shizuku was not available). This is useful evidence about that separate route only; it does not validate this firmware-derived profile or justify marking it device-tested.

The feed exposes KernelSU 3.3.0 and KernelSU-Next 3.4.0 daemons built for the Android 15 / 6.6 KMI. The repository also contains the upstream Samsung patches, KSU build workflow and `dfroot-lkm` source/workflow. The app repository already bundles the `dirtyfrag-android15-6.6.ko` module for this KMI.
