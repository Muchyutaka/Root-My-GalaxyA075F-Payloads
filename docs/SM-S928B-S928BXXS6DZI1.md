# SM-S928B / S928BXXS6DZI1 port record

This profile was derived from the user-supplied AP and BL firmware archives. The AP archive contains `boot.img.lz4`; its SHA-256 matches the separately supplied boot image exactly. The model/build from the AP/BL filenames and kernel banner agree on `SM-S928B` / `S928BXXS6DZI1`.

## Firmware evidence

| Object | Size | SHA-256 |
| --- | ---: | --- |
| Supplied `boot.img.lz4` | 22,105,132 bytes | `f426ca87cf14034f9e3b873ebe55b743d0c208eee66eaf48a57b1d4a040e5a23` |
| Decompressed `boot.img` | 100,663,296 bytes | `b267fef5473876bbc11e97ef90df47842639399f07ea09e1ec8d2d4f2d18c36a` |
| Raw ARM64 Image | 38,005,248 bytes | `eb84717736af62dca7a2fba87e51a6ad404d0b2c43369920ddf6bfbaee4ac02d` |
| Extracted BTF | 5,981,779 bytes | `20176e654112f44e198337e902d66b5214ff45e0e1facc572a5a6d22fcd8c3d4` |
| Supplied BL tar.md5 | 103,956,593 bytes | `d64135395a307a6bf4157154d0b0c2d5b6c1444ffc819cc5cf06d91f25d1af77` |

Kernel banner: `6.1.145-android14-11-33419968-abS928BXXS6DZI1`. The recovered ELF has 107,257 kallsyms entries.

## Port differences from DZF2

The exploit-sensitive BTF layouts remain compatible where checked: `rt_mutex_waiter` is `0x58` bytes, `file_operations` is `0x110`, `configfs_buffer` is `0x80`, `workqueue_struct` is `0x140`, and `pool_workqueue` is `0x100`. The worker-thread return address used by tracefs was re-derived by disassembly: `worker_thread` starts at `0xdb100`; the return after its `schedule()` call is `0xdb1a0`.

The following offsets changed and were updated from DZI1 kallsyms/raw Image data:

| Symbol/data | DZF2 | DZI1 |
| --- | ---: | ---: |
| `ashmem_ioctl` | `0x00d3a314` | `0x00d3a67c` |
| `compat_ashmem_ioctl` | `0x00d3ac4c` | `0x00d3afb4` |
| `ashmem_mmap` | `0x00d3aca4` | `0x00d3b00c` |
| `ashmem_open` | `0x00d3aed0` | `0x00d3b238` |
| `ashmem_release` | `0x00d3af58` | `0x00d3b2c0` |
| `ashmem_show_fdinfo` | `0x00d3b078` | `0x00d3b3e0` |
| `configfs_read_iter` | `0x004712a4` | `0x004712dc` |
| `configfs_bin_write_iter` | `0x004717d4` | `0x0047180c` |
| `kmalloc_caches` | `0x0176c6f8` | `0x0176c958` |
| `ashmem_misc.fops` | `0x023bb5b0` | `0x023bb600` |
| `nfnetlink_log` string | `0x016a622a` | `0x016a6345` |

The `random_table` boot ID pointer remains at `0x023762f0` and points to `sysctl_bootid` at `0x026046e8`. Other target constants retained from DZF2 were checked against the extracted symbol table. The P0 32-by-8 fingerprint table was regenerated from the DZI1 raw Image at probe `0x1f0000`.

## Build and validation status

The app exploit payload was compiled with Android NDK r28.2, API 35, the repository's S928 stable-race flags, and the DZI1 target header. It is padded to the repository's fixed S928 stable payload size of 104,128 bytes (SHA-256 `8e6fe4235ff4d975fdbbf28f985cfd037a9defa0babbe2f7eb7663bec64f5e78`). See `artifacts/e3q-S928BXXS6DZI1/cve-2026-43499-app.so` and `src/targets/e3q-S928BXXS6DZI1/`.

The firmware-derived app profile and KernelSU-Next 3.4.0 pair were built for the exact DZI1 release by GitHub Actions run [#16](https://github.com/ProofPage/Root-My-Galaxy-Payloads/actions/runs/37183880240). The module build verified exact-release vermagic and the pair check verified the daemon/module version agreement. The run warned that no device-tested module was available for import comparison. This profile remains **not device-tested**; its feed display is marked `(test)`. Verify it on an SM-S928B running this exact release before treating it as a confirmed working payload.
