# SM-A075F target port (kernel 6.12.38)

The A07 profile is intentionally fail-closed. `SM-A175F`/A17 offsets are not accepted as defaults.
`extract-a07-target.yml` downloads the `a07-firmware-v1` release assets, extracts the embedded
`Kernel/Kernel.tar.gz` from `SM-A075F_16_Opensource.zip`, prefers the supplied `kernel.elf`, and only
runs `vmlinux-to-elf` on `kernel.raw` if the ELF is incomplete. It audits ELF symbols with `nm` and
`readelf`, cross-checks names against `kallsyms.txt`, and runs `pahole` against the supplied BTF.

## Target profile inputs

The workflow writes a sanitized report and uploads it as `a07-target-<run-id>`. It does not upload
firmware images, the source archive, or the full kallsyms file. A production `target.h` is emitted
only when the exact kernel release, required symbol offsets, BTF structure layouts, source check, and
all evidence-bearing profile values are present.

To supply values that cannot be proven from ELF/BTF/source alone, copy
`src/targets/a07-SM-A075F/target-values.template.json` to
`src/targets/a07-SM-A075F/target-values.json`. Keep `model` and `kernelVersion` unchanged. Add each
required value under `macros` and a concise, non-personal-data evidence note for the same key under
`evidence`. The extractor currently requires evidence for:

- Physical/kernel memory map: `P0_PAGE_OFFSET`, `P0_PHYS_OFFSET`, `P0_KERNEL_PHYS_LOAD`,
  `DIRECT_MAP_BASE`, `DIRECT_MAP_END`, and `VMEMMAP_START`.
- A07-specific exploit geometry: `SKB_DATA_DELTA`, `SLIDE_PSELECT_WORD_SHIFT`,
  `SLIDE_TRACEFS_EVENT_ID`, and `SLIDE_TRACEFS_WORKER_CALLER_OFF`.
- The target's slide-chain data locations: `SLIDE_NFULNL_LOGGER_NAME_OFF`,
  `SLIDE_NFULNL_LOGGER_OBJECT_OFF`, `SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF`, and
  `SLIDE_SYSCTL_BOOTID_OFF`.
- Allocator/runtime layout and choices: `KMALLOC_CACHE_TYPES`, `KMALLOC_CGROUP_TYPE`,
  `SLIDE_FAKE_WAITER_PRIO`, `SLIDE_WAITER_WAKE_STATE`, `LEGACY_RT_MUTEX_WAITER`,
  `COMPACT_RT_MUTEX_WAITER`, `SLIDE_LOCK_OWNER_VALUE`, `SLIDE_USE_FAKE_TASK`,
  `SLIDE_RB_PARENT_TYPE_RESTORE`, and `SLIDE_P0_OFFSET_CANDIDATES`. Set exactly one of the two
  waiter-layout flags to `1`, based on A07's `rt_mutex_waiter` BTF/source layout.

Use C integer literals for numeric values (for example `0x1234ULL`); the slide-candidate macro may
be a single-line, comma-separated list of integer literals. Every value needs a brief explanation of
its A07 evidence. Do not use the A17 reference values, fill fields from a nearest-name match, or use
a generic `common.h` fallback as evidence. The script reports the exact missing ELF/BTF member and
its closest names when a required symbol or structure field is absent. In particular,
`task_struct.mm` must be present in both the exact `vmlinux.btf`/`pahole` layout and Samsung's
`include/linux/sched.h` source.

After a successful extraction run, dispatch `build-a07-payload.yml` with that extraction run ID. The
build reuses the repo's target-specific KernelSU pair workflow for KernelSU v3.3.0, KernelSU-Next
v3.4.0, and ReSukiSU v4.2.0-rc3, builds the requested stable `.so` with JBR 21, SDK 37, NDK r28c,
and CMake 3.22.1, and checks the manager APK package IDs before release.

The manifest's artifact URLs use the source repository branch because the app pins allowed raw
GitHub URLs to the commit from which it read `targets-v3.json`. The build workflow commits the
payload, target header, KSU modules/daemons, and feed to the branch on which it was dispatched, then
also publishes the binaries and three manager APKs as release assets. `managerPackage` is descriptive
metadata; the current app selects the package from `flavor` and has these same package mappings.

Neither workflow writes to a device or to device partitions.

## Current verification status (2026-10-08)

**NOT DEVICE-TESTED.** This repository does not currently contain an A07 `target.h`, an A07
`.so`, an A07 KernelSU pair, or A07 entries in `support/targets-v3.json`. There is **no A07
payload to run or select in the app yet**. A successful compiler exit alone would not establish
that a locked-bootloader phone can load a late-load module or that the exploit works on CZF2.
Never fill missing offsets from another model, or publish placeholder hashes/entries.

The exact input assets are under the GitHub release `a07-firmware-v1`. Extraction consumes
`kernel.elf`, `kernel.raw` (fallback only), `kallsyms.txt`, `vmlinux.btf` and
`SM-A075F_16_Opensource.zip`, checking each against the release API's SHA-256 digest. The AP/BL
images and ramdisk on that release are *not* flashed or modified by either workflow. They are
not currently parsed into exploit geometry; their presence alone cannot verify the physical map,
tracefs event ID, skb delta, or runtime choices listed above. The evidence-bearing profile's
`kernelRelease` must match the ELF UTS_RELEASE exactly. Even when `target.h` is generated, the
remaining device/runtime assumptions need independent validation on the **exact** build.

The selected upstream release tags in the pair workflow are
[KernelSU v3.3.0](https://github.com/tiann/KernelSU/releases/tag/v3.3.0),
[KernelSU-Next v3.4.0](https://github.com/KernelSU-Next/KernelSU-Next/releases/tag/v3.4.0), and
[ReSukiSU v4.2.0-rc3](https://github.com/ReSukiSU/ReSukiSU/releases/tag/v4.2.0-rc3).
These tags and the named manager APK assets exist upstream. The versions become
`kernelsu.version` **only after** matching target-specific daemon/module builds exist.

### How the app reads a completed source

Source of truth: `rushiranpise/Root-My-Galaxy-Next`'s `PayloadSources.kt`,
`PayloadRepository.kt`, `SupportManifest.kt`, and `LocalPayload.kt`. In Settings → Payload
Management → Payload Sources, the app takes separate **repository** and **branch** fields,
not a release/download URL. After publication, enter repository
`Muchyutaka/Root-My-GalaxyA075F-Payloads` and branch
`arena/15acdeec-root-my-galaxya075f-payloads`. It reads `support/targets-v3.json` at the
resolved commit. The feed must point to **raw GitHub branch URLs in that same repository** for
both `exploit` (`.so`) and `kernelsu` (daemon); the app rewrites those URLs to the resolved commit
before downloading. A GitHub Release URL cannot be used as the artifact URL in this app.

The app's v3 parser reads `schemaVersion`, `payloads`, `payloadId`, `displayName`, `models`,
`kernelVersions`, `flavor`, `exploit` (`url`, `size`, `sha256`), and `kernelsu` (`url`, `size`,
`sha256`, `version`). It does **not** read `managerPackage` or `kernelModule`; these are not
emitted in newly generated A07 entries. Each of the three flavors will get a separate row.
The module is embedded in the matching daemon by the pair build; the module file is separately
retained for offline verification. The app checks the hashes on downloaded artifacts.

For a local `.so` test, Settings → Payload Management → Local Payload accepts an ELF file named
with `.so` (up to 16 MiB). Its `LocalPayload` implementation copies the exploit library into
app storage and substitutes it for the downloaded exploit in a run. **It does not import a
KernelSU daemon/module and does not make an unsupported model appear in the feed.** A matching
source/daemon must still be selected. Import is useful only after a real A07 `.so` exists; it
cannot compensate for unverified offsets. Neither workflow writes any device partition.
