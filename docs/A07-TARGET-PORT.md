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

The build dispatch also takes `ddk_release` (default `20260828`), the date suffix of the
`ghcr.io/ylarod/ddk-min:<kmi>-<release>` image used for all three pairs. Nothing in this repository
can prove that tag exists, so it is not hardcoded: `ksu-build.yml`'s `ddk-image` job queries the
`ghcr.io` manifest first, and on a non-200 it fails the run and lists the KMI families actually
published for that date. If it fails, re-dispatch with a published date rather than editing the
three call sites.

The manifest's artifact URLs use the source repository branch because the app pins allowed raw
GitHub URLs to the commit from which it read `targets-v3.json`. The build workflow commits the
payload, target header, KSU modules/daemons, and feed to the branch on which it was dispatched, then
also publishes the binaries and three manager APKs as release assets. `managerPackage` is descriptive
metadata; the current app selects the package from `flavor` and has these same package mappings.

Neither workflow writes to a device or to device partitions.
