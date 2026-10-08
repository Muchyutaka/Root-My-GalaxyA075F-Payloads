# SM-A075F target port (kernel 6.12.38)

The A07 profile is intentionally fail-closed. `SM-A175F`/A17 offsets are not accepted as defaults.
`extract-a07-target.yml` downloads the `a07-firmware-v1` release assets, extracts the embedded
the unique `Kernel.tar.gz` (if present) from `SM-A075F_16_Opensource.zip`, prefers the supplied `kernel.elf`, and only
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

After a successful extraction run, the extraction workflow calls `build-a07-payload.yml` as
a reusable workflow with the verified artifact run ID (no Actions API dispatch is needed). The
build reuses the repo's target-specific KernelSU pair workflow for KernelSU v3.3.0, KernelSU-Next
v3.4.0, and ReSukiSU v4.2.0-rc3, builds the requested stable `.so` with JBR 21, SDK 37, NDK r28c,
and CMake 3.22.1, and checks the manager APK package IDs. This review build **does not
publish** artifacts or feed entries to the repository.

The candidate manifest's artifact URLs use the source repository branch because the app pins allowed
raw GitHub URLs to the commit from which it read `targets-v3.json`. The build workflow generates a
**draft** feed only in the Actions workspace, after validating the `.so` and KernelSU pairs, and
uploads it with the review bundle. It does not commit the feed, push binaries, or create a release.
The app selects the manager package from `flavor`; `managerPackage` is not a v3 parser field.
The draft is not usable as a remote source until separately reviewed and published with the
matching binaries in the same commit. The checked-in feed deliberately has no A07 entry.

Neither workflow writes to a device or to device partitions.

## Current verification status (2026-10-08)

**NOT DEVICE-TESTED.** This repository does not currently contain an A07 `target.h`, an A07
`.so`, an A07 KernelSU pair, or A07 entries in `support/targets-v3.json`. There is **no A07
payload to run or select in the app yet**. A successful compiler exit alone would not establish
that a locked-bootloader phone can load a late-load module or that the exploit works on CZF2.
Never fill missing offsets from another model, or publish placeholder hashes/entries.

The exact 13 input assets are under the GitHub release `a07-firmware-v1`. Extraction downloads
`boot.img`, `vendor_boot.img`, `dtbo.img`, `preloader.img`, `lk-verified.img`, `param.bin`,
`up_param.bin`, `kernel.raw`, `kernel.elf`, `ramdisk.cpio`, `kallsyms.txt`, `vmlinux.btf`, and
`SM-A075F_16_Opensource.zip`, checking **every file** against the release API's SHA-256 digest
and size, and re-reading release metadata after download to detect changed assets. The verifier
writes only `input-hashes.json` into the sanitized workflow artifact. The extractor consumes
`kernel.elf`, `kernel.raw` (fallback only), `kallsyms.txt`, `vmlinux.btf` and the source zip. The AP/BL
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

### P0 fingerprint table (generated, verified)

`src/targets/a07-SM-A075F/p0_fingerprint.h` was generated in CI (run `37781227490`, commit
`3e8921f`) by `tools/generate_p0_fingerprint.pl` at probe offset `0x1f0000` from the release asset
`kernel.raw`, after that asset passed SHA-256 verification against the `a07-firmware-v1` release and
proved it is a raw arm64 Image (`ARM\x64` magic at `0x38`, `image_size=0x3250000`, `flags=0xa`).

- 32 slide rows (`0x000000`..`0x1f0000`, step `0x10000`), 8 qwords each, read at
  `Image[0x1f0000 - slide + {0x000,0x200,...,0xe00}]`.
- File SHA-256 `37713e9b894e5c6a9e2e679ee230da19904827b40b169b19cbd17e7aa02595af`, 7476 bytes. The
  header travelled out of CI as base64 chunks with that digest and was rebuilt locally; the rebuilt
  file reproduces the digest, so it is the same bytes CI generated.
- Every row carries distinct AArch64 code words (the highest slide reads the Image header, whose
  first word contains the `MZ` PE magic), so the rows are distinguishable by `p0_fingerprint_score`.

This table is target data only. It does not make the payload buildable: `target.h` still cannot be
generated, and the reason is recorded in the next section.

## Why the payload cannot be built for A07 (measured, not assumed)

A07's kernel does not contain the ashmem driver the payload's write primitive depends on.
`arch/arm64/configs/gki_defconfig` sets `CONFIG_ASHMEM=y` and `CONFIG_ASHMEM_RUST=y`, and
`drivers/staging/android/Kconfig` defines `ASHMEM_C` as `def_bool ASHMEM && !ASHMEM_RUST`, so the C
driver (`drivers/staging/android/ashmem.c`, the `/dev/ashmem` misc device whose
`struct ashmem_area` holds `char name[ASHMEM_NAME_LEN]` inline) is not compiled in. The ELF agrees:
no `ashmem_fops`, `ashmem_misc_fops`, `ashmem_ioctl`, `ashmem_open`, `ashmem_release`, `ashmem_mmap`
or `ashmem_show_fdinfo`; only `ashmem_memfd_ioctl`, `ashmem_area_name`, `ashmem_area_size` and
`ashmem_area_vmfile`.

`drivers/staging/android/ashmem_rust.rs` (quoted from CI run `37743414981`) shows what replaces it:

- `struct Ashmem { inner: Mutex<AshmemInner> }`, `struct AshmemInner { size, prot_mask,
  name: Option<KVec<u8>>, file: Option<ShmemFile>, area: Area }`, and `file->private_data` holds a
  `Pin<KBox<Ashmem>>` (`get_ashmem_area()` borrows that `ForeignOwnable`).
- `fn set_name` copies the user string into a **fresh heap vector sized to the string**
  (`KVec::with_capacity(name.len(), GFP_KERNEL)`) and stores it in `asma.name`; it returns `EINVAL`
  once `asma.file.is_some()`.

So the name is not a 256-byte array at a fixed offset from `file->private_data`. The payload's
primitive - `ioctl(fd, ASHMEM_SET_NAME, blob)` writing 255 controlled bytes at exactly
`private_data + ASHMEM_NAME_PREFIX_LEN` so a fake `configfs_buffer` can be overlaid on the object
that `configfs_read_iter`/`configfs_bin_write_iter` will then use - has no equivalent on this
kernel, and `vmlinux.btf` contains no ashmem type names at all, so no offset for the Rust layout is
measurable from the release inputs either.

That is a missing mechanism, not a missing number: no `target.h` value can supply it. Porting A07
therefore requires a different arbitrary-write primitive, which is exploit design work and cannot be
invented from these inputs without guessing - which this repository forbids.

## What CI measured (extraction run 37710697461, commit 0e8df9a)

The push-triggered extraction run executed on a GitHub-hosted runner. Stages 1-3 **pass**; stage 4
is **partial**; stages 5-10 were correctly **not reached**. Nothing below was copied from another
model, and no value was accepted without a cross-check.

| Stage | Result | Evidence |
| --- | --- | --- |
| 1. Release assets downloaded | **PASS** | all 13 assets of `a07-firmware-v1` via `gh release download` using the run's own `GITHUB_TOKEN` |
| 2. SHA-256 verified | **PASS** | every file's size and `sha256:` digest from the Releases API; release metadata re-read after download and compared, so a swapped asset fails |
| 3. Kernel ELF/BTF parsed | **PASS** | `UTS_RELEASE` = `6.12.38-android16-5-abA075FXXS5CZF2-4k` (matches firmware `A075FXXS5CZF2`, kernel `6.12.38`, 4K pages); `task_struct.mm` = **1672 (0x688)** from A07's own `vmlinux.btf`, cross-checked against Samsung's `include/linux/sched.h` inside `SM-A075F_16_Opensource.zip` |
| 4. Offsets extracted | **PARTIAL** | 10/19 required symbol offsets cross-verified (`nm` == `readelf`, name present in `kallsyms.txt`); 5 waiter offsets derived from nested BTF with spacing + leaf-type checks; 9 symbols and 3 BTF members do not exist in this kernel |
| 5. `target.h` generated | **NOT GENERATED** | fail-closed: 38 requirements unmet (9 symbols, 24 profile values, 5 structural) |
| 6-10. `.so`, pairs, feed, app source | **NOT REACHED** | the build job is gated on a ready extraction; `support/targets-v3.json` still has no SM-A075F entry |

Cross-verified image-relative symbol offsets (text base subtracted): `INIT_TASK_OFF=0x250cf40`,
`ROOT_TASK_GROUP_OFF=0x2dcfd80`, `KMALLOC_CACHES_OFF=0x18934c0`, `ANON_PIPE_BUF_OPS_OFF=0x126efc8`,
`NOOP_LLSEEK_OFF=0x4414d8`, `COPY_SPLICE_READ_OFF=0x4943f0`, `CONFIGFS_READ_ITER_OFF=0x5184bc`,
`CONFIGFS_BIN_WRITE_ITER_OFF=0x518a68`, `CALL_USERMODEHELPER_EXEC_WORK_OFF=0xf8e68`,
`SYSTEM_UNBOUND_WQ_OFF=0x1893250`.

Derived from A07's BTF by walking embedded members, each with an independent check
(`pi_tree - tree == sizeof(struct rt_waiter_node) == 0x28`, and the leaf of `pi_tree.entry`
asserted to embed `struct rb_node`): `FAKE_WAITER_TREE_PRIO_OFF=0x18`,
`FAKE_WAITER_TREE_DEADLINE_OFF=0x20`, `FAKE_WAITER_PI_TREE_ENTRY_OFF=0x28`,
`FAKE_WAITER_PI_TREE_PRIO_OFF=0x40`, `FAKE_WAITER_PI_TREE_DEADLINE_OFF=0x48`. A07's
`rt_mutex_waiter` members are `tree`, `pi_tree`, `task`, `lock`, `wake_state`, `ww_ctx`;
`struct rt_waiter_node` is `entry`, `prio`, `deadline`.

Also measured and reported but **not** accepted: `struct slab` in this kernel does not embed
`struct page __page` (its members are `__page_flags`, `__page_refcount`, `__page_type`,
`slab_cache@0x8`, `freelist`, `obj_exts`, ...), so the page-relative equivalence the payload
assumes for `STRUCT_SLAB_CACHE_OFF` is unproven and stays a reported gap rather than a value.

### The three blockers that remain (each needs evidence or a source port, never a guess)

1. **Nine required symbols do not exist in this kernel.** `selinux_enforcing` is present only as
   `selinux_enforcing_boot`; the eight `ashmem_*` symbols are gone (A07's 6.12 kernel exposes
   `ashmem_memfd_ioctl`, i.e. the memfd shim). The extractor refuses closest-name substitution, so
   `SELINUX_ENFORCING_OFF` and the `ASHMEM_*_OFF` set cannot be filled for A07 as the payload is
   written today. Porting the exploit to 6.12's SELinux state and memfd-based ashmem is a **source
   change**, not a header value.
2. **`rt_mutex_waiter` has a third layout.** `src/common.h` offers only `LEGACY_RT_MUTEX_WAITER`
   (flat `pi_tree_entry`/`pi_tree_prio`/`pi_tree_deadline`) and `COMPACT_RT_MUTEX_WAITER`
   (`tree_entry`/`prio`/`deadline`). A07 embeds `tree`/`pi_tree` node structs, so neither flag
   describes it. Deciding which flag's code paths match the nested layout - or adding a third -
   requires reading how `src/util.c` and `src/slide_app.c` write the rb_node and prio/deadline
   fields. `pool_workqueue.max_active` is the same class of problem: it moved to
   `workqueue_struct.max_active` (measured at `0xa4`), while `src/root.c:355` reads
   `pwq + PWQ_MAX_ACTIVE_OFF`; that is a source port.
3. **24 evidence-bearing profile values are absent** (`src/targets/a07-SM-A075F/target-values.json`
   does not exist). They include the P0/direct-map physical constants, `SKB_DATA_DELTA`, the pselect
   word shift, the tracefs event ID and worker caller offset, the allocator/runtime choices, and the
   four text-relative slide addresses (`SLIDE_NFULNL_LOGGER_NAME_OFF`,
   `SLIDE_NFULNL_LOGGER_OBJECT_OFF`, `SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF`,
   `SLIDE_SYSCTL_BOOTID_OFF`). Those four are addresses of code/data **inside the A07 image** and
   require disassembling A07's own `kernel.elf`; no other device's values transfer.

Unrelated `nm`/`readelf` address disagreements (`add`, `gic_of_init`, `phy_exit`, `phy_init`,
`poly1305_blocks`, `shrinker_list`, `user_destroy`, `user_read`) are reported and never used.

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


### CI authorization and invocation

The repository's `a07-firmware-v1` release and all 13 `digest: sha256:…` values are readable via
the GitHub API. `extract-a07-target.yml` now runs on a push to this session's branch when its
workflow, verifier, extractor or evidence profile changes; it also supports manual execution in
the GitHub Actions web UI. A push does not call the `workflow_dispatch` REST endpoint. The run
uses its own `${{ github.token }}` with `contents: read` to enumerate/download same-repository
release assets and `actions: read` for the later review build's artifact retrieval. `gh release
download` follows GitHub's asset redirect **on a GitHub-hosted runner**. The Arena sandbox's
network does not allow that redirected host, so a local `gh release download` cannot substitute
for an Actions run. If the hosted runner also cannot follow the redirect, the download step
fails without claiming any input SHA-256 succeeded.

**Resolved by not needing that permission:** extraction now starts from a push to this branch, and
runs `37707541106`, `37708402625`, `37708933950`, `37709369351`, `37710215624`, `37710306116`, and
`37710697461` all executed on GitHub-hosted runners. The earlier API request to dispatch a workflow
returned HTTP 403 with
`X-Accepted-Github-Permissions: actions=write`: the **Arena GitHub integration** lacks the
`Actions: write` repository permission needed by `POST /actions/workflows/{id}/dispatches`.
Adding `permissions: actions: write` to workflow YAML does **not** change that external
integration. Reading the repository's Actions settings also returned HTTP 403 with
`X-Accepted-Github-Permissions: administration=read`; therefore the repository's default
`GITHUB_TOKEN` setting cannot be confirmed from this sandbox. Repository Settings → Actions →
General must allow GitHub Actions to run and permit the actions used by this workflow. If
manual API dispatch is needed, reconnect/update the Arena GitHub app installation with
**Actions: write** on this repository; changing `GITHUB_TOKEN` YAML alone cannot repair that
403. GitHub's web Actions tab can dispatch with the owner's own permissions instead.

**No automatic publication:** the old shared `ksu-build.yml` declares `contents: write`
even when its caller sets `publish: false`. GitHub validates a nested reusable workflow's
requested permissions *before* executing any jobs; the first push-triggered extraction run
failed at startup when the caller allowed only `contents: read`. To satisfy that existing
contract without changing unrelated KSU publishing, the **parent and pair-build jobs** now
allow `contents: write`; the firmware extraction job and the review build's preparation and
candidate-bundle jobs explicitly use `contents: read`. All A07 KSU calls pass
`publish: false`, and the A07 build workflow has **no `git push` or release publishing
step**. This write scope is an internal reusable-workflow requirement; it does not grant
Arena's external integration the missing `Actions: write` needed for API dispatch.

The optional `workflow_dispatch` requires an actual successful extraction run ID; extraction
can call the review build directly on success. Any generated `target.h`, `.so`, and draft
`targets-v3.json` are review artifacts only. Until the verified profile and all three pairs
exist and a separate reviewed publication occurs, the checked-in feed stays without an A07
entry. Temporary root on SM-A075F/A075FXXS5CZF2 with a locked bootloader remains
**NOT DEVICE-TESTED**.
