# A075FXXS5BZD2 derivation report

kernel release: **6.12.23-android16-5-abA075FXXS5BZD2-4k**
symbols: 130464

| check | result | detail |
| --- | --- | --- |
| kernel.banner | PASS | 6.12.23-android16-5-abA075FXXS5BZD2-4k |
| kernel.release-match | PASS | banner '6.12.23-android16-5-abA075FXXS5BZD2-4k' vs expected '6.12.23-android16-5-abA075FXXS5BZD2-4k' |
| elf.base | PASS | first LOAD VMA 0xffffffc080000000 vs KIMAGE_TEXT_BASE 0xffffffc080000000 |
| sym.CALL_USERMODEHELPER_EXEC_WORK_OFF | PASS | call_usermodehelper_exec_work 0xf758c vs 0xf758c |
| sym.NOOP_LLSEEK_OFF | PASS | noop_llseek 0x43a610 vs 0x43a610 |
| sym.COPY_SPLICE_READ_OFF | PASS | copy_splice_read 0x48d0ac vs 0x48d0ac |
| sym.CONFIGFS_READ_ITER_OFF | PASS | configfs_read_iter 0x510c04 vs 0x510c04 |
| sym.CONFIGFS_BIN_WRITE_ITER_OFF | PASS | configfs_bin_write_iter 0x5111b0 vs 0x5111b0 |
| sym.ANON_PIPE_BUF_OPS_OFF | PASS | anon_pipe_buf_ops 0x124ee88 vs 0x124ee88 |
| sym.KMALLOC_CACHES_OFF | PASS | kmalloc_caches 0x186b4c0 vs 0x186b4c0 |
| sym.SYSTEM_UNBOUND_WQ_OFF | PASS | system_unbound_wq 0x186b250 vs 0x186b250 |
| sym.SLIDE_NFULNL_LOGGER_OBJECT_OFF | PASS | nfulnl_logger 0x24c2198 vs 0x24c2198 |
| sym.INIT_TASK_OFF | PASS | init_task 0x24ccf00 vs 0x24ccf00 |
| sym.ROOT_TASK_GROUP_OFF | PASS | root_task_group 0x26fdd80 vs 0x26fdd80 |
| sym.SELINUX_ENFORCING_OFF | PASS | selinux_state 0x274a820 vs 0x274a820 |
| sym.SYSCTL_BOOTID_OFF | PASS | sysctl_bootid 0x27ec630 vs 0x27ec630 |
| btf.extract | PASS | 2 candidate blob(s) [0x1990120-0x20333c9, 0x19c3bd4-0x19e2837], chose Image[0x1990120, 0x20333c9), 165682 types, payload(float,decltag)=(0, 8), 1-based type ids (encoder omits UNKNOWN type 0; synthetic UNKNOWN prepended, refs index directly) |
| btf.SIZEOF_FILE_OPERATIONS | PASS | file_operations.size 0x108 vs 0x108 |
| btf.FOPS_LLSEEK_OFF | PASS | file_operations.llseek 0x10 vs 0x10 |
| btf.FOPS_READ_OFF | PASS | file_operations.read 0x18 vs 0x18 |
| btf.FOPS_WRITE_OFF | PASS | file_operations.write 0x20 vs 0x20 |
| btf.FOPS_READ_ITER_OFF | PASS | file_operations.read_iter 0x28 vs 0x28 |
| btf.FOPS_WRITE_ITER_OFF | PASS | file_operations.write_iter 0x30 vs 0x30 |
| btf.FOPS_UNLOCKED_IOCTL_OFF | PASS | file_operations.unlocked_ioctl 0x50 vs 0x50 |
| btf.FOPS_COMPAT_IOCTL_OFF | PASS | file_operations.compat_ioctl 0x58 vs 0x58 |
| btf.FOPS_MMAP_OFF | PASS | file_operations.mmap 0x60 vs 0x60 |
| btf.FOPS_OPEN_OFF | PASS | file_operations.open 0x68 vs 0x68 |
| btf.FOPS_RELEASE_OFF | PASS | file_operations.release 0x78 vs 0x78 |
| btf.FOPS_SPLICE_READ_OFF | PASS | file_operations.splice_read 0xb8 vs 0xb8 |
| btf.FOPS_SHOW_FDINFO_OFF | PASS | file_operations.show_fdinfo 0xd8 vs 0xd8 |
| btf.TASK_USAGE_OFF | PASS | task_struct.usage 0x40 vs 0x40 |
| btf.TASK_PRIO_OFF | PASS | task_struct.prio 0x94 vs 0x94 |
| btf.TASK_NORMAL_PRIO_OFF | PASS | task_struct.normal_prio 0x9c vs 0x9c |
| btf.TASK_SCHED_TASK_GROUP_OFF | PASS | task_struct.sched_task_group 0x420 vs 0x420 |
| btf.TASK_PI_LOCK_OFF | PASS | task_struct.pi_lock 0x9ec vs 0x9ec |
| btf.TASK_PI_WAITERS_OFF | PASS | task_struct.pi_waiters 0xa00 vs 0xa00 |
| btf.TASK_PI_TOP_TASK_OFF | PASS | task_struct.pi_top_task 0xa10 vs 0xa10 |
| btf.TASK_PI_BLOCKED_ON_OFF | PASS | task_struct.pi_blocked_on 0xa18 vs 0xa18 |
| btf.PAGE_COMPOUND_HEAD_OFF | PASS | page.compound_head 0x8 vs 0x8 |
| btf.PAGE_PAGE_TYPE_OFF | PASS | page.page_type 0x30 vs 0x30 |
| btf.PWQ_NR_ACTIVE_OFF | PASS | pool_workqueue.nr_active 0x60 vs 0x60 |
| btf.WQ_DFL_PWQ_OFF | PASS | workqueue_struct.dfl_pwq 0xc0 vs 0xc0 |
| btf.WORK_FUNC_OFF | PASS | work_struct.func 0x18 vs 0x18 |
| btf.FAKE_WAITER_PI_TREE_ENTRY_OFF | PASS | rt_mutex_waiter.pi_tree 0x28 vs 0x28 |
| btf.FAKE_WAITER_TASK_OFF | PASS | rt_mutex_waiter.task 0x50 vs 0x50 |
| btf.FAKE_WAITER_LOCK_OFF | PASS | rt_mutex_waiter.lock 0x58 vs 0x58 |
| btf.FAKE_WAITER_WAKE_STATE_OFF | PASS | rt_mutex_waiter.wake_state 0x60 vs 0x60 |
| btf.FAKE_WAITER_WW_CTX_OFF | PASS | rt_mutex_waiter.ww_ctx 0x68 vs 0x68 |
| waiter.FAKE_WAITER_TREE_DEADLINE_OFF | PASS | 0x20 in [0x0,0x28) |
| waiter.FAKE_WAITER_PI_TREE_DEADLINE_OFF | PASS | 0x48 in [0x28,0x50) |
| slide.worker_caller | PASS | 1 'bl schedule' in worker_thread body [0x101e4c, 0x102234), at +[0xa8] (last +0xa8), return PC 0x101ef8 vs 0x101ef8 |
| slide.event_id | PASS | index 90 + base 20 = 110 vs 110, sched_waking index 74 |
| slide.pselect_shift | PASS | 0x2 vs 6.12 GKI cross-ref 2 |
| data.nfulnl_logger | PASS | name qword -> 0x17e8698 ("nfnetlink_log") vs 0x17e8698 |
| data.random_table_boot_id | PASS | entry 0x25eafd0, .data slot 0x25eafd8 -> 0x27ec630 (sysctl_bootid 0x27ec630), ctl_table size 0x38 |
| ashmem.fops_table | PASS | fops @0x24d2110 (6.12 layout): 6/6 slots match |
| config.ikconfig | PASS | DEGRADED: no embedded ikconfig in the Image (probes {'CONFIG_IKCONFIG=y': 0, 'CONFIG_IKCONFIG': 0, 'hdr DO NOT EDIT': 0, 'banner 6.12.23': 0}) - config cannot be verified against the running kernel; committed config is from the official GKI package (banner and source checks still apply) |
| p0.fingerprint | PASS | 32 rows / 256 qwords at probe 0x1f0000, readback ok, header matches |
| src.pool_workqueue_max_active | PASS | max_active presence in the 6.12 pool_workqueue source definition |

## recovered values

- `kernel_release` = 6.12.23-android16-5-abA075FXXS5BZD2-4k
- `kimage_text_base` = 0xffffffc080000000
- `symbol_count` = 130464
- `CALL_USERMODEHELPER_EXEC_WORK_OFF` = 0xf758c
- `NOOP_LLSEEK_OFF` = 0x43a610
- `COPY_SPLICE_READ_OFF` = 0x48d0ac
- `CONFIGFS_READ_ITER_OFF` = 0x510c04
- `CONFIGFS_BIN_WRITE_ITER_OFF` = 0x5111b0
- `ANON_PIPE_BUF_OPS_OFF` = 0x124ee88
- `KMALLOC_CACHES_OFF` = 0x186b4c0
- `SYSTEM_UNBOUND_WQ_OFF` = 0x186b250
- `SLIDE_NFULNL_LOGGER_OBJECT_OFF` = 0x24c2198
- `INIT_TASK_OFF` = 0x24ccf00
- `ROOT_TASK_GROUP_OFF` = 0x26fdd80
- `SELINUX_ENFORCING_OFF` = 0x274a820
- `SYSCTL_BOOTID_OFF` = 0x27ec630
- `btf.kind_hist` = UNKN=1, INT=30, PTR=28235, ARRAY=3881, STRUCT=12287, UNION=2358, ENUM=2643, FWD=73, TYPEDEF=2669, VOLATILE=439, CONST=3340, RESTRICT=7, FUNC=62265, FUNC_PROTO=41739, VAR=4730, DATASEC=1, FLOAT=1, TYPE_TAG=968, ENUM64=15
- `btf.first_types` = 1:INT:DW_ATE_signed_32, 2:INT:DW_ATE_signed_64, 3:INT:DW_ATE_unsigned_64, 4:INT:DW_ATE_unsigned_32, 5:STRUCT:tracepoint, 6:PTR:, 7:CONST:, 8:INT:char, 9:UNION:, 10:STRUCT:static_key, 11:TYPEDEF:atomic_t, 12:STRUCT:, 13:INT:int, 14:INT:unsigned long, 15:PTR:, 16:STRUCT:jump_entry, 17:TYPEDEF:s32, 18:TYPEDEF:__s32, 19:INT:long, 20:PTR:, 21:PTR:, 22:STRUCT:static_call_key, 23:PTR:, 24:PTR:, 25:FUNC_PROTO:, 26:PTR:, 27:FUNC_PROTO:, 28:TYPE_TAG:rcu, 29:PTR:, 30:STRUCT:tracepoint_func
- `btf.probe.file_operations` = exact=2 at [254, 30399]; substring=['254:STRUCT:file_operations', '30399:STRUCT:file_operations', '49155:STRUCT:media_file_operations', '49208:STRUCT:v4l2_file_operations']
- `btf.probe.task_struct` = exact=2 at [429, 30353]; substring=['429:STRUCT:task_struct', '8148:VAR:alloc_task_struct_node._alloc_tag_cntr', '15285:STRUCT:task_struct__safe_rcu', '28522:STRUCT:task_struct_offsets', '28535:ENUM:kzt_task_struct_interests', '30353:STRUCT:task_struct', '81991:FUNC:__probestub_android_vh_dup_task_struct', '83700:FUNC:__put_task_struct']
- `btf.probe.page` = exact=2 at [840, 30331]; substring=['679:STRUCT:page_counter', '752:STRUCT:per_cpu_pages', '840:STRUCT:page', '845:STRUCT:dev_pagemap', '853:STRUCT:dev_pagemap_ops', '1698:STRUCT:page_frag', '2198:STRUCT:wait_page_queue', '4507:ENUM:vvar_pages']
- `btf.probe.pool_workqueue` = exact=1 at [8672]; substring=['8672:STRUCT:pool_workqueue', '8767:ENUM:pool_workqueue_stats']
- `btf.variants.file_operations` = 2
- `SIZEOF_FILE_OPERATIONS` = 0x108
- `FOPS_LLSEEK_OFF` = 0x10
- `FOPS_READ_OFF` = 0x18
- `FOPS_WRITE_OFF` = 0x20
- `FOPS_READ_ITER_OFF` = 0x28
- `FOPS_WRITE_ITER_OFF` = 0x30
- `FOPS_UNLOCKED_IOCTL_OFF` = 0x50
- `FOPS_COMPAT_IOCTL_OFF` = 0x58
- `FOPS_MMAP_OFF` = 0x60
- `FOPS_OPEN_OFF` = 0x68
- `FOPS_RELEASE_OFF` = 0x78
- `FOPS_SPLICE_READ_OFF` = 0xb8
- `FOPS_SHOW_FDINFO_OFF` = 0xd8
- `btf.variants.task_struct` = 2
- `TASK_USAGE_OFF` = 0x40
- `TASK_PRIO_OFF` = 0x94
- `TASK_NORMAL_PRIO_OFF` = 0x9c
- `TASK_SCHED_TASK_GROUP_OFF` = 0x420
- `TASK_PI_LOCK_OFF` = 0x9ec
- `TASK_PI_WAITERS_OFF` = 0xa00
- `TASK_PI_TOP_TASK_OFF` = 0xa10
- `TASK_PI_BLOCKED_ON_OFF` = 0xa18
- `btf.variants.page` = 2
- `PAGE_COMPOUND_HEAD_OFF` = 0x8
- `PAGE_PAGE_TYPE_OFF` = 0x30
- `PWQ_NR_ACTIVE_OFF` = 0x60
- `WQ_DFL_PWQ_OFF` = 0xc0
- `WORK_FUNC_OFF` = 0x18
- `btf.pool_workqueue` = size 0x200: pool=0x0, wq=0x8, work_color=0x10, flush_color=0x14, refcnt=0x18, nr_in_flight=0x1c, plugged=0x5c, nr_active=0x60, inactive_works=0x68, pending_node=0x78, pwqs_node=0x88, mayday_node=0x98, stats=0xa8, release_work=0xe8, rcu=0x110
- `btf.mm_struct` = size 0x4c0: mm_count=0x0, mm_mt=0x40, mmap_base=0x50, mmap_legacy_base=0x58, task_size=0x60, pgd=0x68, membarrier_state=0x70, mm_users=0x74, pgtables_bytes=0x78, map_count=0x80, page_table_lock=0x84, mmap_lock=0x88, mmlist=0xc8, vma_writer_wait=0xd8, mm_lock_seq=0xe0, hiwater_rss=0xe8, hiwater_vm=0xf0, total_vm=0xf8, locked_vm=0x100, pinned_vm=0x108, data_vm=0x110, exec_vm=0x118, stack_vm=0x120, def_flags=0x128, write_protect_seq=0x130, arg_lock=0x134, start_code=0x138, end_code=0x140, start_data=0x148, end_data=0x150, start_brk=0x158, brk=0x160, start_stack=0x168, arg_start=0x170, arg_end=0x178, env_start=0x180, env_end=0x188, saved_auxv=0x190, rss_stat=0x320, binfmt=0x3c0, context=0x3c8, flags=0x3f8, ioctx_lock=0x400, ioctx_table=0x408, owner=0x410, user_ns=0x418, exe_file=0x420, notifier_subscriptions=0x428, tlb_flush_pending=0x430, tlb_flush_batched=0x434, uprobes_state=0x438, async_put_work=0x440, lru_gen=0x460, __kabi_reserved1=0x480, cpu_bitmap=0x4c0
- `btf.sk_buff` = size 0xf8: next=0x0, prev=0x8, dev=0x10, dev_scratch=0x10, rbnode=0x0, list=0x0, ll_node=0x0, sk=0x18, tstamp=0x20, skb_mstamp_ns=0x20, cb=0x28, _skb_refdst=0x58, destructor=0x60, tcp_tsorted_anchor=0x58, _sk_redir=0x58, _nfct=0x68, len=0x70, data_len=0x74, mac_len=0x78, hdr_len=0x7a, queue_mapping=0x7c, __cloned_offset=0x7e, cloned=0x7e, nohdr=bit1009, fclone=bit1010, peeked=bit1012, head_frag=bit1013, pfmemalloc=bit1014, pp_recycle=bit1015, active_extensions=0x7f, __pkt_type_offset=0x80, pkt_type=0x80, ignore_df=bit1027, dst_pending_confirm=bit1028, ip_summed=bit1029, ooo_okay=bit1031, __mono_tc_offset=0x81, tstamp_type=0x81, tc_at_ingress=bit1034, tc_skip_classify=bit1035, remcsum_offload=bit1036, csum_complete_sw=bit1037, csum_level=bit1038, inner_protocol_type=0x82, l4_hash=bit1041, sw_hash=bit1042, wifi_acked_valid=bit1043, wifi_acked=bit1044, no_fcs=bit1045, encapsulation=bit1046, encap_hdr_csum=bit1047, csum_valid=0x83, ndisc_nodetype=bit1049, nf_trace=bit1051, redirected=bit1052, from_ingress=bit1053, nf_skip_egress=bit1054, slow_gro=bit1055, unreadable=0x84, tc_index=0x86, alloc_cpu=0x88, csum=0x8c, csum_start=0x8c, csum_offset=0x8e, priority=0x90, skb_iif=0x94, hash=0x98, vlan_all=0x9c, vlan_proto=0x9c, vlan_tci=0x9e, napi_id=0xa0, sender_cpu=0xa0, secmark=0xa4, mark=0xa8, reserved_tailroom=0xa8, inner_protocol=0xac, inner_ipproto=0xac, inner_transport_header=0xae, inner_network_header=0xb0, inner_mac_header=0xb2, protocol=0xb4, transport_header=0xb6, network_header=0xb8, mac_header=0xba, __kabi_reserved1=0xc0, __kabi_reserved2=0xc8, headers=0x80, tail=0xd0, end=0xd4, head=0xd8, data=0xe0, truesize=0xe8, users=0xec, extensions=0xf0
- `btf.rt_mutex_waiter` = size 0x70: tree=0x0, pi_tree=0x28, task=0x50, lock=0x58, wake_state=0x60, ww_ctx=0x68
- `btf.task_struct` = size 0x1440: thread_info=0x0, __state=0x30, saved_state=0x34, stack=0x38, usage=0x40, flags=0x44, ptrace=0x48, alloc_tag=0x50, on_cpu=0x58, wake_entry=0x60, wakee_flips=0x70, wakee_flip_decay_ts=0x78, last_wakee=0x80, recent_used_cpu=0x88, wake_cpu=0x8c, on_rq=0x90, prio=0x94, static_prio=0x98, normal_prio=0x9c, rt_priority=0xa0, se=0xc0, rt=0x200, dl=0x250, dl_server=0x348, scx=0x350, sched_class=0x418, sched_task_group=0x420, uclamp_req=0x428, uclamp=0x430, stats=0x440, preempt_notifiers=0x540, policy=0x548, max_allowed_capacity=0x550, nr_cpus_allowed=0x558, cpus_ptr=0x560, user_cpus_ptr=0x568, cpus_mask=0x570, migration_pending=0x578, migration_disabled=0x580, migration_flags=0x582, rcu_read_lock_nesting=0x584, rcu_read_unlock_special=0x588, rcu_node_entry=0x590, rcu_blocked_node=0x5a0, rcu_tasks_nvcsw=0x5a8, rcu_tasks_holdout=0x5b0, rcu_tasks_idx=0x5b1, rcu_tasks_idle_cpu=0x5b4, rcu_tasks_holdout_list=0x5b8, rcu_tasks_exit_cpu=0x5c8, rcu_tasks_exit_list=0x5d0, trc_reader_nesting=0x5e0, trc_ipi_to_cpu=0x5e4, trc_reader_special=0x5e8, trc_holdout_list=0x5f0, trc_blkd_node=0x600, trc_blkd_cpu=0x610, sched_info=0x618, tasks=0x638, pushable_tasks=0x648, pushable_dl_tasks=0x670, mm=0x688, active_mm=0x690, faults_disabled_mapping=0x698, exit_state=0x6a0, exit_code=0x6a4, exit_signal=0x6a8, pdeath_signal=0x6ac, jobctl=0x6b0, personality=0x6b8, sched_reset_on_fork=0x6bc, sched_contributes_to_load=bit13793, sched_migrated=bit13794, sched_task_hot=bit13795, sched_remote_wakeup=0x6c0, sched_rt_mutex=bit13825, in_execve=bit13826, in_iowait=bit13827, in_user_fault=bit13828, in_lru_fault=bit13829, no_cgroup_migration=bit13830, frozen=bit13831, use_memdelay=0x6c1, in_memstall=bit13833, in_page_owner=bit13834, in_eventfd=bit13835, in_thrashing=bit13836, atomic_flags=0x6c8, restart_block=0x6d0, pid=0x708, tgid=0x70c, stack_canary=0x710, real_parent=0x718, parent=0x720, children=0x728, sibling=0x738, group_leader=0x748, ptraced=0x750, ptrace_entry=0x760, thread_pid=0x770, pid_links=0x778, thread_node=0x7b8, vfork_done=0x7c8, set_child_tid=0x7d0, clear_child_tid=0x7d8, worker_private=0x7e0, utime=0x7e8, stime=0x7f0, gtime=0x7f8, time_in_state=0x800, max_state=0x808, prev_cputime=0x810, nvcsw=0x828, nivcsw=0x830, start_time=0x838, start_boottime=0x840, min_flt=0x848, maj_flt=0x850, posix_cputimers=0x858, posix_cputimers_work=0x8a8, ptracer_cred=0x8f0, real_cred=0x8f8, cred=0x900, cached_requested_key=0x908, comm=0x910, nameidata=0x920, last_switch_count=0x928, last_switch_time=0x930, fs=0x938, files=0x940, io_uring=0x948, nsproxy=0x950, signal=0x958, sighand=0x960, blocked=0x968, real_blocked=0x970, saved_sigmask=0x978, pending=0x980, sas_ss_sp=0x998, sas_ss_size=0x9a0, sas_ss_flags=0x9a8, task_works=0x9b0, audit_context=0x9b8, loginuid=0x9c0, sessionid=0x9c4, seccomp=0x9c8, syscall_dispatch=0x9d8, parent_exec_id=0x9d8, self_exec_id=0x9e0, alloc_lock=0x9e8, pi_lock=0x9ec, wake_q=0x9f0, wake_q_count=0x9f8, pi_waiters=0xa00, pi_top_task=0xa10, pi_blocked_on=0xa18, blocked_on_state=0xa20, blocked_on=0xa28, blocked_donor=0xa30, migration_node=0xa38, blocked_head=0xa48, blocked_node=0xa58, blocked_activation_node=0xa68, sleeping_owner=0xa78, blocked_lock=0xa80, journal_info=0xa88, bio_list=0xa90, plug=0xa98, reclaim_state=0xaa0, io_context=0xaa8, capture_control=0xab0, ptrace_message=0xab8, last_siginfo=0xac0, ioac=0xac8, psi_flags=0xb08, acct_rss_mem1=0xb10, acct_vm_mem1=0xb18, acct_timexpd=0xb20, mems_allowed=0xb28, mems_allowed_seq=0xb30, cpuset_mem_spread_rotor=0xb34, cgroups=0xb38, cg_list=0xb40, robust_list=0xb50, compat_robust_list=0xb58, pi_state_list=0xb60, pi_state_cache=0xb70, futex_exit_mutex=0xb78, futex_state=0xba8, perf_recursion=0xbac, perf_event_ctxp=0xbb0, perf_event_mutex=0xbb8, perf_event_list=0xbe8, tlb_ubc=0xbf8, splice_pipe=0xc00, task_frag=0xc08, delays=0xc18, nr_dirtied=0xc20, nr_dirtied_pause=0xc24, dirty_paused_when=0xc28, timer_slack_ns=0xc30, default_timer_slack_ns=0xc38, kunit_test=0xc40, trace_recursion=0xc48, memcg_in_oom=0xc50, memcg_nr_pages_over_high=0xc58, active_memcg=0xc60, objcg=0xc68, throttle_disk=0xc70, utask=0xc78, kmap_ctrl=0xc80, rcu=0xc80, rcu_users=0xc90, pagefault_disabled=0xc94, oom_reaper_list=0xc98, oom_reaper_timer=0xca0, stack_vm_area=0xcc8, stack_refcount=0xcd0, security=0xcd8, bpf_storage=0xce0, bpf_ctx=0xce8, bpf_net_context=0xcf0, android_vendor_data1=0xcf8, android_oem_data1=0xd28, kretprobe_instances=0xd58, __kabi_reserved1=0xd60, __kabi_reserved2=0xd68, __kabi_reserved3=0xd70, __kabi_reserved4=0xd78, __kabi_reserved5=0xd80, __kabi_reserved6=0xd88, __kabi_reserved7=0xd90, __kabi_reserved8=0xd98, thread=0xda0
- `btf.rb_node` = size 0x18: __rb_parent_color=0x0, rb_right=0x8, rb_left=0x10
- `btf.file_operations` = size 0x108: owner=0x0, fop_flags=0x8, llseek=0x10, read=0x18, write=0x20, read_iter=0x28, write_iter=0x30, iopoll=0x38, iterate_shared=0x40, poll=0x48, unlocked_ioctl=0x50, compat_ioctl=0x58, mmap=0x60, open=0x68, flush=0x70, release=0x78, fsync=0x80, fasync=0x88, lock=0x90, get_unmapped_area=0x98, check_flags=0xa0, flock=0xa8, splice_write=0xb0, splice_read=0xb8, splice_eof=0xc0, setlease=0xc8, fallocate=0xd0, show_fdinfo=0xd8, copy_file_range=0xe0, remap_file_range=0xe8, fadvise=0xf0, uring_cmd=0xf8, uring_cmd_iopoll=0x100
- `btf.configfs_buffer` = size 0x80: count=0x0, pos=0x8, page=0x10, ops=0x18, mutex=0x20, needs_read_fill=0x50, read_in_progress=0x54, write_in_progress=0x55, bin_buffer=0x58, bin_buffer_size=0x60, cb_max_size=0x64, item=0x68, owner=0x70, attr=0x78, bin_attr=0x78
- `btf.miscdevice` = size 0x50: minor=0x0, name=0x8, fops=0x10, list=0x18, parent=0x28, this_device=0x30, groups=0x38, nodename=0x40, mode=0x48
- `btf.ctl_table` = size 0x38: procname=0x0, data=0x8, maxlen=0x10, mode=0x14, proc_handler=0x18, poll=0x20, extra1=0x28, extra2=0x30
- `btf.nf_logger` = size 0x20: name=0x0, type=0x8, logfn=0x10, me=0x18
- `btf.page` = size 0x40: flags=0x0, lru=0x8, __filler=0x8, mlock_count=0x10, buddy_list=0x8, pcp_list=0x8, mapping=0x18, index=0x20, share=0x20, private=0x28, pp_magic=0x8, pp=0x10, _pp_mapping_pad=0x18, dma_addr=0x20, pp_ref_count=0x28, compound_head=0x8, pgmap=0x8, zone_device_data=0x10, callback_head=0x8, page_type=0x30, _mapcount=0x30, _refcount=0x34, memcg_data=0x38
- `worker_caller_bl_context` = bl at +0xa8 (0x101ef4):
0x101ecc: .word 0x52803915
0x101ed0: .word 0xf2ec391b
0x101ed4: b +0x34 -> 0x101f08
0x101ed8: .word 0x321d0108
0x101edc: .word 0xb9007a88
0x101ee0: .word 0xaa1403e0
0x101ee4: bl +0x-15ac -> 0x100938
0x101ee8: .word 0xaa1303e0
0x101eec: .word 0xb90032fa
0x101ef0: bl +0x10cca0c -> 0x11ce8fc
0x101ef4: bl +0x10c30c8 -> 0x11c4fbc <<<
0x101ef8: .word 0xaa1303e0
0x101efc: bl +0x10cc890 -> 0x11ce78c
0x101f00: .word 0xb9407a88
0x101f04: .word 0x37081668
- `worker_caller_source_schedule_calls` = worker_thread not found in kernel/workqueue.c
- `SLIDE_TRACEFS_WORKER_CALLER_OFF` = 0x101ef8
- `trace_event_base_source` = target kernel/trace/trace.h
- `trace_event_base` = 20
- `SLIDE_TRACEFS_EVENT_ID` = 110
- `ftrace_event_index` = 90
- `SLIDE_PSELECT_WORD_SHIFT` = 2
- `SLIDE_NFULNL_LOGGER_NAME_OFF` = 0x17e8698
- `SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF` = 0x25eafd8
- `ashmem.fops_table_dump@0x24d2110` = 0x0=0x3f80000000 0x8=0x3f80000000 0x10=0x43a610 0x18=0x3f80000000 0x20=0x3f80000000 0x28=0x3f80000000 0x30=0x3f80000000 0x38=0x3f80000000 0x40=0x3f80000000 0x48=0x3f80000000 0x50=0x5f0e0 0x58=0x5d3ac 0x60=0x3f80000000 0x68=0x5d408 0x70=0x3f80000000 0x78=0x3f80000000 0x80=0x3f80000000 0x88=0x3f80000000 0x90=0x3f80000000 0x98=0x3f80000000 0xa0=0x3f80000000 0xa8=0x3f80000000 0xb0=0x3f80000000 0xb8=0x3f80000000 0xc0=0x3f80000000 0xc8=0x3f80000000 0xd0=0x3f80000000 0xd8=0x3f80000000 0xe0=0x3f80000000 0xe8=0x3f80000000 0xf0=0x3f80000000 0xf8=0x3f80000000 0x100=0x3f80000000
- `misc_candidate.0x24d2370` = name="kvm" .fops=0x24d2110 llseek=0x43a610 ioctl=0x5f0e0  (SAME TABLE AS ASHMEM_FOPS_OFF)
- `misc_candidate.0x25f3200` = name="udmabuf" .fops=0x1382e10 llseek=0x-ffffffc080000000 ioctl=0xaa2058
- `misc_candidate.0x24cf630` = name="[vectors]" .fops=0x1863228 llseek=0x175d739 ioctl=0x30d48
- `misc_candidate.0x24dfe68` = name="oops_limit" .fops=0x24dfe68 llseek=0x24dfe68 ioctl=0xdb5bc
- `misc_candidate.0x24e0500` = name="int" .fops=0x1222ea8 llseek=0x184faab ioctl=0x17f2f28
- `misc_candidate.0x24e0578` = name="int" .fops=0x1222ea8 llseek=0x184faab ioctl=0x17f2f28
- `misc_candidate.0x24e08e0` = name="sysctl_writes_strict" .fops=0x24e0870 llseek=0x24dd0fc ioctl=0x-fffffe1c7ffffff8
- `misc_candidate.0x24e0bb8` = name="panic_on_oops" .fops=0x24dd0f8 llseek=0x178c22e ioctl=0x24bafe4
- `misc_candidate.0x24e0cd0` = name="max_lock_depth" .fops=0x24eb4e8 llseek=0x24eb4f0 ioctl=0x-ffffffc080000000
- `misc_candidate.0x24e0fe0` = name="dirtytime_expire_seconds" .fops=0x2599d20 llseek=0x480b30 ioctl=0x480f48
- `misc_candidate.0x24e1088` = name="page_lock_unfairness" .fops=0x257a2b8 llseek=0x17a8ccc ioctl=0x-ffffffc080000000
- `misc_candidate.0x24e11d8` = name="mmap_min_addr" .fops=0x25ca528 llseek=0x-ffffffc080000000 ioctl=0x17e2e40
- `misc_candidate_count` = 106
- `ashmem.fops_symbols` = no Rust ashmem fops_* symbols in this ELF (release build strips Rust statics) - the in-image table check above is the primary verification for this kernel
- `ikconfig_image_probe` = {'CONFIG_IKCONFIG=y': 0, 'CONFIG_IKCONFIG': 0, 'hdr DO NOT EDIT': 0, 'banner 6.12.23': 0}
- `ikconfig_status` = not-embedded
- `p0_probe_offset` = 0x1f0000
- `workqueue_pool_members_src` = work_color, flush_color, refcnt, plugged, nr_active, flush_color
