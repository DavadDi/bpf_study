# BPF 程序类型

BPF 相关的程序，首先需要设置为相对应的的程序类型，截止当前完整的程序类型定义有 31 种之多，而且还是持续增加中，完整的列表可参见 [bpf.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h)，。

```
enum bpf_prog_type {
	BPF_PROG_TYPE_UNSPEC,
	BPF_PROG_TYPE_SOCKET_FILTER,
	BPF_PROG_TYPE_KPROBE,
	BPF_PROG_TYPE_SCHED_CLS,
	BPF_PROG_TYPE_SCHED_ACT,
	BPF_PROG_TYPE_TRACEPOINT,
	BPF_PROG_TYPE_XDP,
	BPF_PROG_TYPE_PERF_EVENT,
	BPF_PROG_TYPE_CGROUP_SKB,
	BPF_PROG_TYPE_CGROUP_SOCK,
	BPF_PROG_TYPE_LWT_IN,
	BPF_PROG_TYPE_LWT_OUT,
	BPF_PROG_TYPE_LWT_XMIT,
	BPF_PROG_TYPE_SOCK_OPS,
	BPF_PROG_TYPE_SK_SKB,
	BPF_PROG_TYPE_CGROUP_DEVICE,
	BPF_PROG_TYPE_SK_MSG,
	BPF_PROG_TYPE_RAW_TRACEPOINT,
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
	BPF_PROG_TYPE_LWT_SEG6LOCAL,
	BPF_PROG_TYPE_LIRC_MODE2,
	BPF_PROG_TYPE_SK_REUSEPORT,
	BPF_PROG_TYPE_FLOW_DISSECTOR,
	BPF_PROG_TYPE_CGROUP_SYSCTL,
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
	BPF_PROG_TYPE_CGROUP_SOCKOPT,
	BPF_PROG_TYPE_TRACING,
	BPF_PROG_TYPE_STRUCT_OPS,
	BPF_PROG_TYPE_EXT,
	BPF_PROG_TYPE_LSM,
	BPF_PROG_TYPE_SK_LOOKUP,
};
```

BPF 的程序类型是在程序加载的时候在内核中进行确定的，一旦程序类型确定，也就确定了 BPF 程序能够访问到的 BPF 内核帮助函数。

每种 BPF 类型可以使用的函数列表参见：[program-types](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#program-types)。程序类型对应的函数关系可以通过以下命令来进行获取：

    git grep -W 'func_proto(enum bpf_func_id func_id' kernel/ net/ drivers/

完整的程序类型对应的帮助函数表格如下：
|Program Type| Helper Functions|
|------------|-----------------|
|`BPF_PROG_TYPE_SOCKET_FILTER`|`BPF_FUNC_skb_load_bytes()` <br> `BPF_FUNC_skb_load_bytes_relative()` <br> `BPF_FUNC_get_socket_cookie()` <br> `BPF_FUNC_get_socket_uid()` <br> `BPF_FUNC_perf_event_output()` <br> `Base functions`|
|`BPF_PROG_TYPE_KPROBE`|`BPF_FUNC_perf_event_output()` <br> `BPF_FUNC_get_stackid()` <br> `BPF_FUNC_get_stack()` <br> `BPF_FUNC_perf_event_read_value()` <br> `BPF_FUNC_override_return()` <br> `Tracing functions`|
|`BPF_PROG_TYPE_SCHED_CLS` <br> `BPF_PROG_TYPE_SCHED_ACT`|`BPF_FUNC_skb_store_bytes()` <br> `BPF_FUNC_skb_load_bytes()` <br> `BPF_FUNC_skb_load_bytes_relative()` <br> `BPF_FUNC_skb_pull_data()` <br> `BPF_FUNC_csum_diff()` <br> `BPF_FUNC_csum_update()` <br> `BPF_FUNC_l3_csum_replace()` <br> `BPF_FUNC_l4_csum_replace()` <br> `BPF_FUNC_clone_redirect()` <br> `BPF_FUNC_get_cgroup_classid()` <br> `BPF_FUNC_skb_vlan_push()` <br> `BPF_FUNC_skb_vlan_pop()` <br> `BPF_FUNC_skb_change_proto()` <br> `BPF_FUNC_skb_change_type()` <br> `BPF_FUNC_skb_adjust_room()` <br> `BPF_FUNC_skb_change_tail()` <br> `BPF_FUNC_skb_get_tunnel_key()` <br> `BPF_FUNC_skb_set_tunnel_key()` <br> `BPF_FUNC_skb_get_tunnel_opt()` <br> `BPF_FUNC_skb_set_tunnel_opt()` <br> `BPF_FUNC_redirect()` <br> `BPF_FUNC_get_route_realm()` <br> `BPF_FUNC_get_hash_recalc()` <br> `BPF_FUNC_set_hash_invalid()` <br> `BPF_FUNC_set_hash()` <br> `BPF_FUNC_perf_event_output()` <br> `BPF_FUNC_get_smp_processor_id()` <br> `BPF_FUNC_skb_under_cgroup()` <br> `BPF_FUNC_get_socket_cookie()` <br> `BPF_FUNC_get_socket_uid()` <br> `BPF_FUNC_fib_lookup()` <br> `BPF_FUNC_skb_get_xfrm_state()` <br> `BPF_FUNC_skb_cgroup_id()` <br> `Base functions`|
|`BPF_PROG_TYPE_TRACEPOINT`|`BPF_FUNC_perf_event_output()` <br> `BPF_FUNC_get_stackid()` <br> `BPF_FUNC_get_stack()` <br> `Tracing functions`|
|`BPF_PROG_TYPE_XDP`| `BPF_FUNC_perf_event_output()` <br> `BPF_FUNC_get_smp_processor_id()` <br> `BPF_FUNC_csum_diff()` <br> `BPF_FUNC_xdp_adjust_head()` <br> `BPF_FUNC_xdp_adjust_meta()` <br> `BPF_FUNC_redirect()` <br> `BPF_FUNC_redirect_map()` <br> `BPF_FUNC_xdp_adjust_tail()` <br> `BPF_FUNC_fib_lookup()` <br> `Base functions`|
|`BPF_PROG_TYPE_PERF_EVENT`| `BPF_FUNC_perf_event_output()` <br> `BPF_FUNC_get_stackid()` <br> `BPF_FUNC_get_stack()` <br> `BPF_FUNC_perf_prog_read_value()` <br> `Tracing functions`|
|`BPF_PROG_TYPE_CGROUP_SKB`|`BPF_FUNC_skb_load_bytes()` <br> `BPF_FUNC_skb_load_bytes_relative()` <br> `BPF_FUNC_get_socket_cookie()` <br> `BPF_FUNC_get_socket_uid()` <br> `Base functions`|
|`BPF_PROG_TYPE_CGROUP_SOCK`|`BPF_FUNC_get_current_uid_gid()` <br> `Base functions`|
|`BPF_PROG_TYPE_LWT_IN`|`BPF_FUNC_lwt_push_encap()` <br> `LWT functions` <br> `Base functions`|
|`BPF_PROG_TYPE_LWT_OUT`| `LWT functions` <br> `Base functions`|
|`BPF_PROG_TYPE_LWT_XMIT`| `BPF_FUNC_skb_get_tunnel_key()` <br> `BPF_FUNC_skb_set_tunnel_key()` <br> `BPF_FUNC_skb_get_tunnel_opt()` <br> `BPF_FUNC_skb_set_tunnel_opt()` <br> `BPF_FUNC_redirect()` <br> `BPF_FUNC_clone_redirect()` <br> `BPF_FUNC_skb_change_tail()` <br> `BPF_FUNC_skb_change_head()` <br> `BPF_FUNC_skb_store_bytes()` <br> `BPF_FUNC_csum_update()` <br> `BPF_FUNC_l3_csum_replace()` <br> `BPF_FUNC_l4_csum_replace()` <br> `BPF_FUNC_set_hash_invalid()` <br> `LWT functions`|
|`BPF_PROG_TYPE_SOCK_OPS`|`BPF_FUNC_setsockopt()` <br> `BPF_FUNC_getsockopt()` <br> `BPF_FUNC_sock_ops_cb_flags_set()` <br> `BPF_FUNC_sock_map_update()` <br> `BPF_FUNC_sock_hash_update()` <br> `BPF_FUNC_get_socket_cookie()` <br> `Base functions`|
|`BPF_PROG_TYPE_SK_SKB`|`BPF_FUNC_skb_store_bytes()` <br> `BPF_FUNC_skb_load_bytes()` <br> `BPF_FUNC_skb_pull_data()` <br> `BPF_FUNC_skb_change_tail()` <br> `BPF_FUNC_skb_change_head()` <br> `BPF_FUNC_get_socket_cookie()` <br> `BPF_FUNC_get_socket_uid()` <br> `BPF_FUNC_sk_redirect_map()` <br> `BPF_FUNC_sk_redirect_hash()` <br> `BPF_FUNC_sk_lookup_tcp()` <br> `BPF_FUNC_sk_lookup_udp()` <br> `BPF_FUNC_sk_release()` <br> `Base functions`|
|`BPF_PROG_TYPE_CGROUP_DEVICE`|`BPF_FUNC_map_lookup_elem()` <br> `BPF_FUNC_map_update_elem()` <br> `BPF_FUNC_map_delete_elem()` <br> `BPF_FUNC_get_current_uid_gid()` <br> `BPF_FUNC_trace_printk()`|
|`BPF_PROG_TYPE_SK_MSG`|`BPF_FUNC_msg_redirect_map()` <br> `BPF_FUNC_msg_redirect_hash()` <br> `BPF_FUNC_msg_apply_bytes()` <br> `BPF_FUNC_msg_cork_bytes()` <br> `BPF_FUNC_msg_pull_data()` <br> `BPF_FUNC_msg_push_data()` <br> `BPF_FUNC_msg_pop_data()` <br> `Base functions`|
|`BPF_PROG_TYPE_RAW_TRACEPOINT`|`BPF_FUNC_perf_event_output()` <br> `BPF_FUNC_get_stackid()` <br> `BPF_FUNC_get_stack()` <br> `BPF_FUNC_skb_output()` <br> `Tracing functions`|
|`BPF_PROG_TYPE_CGROUP_SOCK_ADDR`|`BPF_FUNC_get_current_uid_gid()` <br> `BPF_FUNC_bind()` <br> `BPF_FUNC_get_socket_cookie()` <br> `Base functions`|
|`BPF_PROG_TYPE_LWT_SEG6LOCAL`|`BPF_FUNC_lwt_seg6_store_bytes()` <br> `BPF_FUNC_lwt_seg6_action()` <br> `BPF_FUNC_lwt_seg6_adjust_srh()` <br> `LWT functions`|
|`BPF_PROG_TYPE_LIRC_MODE2`|`BPF_FUNC_rc_repeat()` <br> `BPF_FUNC_rc_keydown()` <br> `BPF_FUNC_rc_pointer_rel()` <br> `BPF_FUNC_map_lookup_elem()` <br> `BPF_FUNC_map_update_elem()` <br> `BPF_FUNC_map_delete_elem()` <br> `BPF_FUNC_ktime_get_ns()` <br> `BPF_FUNC_tail_call()` <br> `BPF_FUNC_get_prandom_u32()` <br> `BPF_FUNC_trace_printk()`|
|`BPF_PROG_TYPE_SK_REUSEPORT`|`BPF_FUNC_sk_select_reuseport()` <br> `BPF_FUNC_skb_load_bytes()` <br> `BPF_FUNC_load_bytes_relative()` <br> `Base functions`|
|`BPF_PROG_TYPE_FLOW_DISSECTOR`|`BPF_FUNC_skb_load_bytes()` <br> `Base functions`|

|Function Group| Functions|
|------------------|-------|
|`Base functions`| `BPF_FUNC_map_lookup_elem()` <br> `BPF_FUNC_map_update_elem()` <br> `BPF_FUNC_map_delete_elem()` <br> `BPF_FUNC_map_peek_elem()` <br> `BPF_FUNC_map_pop_elem()` <br> `BPF_FUNC_map_push_elem()` <br> `BPF_FUNC_get_prandom_u32()` <br> `BPF_FUNC_get_smp_processor_id()` <br> `BPF_FUNC_get_numa_node_id()` <br> `BPF_FUNC_tail_call()` <br> `BPF_FUNC_ktime_get_boot_ns()` <br> `BPF_FUNC_ktime_get_ns()` <br> `BPF_FUNC_trace_printk()` <br> `BPF_FUNC_spin_lock()` <br> `BPF_FUNC_spin_unlock()` |
|`Tracing functions`|`BPF_FUNC_map_lookup_elem()` <br> `BPF_FUNC_map_update_elem()` <br> `BPF_FUNC_map_delete_elem()` <br> `BPF_FUNC_probe_read()` <br> `BPF_FUNC_ktime_get_boot_ns()` <br> `BPF_FUNC_ktime_get_ns()` <br> `BPF_FUNC_tail_call()` <br> `BPF_FUNC_get_current_pid_tgid()` <br> `BPF_FUNC_get_current_task()` <br> `BPF_FUNC_get_current_uid_gid()` <br> `BPF_FUNC_get_current_comm()` <br> `BPF_FUNC_trace_printk()` <br> `BPF_FUNC_get_smp_processor_id()` <br> `BPF_FUNC_get_numa_node_id()` <br> `BPF_FUNC_perf_event_read()` <br> `BPF_FUNC_probe_write_user()` <br> `BPF_FUNC_current_task_under_cgroup()` <br> `BPF_FUNC_get_prandom_u32()` <br> `BPF_FUNC_probe_read_str()` <br> `BPF_FUNC_get_current_cgroup_id()` <br> `BPF_FUNC_send_signal()` <br> `BPF_FUNC_probe_read_kernel()` <br> `BPF_FUNC_probe_read_kernel_str()` <br> `BPF_FUNC_probe_read_user()` <br> `BPF_FUNC_probe_read_user_str()` <br> `BPF_FUNC_send_signal_thread()` <br> `BPF_FUNC_get_ns_current_pid_tgid()` <br> `BPF_FUNC_xdp_output()` <br> `BPF_FUNC_get_task_stack()`|
|`LWT functions`|  `BPF_FUNC_skb_load_bytes()` <br> `BPF_FUNC_skb_pull_data()` <br> `BPF_FUNC_csum_diff()` <br> `BPF_FUNC_get_cgroup_classid()` <br> `BPF_FUNC_get_route_realm()` <br> `BPF_FUNC_get_hash_recalc()` <br> `BPF_FUNC_perf_event_output()` <br> `BPF_FUNC_get_smp_processor_id()` <br> `BPF_FUNC_skb_under_cgroup()`|



