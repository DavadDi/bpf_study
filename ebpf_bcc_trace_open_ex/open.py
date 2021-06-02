#!/usr/bin/python
from bcc import BPF

prog = """
#include <linux/sched.h>

int trace_syscall_open(struct pt_regs *ctx, const char __user *filename, int flags) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 uid = bpf_get_current_uid_gid();
    
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    bpf_trace_printk("%d [%s]\\n", pid, filename);
    return 0;
}
"""

b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("open"), fn_name="trace_syscall_open")
try:
    b.trace_print()
except KeyboardInterrupt:
    exit()
