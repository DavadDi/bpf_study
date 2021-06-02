#!/usr/bin/python
from bcc import BPF
import argparse  # +add

prog = """
#include <linux/sched.h>

int trace_syscall_open(struct pt_regs *ctx, const char __user *filename, int flags) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 uid = bpf_get_current_uid_gid();

    PID_FILTER  // + add PID FILTER
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    bpf_trace_printk("%d [%s]\\n", pid, filename);
    return 0;
}
"""

examples = """examples:
    ./open_pid -p 181    # only trace PID 181
"""

parser = argparse.ArgumentParser(
    description="Trace open() syscalls",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)

parser.add_argument("-p", "--pid",
    help="trace this PID only")

args = parser.parse_args()

if args.pid:
    prog = prog.replace('PID_FILTER',
        'if (pid != %s) { return 0; }' % args.pid)
else:
    prog = prog.replace('PID_TID_FILTER', '')
    
b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("open"), fn_name="trace_syscall_open")
try:
    b.trace_print()
except KeyboardInterrupt:
    exit()
