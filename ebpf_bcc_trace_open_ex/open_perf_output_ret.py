#!/usr/bin/python
from bcc import BPF

prog = """
#include <uapi/linux/limits.h> // for  NAME_MAX
#include <linux/sched.h> // for TASK_COMM_LEN

struct event_data_t {
    u32 pid;
    u32 ret; // +add
    char comm[TASK_COMM_LEN];
    char fname[NAME_MAX];
};

// +add
struct val_t {
    u64 id;
    const char *fname;
};

BPF_HASH(infotmp, u64, struct val_t);
BPF_PERF_OUTPUT(open_events);

int trace_syscall_open(struct pt_regs *ctx, const char __user *filename, int flags) {
    struct val_t val = {};
    u64 id = bpf_get_current_pid_tgid();

    val.id = id;
    val.fname = filename;

    infotmp.update(&id, &val);

    return 0;
}

int trace_syscall_open_return(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct val_t *valp;
    struct event_data_t evt = {};

    valp = infotmp.lookup(&id);
    if (valp == 0) {
        // missed entry
        return 0;
    }

    evt.pid = id >> 32;
    evt.ret = PT_REGS_RC(ctx);
    bpf_probe_read(&evt.fname, sizeof(evt.fname), (void *)valp->fname);
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    open_events.perf_submit(ctx, &evt, sizeof(evt));

    infotmp.delete(&id);
    return 0;
}
"""

b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("open"), fn_name="trace_syscall_open")
b.attach_kretprobe(event=b.get_syscall_fnname("open"), fn_name="trace_syscall_open_return")

# process event
def print_event(cpu, data, size):
  event = b["open_events"].event(data)
  print("[%s] %d, %s, res: %d"%(event.comm, event.pid, event.fname, event.ret))

# loop with callback to print_event
b["open_events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
