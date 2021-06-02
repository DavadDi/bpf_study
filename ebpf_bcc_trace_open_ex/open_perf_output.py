#!/usr/bin/python
from bcc import BPF

prog = """
#include <uapi/linux/limits.h> // for  NAME_MAX

// 1 define struct
struct event_data_t {
    u32 pid;
    char fname[NAME_MAX];  // max of filename
};

// 2. declare BPF_PERF_OUTPUT define 
BPF_PERF_OUTPUT(open_events);

int trace_syscall_open(struct pt_regs *ctx, const char __user *filename, int flags) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
  
    // 3.1 define event data and fill data
    struct event_data_t evt = {};
  
    evt.pid = pid;
    bpf_probe_read(&evt.fname, sizeof(evt.fname), (void *)filename);

    // bpf_trace_printk("%d [%s]\\n", pid, filename); =>
    
    // 3.2 submit the event
    open_events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}
"""

b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("open"), fn_name="trace_syscall_open")

# process event
def print_event(cpu, data, size):
  event = b["open_events"].event(data)
  print("Rcv Event %d, %s"%(event.pid, event.fname))
  
# loop with callback to print_event
b["open_events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
