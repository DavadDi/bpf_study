#!/usr/bin/python
from bcc import BPF
from bcc import DEBUG_PREPROCESSOR

prog = """
#include <uapi/linux/limits.h> // for  NAME_MAX

struct event_data_t {
    u32 pid;
    char fname[NAME_MAX];  // max of filename
};

BPF_PERF_OUTPUT(open_events);

TRACEPOINT_PROBE(syscalls,sys_enter_open){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct event_data_t evt = {};

    evt.pid = pid;
    bpf_probe_read(&evt.fname, sizeof(evt.fname), (void *)args->filename);

    open_events.perf_submit((struct pt_regs *)args, &evt, sizeof(evt));
    return 0;
}
"""

b = BPF(text=prog, debug=DEBUG_PREPROCESSOR)

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
