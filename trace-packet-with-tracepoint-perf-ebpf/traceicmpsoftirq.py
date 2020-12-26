#!/usr/bin/python
bpf_text = """
#include <linux/ptrace.h>
#include <linux/sched.h>        /* For TASK_COMM_LEN */
#include <linux/icmp.h>
#include <linux/netdevice.h>
struct probe_icmp_data_t
{
        u64 timestamp_ns;
        u32 tgid;
        u32 pid;
        char comm[TASK_COMM_LEN];
        int v0;
};
BPF_PERF_OUTPUT(probe_icmp_events);
static inline unsigned char *my_skb_transport_header(const struct sk_buff *skb)
{
    return skb->head + skb->transport_header;
}
static inline struct icmphdr *my_icmp_hdr(const struct sk_buff *skb)
{
    return (struct icmphdr *)my_skb_transport_header(skb);
}
int probe_icmp(struct pt_regs *ctx, struct sk_buff *skb)
{
        u64 __pid_tgid = bpf_get_current_pid_tgid();
        u32 __tgid = __pid_tgid >> 32;
        u32 __pid = __pid_tgid; // implicit cast to u32 for bottom half
        
        struct probe_icmp_data_t __data = {0};
        __data.timestamp_ns = bpf_ktime_get_ns();
        __data.tgid = __tgid;
        __data.pid = __pid;
        bpf_get_current_comm(&__data.comm, sizeof(__data.comm));
        __be16 seq;
        void *addr = &my_icmp_hdr(skb)->un.echo.sequence;
        bpf_probe_read(&seq, sizeof(seq), addr);

        // bpf_probe_read(&seq, sizeof(seq), &my_icmp_hdr(skb)->un.echo.sequence);
        __data.v0 = be16_to_cpu(seq);
        probe_icmp_events.perf_submit(ctx, &__data, sizeof(__data));
        return 0;
}
"""

from bcc import BPF
import ctypes as ct

class Data_icmp(ct.Structure):
    _fields_ = [
        ("timestamp_ns", ct.c_ulonglong),
        ("tgid", ct.c_uint),
        ("pid", ct.c_uint),
        ("comm", ct.c_char * 16),       # TASK_COMM_LEN
        ('v0', ct.c_uint),
    ]

b = BPF(text=bpf_text)

def print_icmp_event(cpu, data, size):
    #event = b["probe_icmp_events"].event(data)
    event = ct.cast(data, ct.POINTER(Data_icmp)).contents
    print("%-7d %-7d %-15s %s" %
                      (event.tgid, event.pid,
                       event.comm.decode('utf-8', 'replace'),
                       event.v0))

b.attach_kprobe(event="icmp_echo", fn_name="probe_icmp")

b["probe_icmp_events"].open_perf_buffer(print_icmp_event)
while 1:
    try:
        b.kprobe_poll()
    except KeyboardInterrupt:
        exit()
