#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports


from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
from socket import inet_ntop, AF_INET
import socket, struct
import argparse
import ctypes as ct
from struct import pack

# arguments
examples = """examples:
    ./tcp_rcv            # summarize TCP RTT
    ./tcp_rcv -p         # filter for dest port
    ./tcp_rcv -P         # filter for src port
    ./tcp_rcv -a         # filter for dest address
    ./tcp_rcv -A         # filter for src address
    ./tcp_rcv -D         # show debug bpf text
"""

parser = argparse.ArgumentParser(
    description="Summarize TCP RTT as a histogram",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)

parser.add_argument("-p", "--sport",
    help="filter for src port")
parser.add_argument("-P", "--dport",
    help="filter for dest port")
parser.add_argument("-a", "--saddr",
    help="filter for src address")
parser.add_argument("-A", "--daddr",
    help="filter for dest address")

parser.add_argument("-D", "--debug", action="store_true",
    help="print BPF program before starting (for debugging purposes)")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()

# define BPF program
bpf_text = """
#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME "bcc"
#endif

#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <linux/ip.h>
#include <net/inet_sock.h>
#include <bcc/proto.h>

struct ipv4_data_t
{
    u64 ts_us;
    u32 pid;
    u32 fun_idx;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u64 arg0;
    u64 arg1;
    u64 arg2;
    u32 syn;
    u32 fin;
    char task[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(ipv4_events);

static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb)
{
    // unstable API. verify logic in ip_hdr() -> skb_network_header().
    return (struct iphdr *)(skb->head + skb->network_header);
}

static struct tcphdr *skb_to_tcphdr(const struct sk_buff *skb)
{
    // unstable API. verify logic in tcp_hdr() -> skb_transport_header().
    return (struct tcphdr *)(skb->head + skb->transport_header);
}

static inline int deal_skb(struct pt_regs *ctx, const struct sock *sk, const struct sk_buff *skb, int fun_idx)
{
    u16 sport = 0;
    u16 dport = 0;
    u32 saddr = 0;
    u32 daddr = 0;
    u32 seq = 0;
    u32 syn = 0;
    u32 fin = 0;
    u16 family = 0;
    u8 ip_proto;

    struct iphdr *iph = skb_to_iphdr(skb);
    struct tcphdr *th = skb_to_tcphdr(skb);

    if (skb->protocol != htons(ETH_P_IP)) {
        return 0;
    }

    ip_proto = iph->protocol;    
    saddr = iph->saddr;
    daddr = iph->daddr;
    
    sport = th->source;
    dport = th->dest;
   
    if (ip_proto != 0x06) {
        return 0;
    }    

    if (ntohs(dport) != 80 && ntohs(dport) != 32193)
    {
	    return 0;
    }

    if (saddr != 0x488610ac)
    {
        return 0;
    }

    SRCPORTFILTER
    DSTPORTFILTER
    SRCADDRFILTER
    DSTADDRFILTER
  
    sport = ntohs(sport);
    dport = ntohs(dport);
  
    struct ipv4_data_t data4 = {};
    data4.ts_us = bpf_ktime_get_ns()/1000;
    data4.pid = bpf_get_current_pid_tgid() >> 32;
    data4.fun_idx = fun_idx; 
	
	
    data4.saddr = saddr;
    data4.daddr = daddr;
   
    data4.sport = sport;
    data4.dport = dport; 
    
    data4.arg0 = (u64)sk;
    
    seq = th->seq;
    seq = ntohl(seq);

    data4.arg2 = seq;   
    data4.arg1 =  (u64)skb;
    // syn  = th->syn;
    // fin = th->fin;

    // data4.syn = syn;
    // data4.fin = fin;

    bpf_get_current_comm(&data4.task, sizeof(data4.task));   
    ipv4_events.perf_submit(ctx, &data4, sizeof(data4)); 
    
    return 0;

}

int trace_tcp_rcv(struct pt_regs *ctx, struct sk_buff *skb)
{   
    return deal_skb(ctx, skb->sk, skb, 100);
}


int trace_ip_rcv(struct pt_regs *ctx,  struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
    return deal_skb(ctx, skb->sk, skb, 1);
}

int trace_ip_rcv_finish(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb)
{
    return deal_skb(ctx, skb->sk, skb, 2);
}

void trace_tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state)
{
    const struct inet_sock *inet = inet_sk(sk);

    u16 sport = 0;
    u16 dport = 0;
    u32 saddr = 0;
    u32 daddr = 0;
    u16 family = 0;
    family = sk->__sk_common.skc_family;


    bpf_probe_read(&dport, sizeof(dport), (void *)&inet->inet_sport);
    bpf_probe_read(&sport, sizeof(sport), (void *)&inet->inet_dport);
    
    bpf_probe_read(&daddr, sizeof(daddr), (void *)&inet->inet_saddr);
    bpf_probe_read(&saddr, sizeof(saddr), (void *)&inet->inet_daddr);    
 
    if (ntohs(dport) != 80 && ntohs(dport) != 32193)
    {
        return;
    }
   
    if (saddr != 0x488610ac)
    {
        return;
    }
    

    if (family == AF_INET)
    {
        struct ipv4_data_t data4 = {};
        data4.ts_us = bpf_ktime_get_ns()/1000;
        data4.pid = bpf_get_current_pid_tgid() >> 32;
        data4.fun_idx = 102; 

        data4.saddr = saddr;
        data4.daddr = daddr;
        data4.sport = be16_to_cpu(sport);
        data4.dport = be16_to_cpu(dport); 
        
        data4.arg0 =  (u64)sk;
        data4.arg1 =  (u64)state;
	    data4.arg2 = (u64)sk->sk_state;        
        bpf_get_current_comm(&data4.task, sizeof(data4.task));

        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    }
}

int trace_tcp_reset(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb)
{
    return deal_skb(ctx, sk, skb, 101);
}

"""

# filter for local port
if args.sport:
    bpf_text = bpf_text.replace('SRCPORTFILTER',
        """if (ntohs(sport) != %d)
        return 0;""" % int(args.sport))
else:
    bpf_text = bpf_text.replace('SRCPORTFILTER', '')

# filter for remote port
if args.dport:
    bpf_text = bpf_text.replace('DSTPORTFILTER',
        """if (ntohs(dport) != %d)
        return 0;""" % int(args.dport))
else:
    bpf_text = bpf_text.replace('DSTPORTFILTER', '')

# filter for local address
if args.saddr:
    bpf_text = bpf_text.replace('SRCADDRFILTER',
        """if (saddr != %d)
        return 0;""" % struct.unpack("=I", socket.inet_aton(args.saddr))[0])
else:
    bpf_text = bpf_text.replace('SRCADDRFILTER', '')

# filter for remote address
if args.daddr:
    bpf_text = bpf_text.replace('DSTADDRFILTER',
        """if (daddr != %d)
        return 0;""" % struct.unpack("=I", socket.inet_aton(args.daddr))[0])
else:
    bpf_text = bpf_text.replace('DSTADDRFILTER', '')

# debug/dump ebpf enable or not
if args.debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

TASK_COMM_LEN = 16  # linux/sched.h

class RouteEvt(ct.Structure):
    _fields_ = [
        ("ts_us", ct.c_ulonglong),
        ("pid",   ct.c_uint32),
        ("fun_idx", ct.c_uint32),
        ("saddr", ct.c_uint32),
        ("daddr", ct.c_uint32),
        ("sport", ct.c_uint16),
        ("dport", ct.c_uint16),
        ("arg0", ct.c_ulonglong),
        ("arg1", ct.c_ulonglong),
 	    ("arg2", ct.c_ulonglong),
        ("syn", ct.c_uint32),
        ("fin", ct.c_uint32),
        ("task", ct.c_char * TASK_COMM_LEN),
    ]


def event_printer(cpu, data, size):
    event = b["ipv4_events"].event(data)
    # Decode event
    event = ct.cast(data, ct.POINTER(RouteEvt)).contents

    saddr = inet_ntop(AF_INET, pack("=I", event.saddr))
    daddr = inet_ntop(AF_INET, pack("=I", event.daddr))

    if event.fun_idx != 102:
        # Print event
        print("-%s [%10s] %d %d - [%d] %s:%d -> %s:%d 0x%x 0x%x 0x%x"
          % (cpu, event.task, event.ts_us, event.pid, event.fun_idx, saddr, event.sport, daddr, event.dport, event.arg0, event.arg1, event.arg2))
    else:
        # Print event
        print("-%s [%10s] %d %d - [%d] %s:%d -> %s:%d 0x%x %s %s syn %d fin %d"
          % (cpu, event.task, event.ts_us, event.pid, event.fun_idx, saddr, event.sport, daddr, event.dport, event.arg0, tcp_stat[event.arg1], tcp_stat[event.arg2]))

# load BPF program
b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_v4_rcv", fn_name="trace_tcp_rcv")

b.attach_kprobe(event="ip_rcv", fn_name="trace_ip_rcv")
b.attach_kprobe(event="ip_rcv_finish", fn_name="trace_ip_rcv_finish")

b.attach_kprobe(event="tcp_v4_send_reset", fn_name="trace_tcp_reset")
b.attach_kprobe(event="tcp_set_state", fn_name="trace_tcp_set_state")

print("Tracing tcp_v4_rcv... Hit Ctrl-C to end.")

tcp_stat = ["UNKNOWN",
    "TCP_ESTABLISHED",
	"TCP_SYN_SENT",
	"TCP_SYN_RECV",
	"TCP_FIN_WAIT1",
	"TCP_FIN_WAIT2",
	"TCP_TIME_WAIT",
	"TCP_CLOSE",
	"TCP_CLOSE_WAIT",
	"TCP_LAST_ACK",
	"TCP_LISTEN",
	"TCP_CLOSING"]

if __name__ == "__main__":
    b["ipv4_events"].open_perf_buffer(event_printer)

    while 1:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()

