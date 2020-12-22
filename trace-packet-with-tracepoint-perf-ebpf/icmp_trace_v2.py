#!/usr/bin/env python
# coding: utf-8

import sys
from socket import inet_ntop, AF_INET, AF_INET6
from bcc import BPF
import ctypes as ct
import subprocess
from struct import pack
from datetime import datetime

bpf_text = '''
#include <bcc/proto.h>
#include <linux/sched.h>
#include <net/inet_sock.h>
#include <linux/net.h>
// for net struct
#include <net/net_namespace.h>

#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/icmp.h>
#include <uapi/linux/icmpv6.h>

#define IFNAMSIZ 16
#define XT_TABLE_MAXNAMELEN 32

// Event structure
struct route_evt_t {
    char comm[TASK_COMM_LEN];
    char ifname[IFNAMSIZ];
    u64 netns;
    u64 ts_us;
    u64 fun_idx;
    u64 cpu;

    /* Packet type (IPv4 or IPv6) and address */
    u64 ip_version; // familiy (IPv4 or IPv6)
    u64 icmptype;
    u64 icmpid;     // In practice, this is the PID of the ping process (see "ident" field in https://github.com/iputils/iputils/blob/master/ping_common.c)
    u64 icmpseq;    // Sequence number
    u64 saddr[2];   // Source address. IPv4: store in saddr[0]
    u64 daddr[2];   // Dest   address. IPv4: store in daddr[0]
};

BPF_PERF_OUTPUT(route_evt);

#define MAC_HEADER_SIZE 14;

#define member_read(destination, source_struct, source_member)                 \
  do{                                                                          \
    bpf_probe_read(                                                            \
      destination,                                                             \
      sizeof(source_struct->source_member),                                    \
      ((char*)source_struct) + offsetof(typeof(*source_struct), source_member) \
    );                                                                         \
  } while(0)

#define member_address(source_struct, source_member) \
({                                                   \
  void* __ret;                                       \
  __ret = (void*) (((char*)source_struct) + offsetof(typeof(*source_struct), source_member)); \
  __ret;                                             \
})

static inline int do_trace(void* ctx, struct sk_buff* skb, int func_idx)
{
    // Built event for userland
    struct route_evt_t evt = {};
    bpf_get_current_comm(evt.comm, TASK_COMM_LEN);
    evt.ts_us = bpf_ktime_get_ns()/1000;
    evt.fun_idx = func_idx;

    struct net_device *dev;
    member_read(&dev, skb, dev);
    // bpf_probe_read(&dev, sizeof(skb->dev), ((char*)skb) + offsetof(typeof(*skb), dev));

    // Load interface name
    bpf_probe_read(&evt.ifname, IFNAMSIZ, dev->name);

    // Compute MAC header address
    char* head;
    u16 mac_header;
    u16 network_header;

    member_read(&head,       skb, head);
    member_read(&mac_header, skb, mac_header);
    member_read(&network_header, skb, network_header);

    if(network_header == 0) {
        network_header = mac_header + MAC_HEADER_SIZE;
    }

        // Compute IP Header address
    char *ip_header_address = head + network_header;

    // Abstract IPv4 / IPv6
    u8 proto_icmp;
    u8 proto_icmp_echo_request;
    u8 proto_icmp_echo_reply;
    u8 icmp_offset_from_ip_header;
    u8 l4proto;

    // Load IP protocol version
    bpf_probe_read(&evt.ip_version, sizeof(u8), ip_header_address);
    evt.ip_version = evt.ip_version >> 4 & 0xf;
    
    evt.cpu = bpf_get_smp_processor_id();
    
    // Filter IP packets
    if (evt.ip_version == 4) {
        // Load IP Header
        struct iphdr iphdr;
        bpf_probe_read(&iphdr, sizeof(iphdr), ip_header_address);

        // Load protocol and address
        icmp_offset_from_ip_header = iphdr.ihl * 4;
        l4proto      = iphdr.protocol;
        evt.saddr[0] = iphdr.saddr;
        evt.daddr[0] = iphdr.daddr;

        // Load constants
        proto_icmp = IPPROTO_ICMP;
        proto_icmp_echo_request = ICMP_ECHO;
        proto_icmp_echo_reply   = ICMP_ECHOREPLY;
    }

     // Filter ICMP packets
    if (l4proto != proto_icmp) {
        return 0;
    }

    // Compute ICMP header address and load ICMP header
    char* icmp_header_address = ip_header_address + icmp_offset_from_ip_header;
    struct icmphdr icmphdr;
    bpf_probe_read(&icmphdr, sizeof(icmphdr), icmp_header_address);

    // Filter ICMP echo request and echo reply
    if (icmphdr.type != proto_icmp_echo_request && icmphdr.type != proto_icmp_echo_reply) {
        return 0;
    }

    // Get ICMP info
    evt.icmptype = icmphdr.type;
    evt.icmpid   = icmphdr.un.echo.id;
    evt.icmpseq  = icmphdr.un.echo.sequence;

    // Fix endian
    evt.icmpid  = be16_to_cpu(evt.icmpid);
    evt.icmpseq = be16_to_cpu(evt.icmpseq);

#ifdef CONFIG_NET_NS
    struct net *net;

    // Get netns id. The code below is equivalent to: evt->netns = dev->nd_net.net->ns.inum
    member_read(&net, dev, nd_net);
    member_read(&evt.netns, net, proc_inum);
#endif

    // Send event to userland
    route_evt.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}


static inline int do_trace_netif_rx(void* ctx, struct sk_buff* skb)
{
    return do_trace(ctx,skb, 0);
}

static inline int do_trace_net_dev_queue(void* ctx, struct sk_buff* skb)
{
    return do_trace(ctx,skb, 1);
}

static inline int do_trace_net_dev_xmit(void* ctx, struct sk_buff* skb)
{
    return do_trace(ctx,skb, 2);
}

static inline int do_trace_netif_receive_skb(void* ctx, struct sk_buff* skb)
{
    return do_trace(ctx,skb, 3);
}


/**
  * Attach to Kernel Tracepoints
  */
TRACEPOINT_PROBE(net, netif_rx) {
    return do_trace_netif_rx(args, (struct sk_buff*)args->skbaddr);
}

TRACEPOINT_PROBE(net, net_dev_queue) {
    return do_trace_net_dev_queue(args, (struct sk_buff*)args->skbaddr);
}

TRACEPOINT_PROBE(net, net_dev_xmit) {
    return do_trace_net_dev_xmit(args, (struct sk_buff*)args->skbaddr);
}

TRACEPOINT_PROBE(net, netif_receive_skb) {
    return do_trace_netif_receive_skb(args, (struct sk_buff*)args->skbaddr);
}
'''

TASK_COMM_LEN = 16 # linux/sched.h
IFNAMSIZ = 16

class RouteEvt(ct.Structure):
    _fields_ = [
        ("comm",    ct.c_char * TASK_COMM_LEN),
        ("ifname",  ct.c_char * IFNAMSIZ),
        ("netns",   ct.c_ulonglong),
        ("ts_us",   ct.c_ulonglong),
        ("fun_idx", ct.c_ulonglong),
        ("cpu",     ct.c_ulonglong),

        # Packet type (IPv4 or IPv6) and address
        ("ip_version",  ct.c_ulonglong),
        ("icmptype",    ct.c_ulonglong),
        ("icmpid",      ct.c_ulonglong),
        ("icmpseq",     ct.c_ulonglong),
        ("saddr",       ct.c_ulonglong * 2),
        ("daddr",       ct.c_ulonglong * 2),
    ]


# start_times 当前没有办法清理，只能用于短期内验证
start_times = {}

def event_printer(cpu, data, size):
    icmq_seq = 0
    start_us = 0

    # Decode event
    event = ct.cast(data, ct.POINTER(RouteEvt)).contents


    start_us = event.ts_us
    key = event.icmpseq + event.icmpid
    if start_times.has_key(key):
        start_us = start_times.get(key, 0)
    else:
        start_times[key] = event.ts_us

    # Decode address
    if event.ip_version == 4:
        saddr = inet_ntop(AF_INET, pack("=I", event.saddr[0]))
        daddr = inet_ntop(AF_INET, pack("=I", event.daddr[0]))

    # Decode direction
    if event.icmptype in [8, 128]:
        direction = "request"
    elif event.icmptype in [0, 129]:
        direction = "reply"
    else:
        return

    # dt = datetime.fromtimestamp(event.ts_ns // 1000000000)
    # data_str = dt.strftime('%Y-%m-%d %H:%M:%S')
    # data_str += '.' + str(int(event.ts_ns % 1000000000)).zfill(6)

    flow = "%s -> %s" % (saddr, daddr)

    delta_ms = (float(event.ts_us) - start_us) / 1000

    tps_name = ["netif_rx", "net_dev_queue", "net_dev_xmit", "netif_receive_skb"]

    fun_name = tps_name[event.fun_idx]

    # Print event
    if (delta_ms > 10.0):
        print "* %5s [%-12s] [%6s] %20s %16s %7s %7s %-34s" % (event.icmpseq, delta_ms, event.cpu, fun_name, event.ifname, event.icmpid, direction, flow)
    else:   
        print "%7s [%-12s] [%6s] %20s %16s %7s %7s %-34s" % (event.icmpseq, delta_ms, event.cpu, fun_name, event.ifname, event.icmpid, direction, flow)

if __name__ == "__main__":
    b = BPF(text=bpf_text)
    b["route_evt"].open_perf_buffer(event_printer)

    while True:
        b.kprobe_poll()



