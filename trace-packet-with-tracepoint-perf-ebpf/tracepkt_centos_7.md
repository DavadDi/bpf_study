```bash
#!/usr/bin/env python
# coding: utf-8

# [tracer_skb]# uname -a
# Linux master-147 3.10.0-957.21.3.el7.x86_64 #1 SMP Tue Jun 18 16:35:19 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
# [tracer_skb]# lsb_release -a
# LSB Version:    :core-4.1-amd64:core-4.1-noarch
# Distributor ID:    CentOS
# Description:    CentOS Linux release 7.6.1810 (Core)
# Release:    7.6.1810
# Codename:    Core

$ perf trace --no-syscalls --event 'net:*' ping 10.81.128.16 -c1 > /dev/null
     
     0.000 net:net_dev_queue:       dev=cali6ecc40249f1          skbaddr=0xffff9eb2d36c5500 len=98
     0.017 net:netif_rx:            dev=eth0                     skbaddr=0xffff9eb2d36c5500 len=84
     0.021 net:net_dev_xmit:        dev=cali6ecc40249f1          skbaddr=0xffff9eb2d36c5500 len=98 rc=0
     0.024 net:netif_receive_skb:   dev=eth0                     skbaddr=0xffff9eb2d36c5500 len=84 

     # ICMP echo reply
     0.058 net:net_dev_queue:        dev=eth0                     skbaddr=0xffff9eb2d36c5d00 len=98  
     0.061 net:netif_rx:             dev=cali6ecc40249f1          skbaddr=0xffff9eb2d36c5d00 len=84
     0.063 net:net_dev_xmit:         dev=eth0                     skbaddr=0xffff9eb2d36c5d00 len=98 rc=0
     0.065 net:netif_receive_skb:    dev=cali6ecc40249f1          skbaddr=0xffff9eb2d36c5d00 len=84
```



针对 CentOS CentOS Linux release 7.6.1810 版本的 tracepkt.py

```python
import sys
from socket import inet_ntop, AF_INET, AF_INET6
from bcc import BPF
import ctypes as ct
import subprocess
from struct import pack

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

static inline int do_trace(void* ctx, struct sk_buff* skb)
{
    // Built event for userland
    struct route_evt_t evt = {};
    bpf_get_current_comm(evt.comm, TASK_COMM_LEN);

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

/**
  * Attach to Kernel Tracepoints
  */
TRACEPOINT_PROBE(net, netif_rx) {
    return do_trace(args, (struct sk_buff*)args->skbaddr);
}

TRACEPOINT_PROBE(net, net_dev_queue) {
    return do_trace(args, (struct sk_buff*)args->skbaddr);
}

TRACEPOINT_PROBE(net, net_dev_xmit) {
    return do_trace(args, (struct sk_buff*)args->skbaddr);
}

TRACEPOINT_PROBE(net, netif_receive_skb) {
    return do_trace(args, (struct sk_buff*)args->skbaddr);
}
'''

TASK_COMM_LEN = 16 # linux/sched.h
IFNAMSIZ = 16

class RouteEvt(ct.Structure):
    _fields_ = [
        ("comm",    ct.c_char * TASK_COMM_LEN),
        ("ifname",  ct.c_char * IFNAMSIZ),
        ("netns",   ct.c_ulonglong),

        # Packet type (IPv4 or IPv6) and address
        ("ip_version",  ct.c_ulonglong),
        ("icmptype",    ct.c_ulonglong),
        ("icmpid",      ct.c_ulonglong),
        ("icmpseq",     ct.c_ulonglong),
        ("saddr",       ct.c_ulonglong * 2),
        ("daddr",       ct.c_ulonglong * 2),
    ]

def event_printer(cpu, data, size):
    # Decode event
    event = ct.cast(data, ct.POINTER(RouteEvt)).contents

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

    flow = "%s -> %s" % (saddr, daddr)

         # Print event
    print "[%12s] %16s %7s %-34s" % (event.netns, event.ifname, direction, flow)

if __name__ == "__main__":
    b = BPF(text=bpf_text)
    b["route_evt"].open_perf_buffer(event_printer)

    while True:
        b.kprobe_poll()
```

