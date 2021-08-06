#!/usr/bin/env python
# coding: utf-8

import sys
import socket
from socket import inet_ntop, AF_INET, AF_INET6
from bcc import BPF
import ctypes as ct
import subprocess
from struct import pack
import argparse
import time
import struct

examples = """examples:
      skbtracer.py                                      # trace all packets
      skbtracer.py --proto=icmp -H 1.2.3.4 --icmpid 22  # trace icmp packet with addr=1.2.3.4 and icmpid=22
      skbtracer.py --proto=tcp  -H 1.2.3.4 -P 22        # trace tcp  packet with addr=1.2.3.4:22
      skbtracer.py --proto=udp  -H 1.2.3.4 -P 22        # trace udp  packet wich addr=1.2.3.4:22
      skbtracer.py -t -T -p 1 --debug -P 80 -H 127.0.0.1 --proto=tcp --kernel-stack --icmpid=100 -N 10000
"""

parser = argparse.ArgumentParser(
    description="Trace any packet through TCP/IP stack",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)

parser.add_argument("-H", "--ipaddr", type=str,
    help="ip address")

parser.add_argument("--proto", type=str,
    help="tcp|udp|icmp|any ")

parser.add_argument("--icmpid", type=int, default=0,
    help="trace icmp id")

parser.add_argument("-c", "--catch-count", type=int, default=1000000,
    help="catch and print count")

parser.add_argument("-P", "--port", type=int, default=0,
    help="udp or tcp port")

parser.add_argument("-p", "--pid", type=int, default=0,
    help="trace this PID only")

parser.add_argument("-N", "--netns", type=int, default=0,
    help="trace this Network Namespace only")

parser.add_argument("--dropstack", action="store_true",
    help="output kernel stack trace when drop packet")

parser.add_argument("--callstack", action="store_true",
    help="output kernel stack trace")

parser.add_argument("--iptable", action="store_true",
    help="output iptable path")

parser.add_argument("--route", action="store_true",
    help="output route path")

parser.add_argument("--keep", action="store_true",
    help="keep trace packet all lifetime")

parser.add_argument("-T", "--time", action="store_true",
    help="show HH:MM:SS timestamp")

parser.add_argument("-t", "--timestamp", action="store_true",
    help="show timestamp in seconds at us resolution")

parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)

parser.add_argument("--debug", action="store_true",
    help=argparse.SUPPRESS)

args = parser.parse_args()
if args.debug == True:
    print("pid=%d time=%d timestamp=%d ipaddr=%s port=%d netns=%d proto=%s icmpid=%d dropstack=%d" % \
            (args.pid,args.time,args.timestamp,args.ipaddr, args.port,args.netns,args.proto,args.icmpid, args.dropstack))
    sys.exit()


ipproto={}
#ipproto["tcp"]="IPPROTO_TCP"
ipproto["tcp"]="6"
#ipproto["udp"]="IPPROTO_UDP"
ipproto["udp"]="17"
#ipproto["icmp"]="IPPROTO_ICMP"
ipproto["icmp"]="1"
proto = 0 if args.proto == None else (0 if ipproto.get(args.proto) == None else ipproto[args.proto])
#ipaddr=socket.htonl(struct.unpack("I",socket.inet_aton("0" if args.ipaddr == None else args.ipaddr))[0])
#port=socket.htons(args.port)
ipaddr=(struct.unpack("I",socket.inet_aton("0" if args.ipaddr == None else args.ipaddr))[0])
port=(args.port)
icmpid=socket.htons(args.icmpid)

bpf_def="#define __BCC_ARGS__\n"
bpf_args="#define __BCC_pid (%d)\n" % (args.pid)
bpf_args+="#define __BCC_ipaddr (0x%x)\n" % (ipaddr)
bpf_args+="#define __BCC_port (%d)\n" % (port)
bpf_args+="#define __BCC_netns (%d)\n" % (args.netns)
bpf_args+="#define __BCC_proto (%s)\n" % (proto)
bpf_args+="#define __BCC_icmpid (%d)\n" % (icmpid)
bpf_args+="#define __BCC_dropstack (%d)\n" % (args.dropstack)
bpf_args+="#define __BCC_callstack (%d)\n" % (args.callstack)
bpf_args+="#define __BCC_iptable (%d)\n" % (args.iptable)
bpf_args+="#define __BCC_route (%d)\n" % (args.route)
bpf_args+="#define __BCC_keep (%d)\n" % (args.keep)

bpf_text=open(r"skbtracer.c", "r").read()
bpf_text=bpf_def + bpf_text
bpf_text=bpf_text.replace("__BCC_ARGS_DEFINE__", bpf_args)

if args.ebpf == True:
   print("%s" % (bpf_text))
   sys.exit()

# uapi/linux/if.h
IFNAMSIZ = 16

# uapi/linux/netfilter/x_tables.h
XT_TABLE_MAXNAMELEN = 32

# uapi/linux/netfilter.h
NF_VERDICT_NAME = [
    'DROP',
    'ACCEPT',
    'STOLEN',
    'QUEUE',
    'REPEAT',
    'STOP',
]

# uapi/linux/netfilter.h
# net/ipv4/netfilter/ip_tables.c
HOOKNAMES = [
    "PREROUTING",
    "INPUT",
    "FORWARD",
    "OUTPUT",
    "POSTROUTING",
]

TCPFLAGS = [
    "CWR",
    "ECE",
    "URG",
    "ACK",
    "PSH",
    "RST",
    "SYN",
    "FIN",
]

ROUTE_EVENT_IF = 0x0001
ROUTE_EVENT_IPTABLE = 0x0002
ROUTE_EVENT_DROP = 0x0004
ROUTE_EVENT_NEW = 0x0010
FUNCNAME_MAX_LEN = 64

class TestEvt(ct.Structure):
    _fields_ = [
        ("func_name",   ct.c_char * FUNCNAME_MAX_LEN),
        ("flags",       ct.c_ubyte),

        ("ifname",      ct.c_char * IFNAMSIZ),
        ("netns",       ct.c_uint),

        ("dest_mac",    ct.c_ubyte * 6),
        ("len",         ct.c_uint),
        ("ip_version",  ct.c_ubyte),
        ("l4_proto",    ct.c_ubyte),
        ("saddr",       ct.c_ulonglong * 2),
        ("daddr",       ct.c_ulonglong * 2),
        ("icmptype",    ct.c_ubyte),
        ("icmpid",      ct.c_ushort),
        ("icmpseq",     ct.c_ushort),
        ("sport",       ct.c_ushort),
        ("dport",       ct.c_ushort),
        ("tcpflags",    ct.c_ushort),

        ("hook",        ct.c_uint),
        ("pf",          ct.c_ubyte),
        ("verdict",     ct.c_uint),
        ("tablename",   ct.c_char * XT_TABLE_MAXNAMELEN),
        ("ipt_delay",   ct.c_ulonglong),

        ("skb",         ct.c_ulonglong),
        ("pkt_type",    ct.c_ubyte),

	("kernel_stack_id", ct.c_int),
	("kernel_ip",   ct.c_ulonglong),

	("start_ns",    ct.c_ulonglong),
	("test",        ct.c_ulonglong)
    ]


def _get(l, index, default):
    '''
    Get element at index in l or return the default
    '''
    if index < len(l):
        return l[index]
    return default
def _get_tcpflags(tcpflags):
    flag=""
    start=1
    for index in range(len(TCPFLAGS)):
        if (tcpflags & (1<<index)):
            if start:
                flag += TCPFLAGS[index]
                start = 0
            else:
                flag += ","+TCPFLAGS[index]
    return flag


def print_stack(event):
    user_stack = []
    stack_traces = b.get_table("stacks")

    kernel_stack = []
    if event.kernel_stack_id > 0:
        kernel_tmp = stack_traces.walk(event.kernel_stack_id)
        # fix kernel stack
        for addr in kernel_tmp:
            kernel_stack.append(addr)
    for addr in kernel_stack:
        print(("    %s" % b.ksym(addr)))

earliest_ts = 0
def time_str(event):
    if args.timestamp:
        global earliest_ts
        if earliest_ts == 0:
            earliest_ts = event.start_ns
        return "%-7.6f " % ((event.start_ns - earliest_ts) / 1000000000.0)
    elif args.time:
        return "%-7s " % time.strftime("%H:%M:%S")
    else:
        return "%-7s " % time.strftime("%H:%M:%S")

def event_printer(cpu, data, size):
    # Decode event
    event = ct.cast(data, ct.POINTER(TestEvt)).contents

    if event.ip_version == 4:
        saddr = inet_ntop(AF_INET, pack("=I", event.saddr[0]))
        daddr = inet_ntop(AF_INET, pack("=I", event.daddr[0]))
    elif event.ip_version == 6:
        saddr = inet_ntop(AF_INET6, event.saddr)
        daddr = inet_ntop(AF_INET6, event.daddr)
    else:
        return

    mac_info = ''.join('%02x' % b for b in event.dest_mac)

    if event.l4_proto == socket.IPPROTO_TCP:
        pkt_info = "T_%s:%s:%u->%s:%u" % (_get_tcpflags(event.tcpflags), saddr, event.sport, daddr, event.dport)
    elif event.l4_proto == socket.IPPROTO_UDP:
        pkt_info = "U:%s:%u->%s:%u" % (saddr, event.sport, daddr, event.dport)
    elif event.l4_proto == socket.IPPROTO_ICMP:
        if event.icmptype in [8, 128]:
            pkt_info = "I_request:%s->%s" % (saddr, daddr)
        elif event.icmptype in [0, 129]:
            pkt_info = "I_reply:%s->%s" % (saddr, daddr)
        else:
            pkt_info = "I:%s->%s" % (saddr, daddr)
    else:
        pkt_info = "%u:%s->%s" % (event.l4_proto, saddr, daddr)

    iptables = ""
    if event.flags & ROUTE_EVENT_IPTABLE == ROUTE_EVENT_IPTABLE:
        verdict = _get(NF_VERDICT_NAME, event.verdict, "~UNK~")
        hook = _get(HOOKNAMES, event.hook, "~UNK~")
        iptables = "%u.%s.%s.%s " % (event.pf, event.tablename, hook, verdict)

    trace_info = "%x.%u:%s%s" % (event.skb, event.pkt_type, iptables, event.func_name)

    # Print event
    print("[%-8s][%-10s] %-12s %-12s %-40s %s" % (time_str(event), event.netns, event.ifname, mac_info, pkt_info, trace_info))
    print_stack(event)
    args.catch_count = args.catch_count - 1
    if args.catch_count <= 0:
        sys.exit(0)

if __name__ == "__main__":
    b = BPF(text=bpf_text)
    b["route_event"].open_perf_buffer(event_printer)

    print("%-10s %-12s %-12s %-12s %-40s %s" % ('time', 'NETWORK_NS', 'INTERFACE', 'DEST_MAC', 'PKT_INFO', 'TRACE_INFO'))

    try:
        while True:
            b.kprobe_poll(10)
    except KeyboardInterrupt:
        sys.exit(0)