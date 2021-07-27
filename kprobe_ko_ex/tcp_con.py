#!/usr/bin/python

from bcc import BPF

text="""
#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME "bcc"
#endif

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <net/ip.h>
#include <uapi/linux/bpf.h>

// see https://github.com/iovisor/bcc/blob/151fe198988ce3ab10964f4fca4401978caa18f1/tools/tcpdrop.py

static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb)
{
    // unstable API. verify logic in ip_hdr() -> skb_network_header().
    return (struct iphdr *)(skb->head + skb->network_header);
}

int kprobe__tcp_conn_request(struct pt_regs *ctx) {
	struct sk_buff  *skb = (void *)PT_REGS_PARM4(ctx);
   	struct iphdr *ip;

	if (skb->protocol == htons(ETH_P_IP)) {
        	ip = skb_to_iphdr(skb);
		bpf_trace_printk("src 0x%x dest 0x%x", ip->saddr, ip->daddr);
    	}

	return 0;
}
"""

BPF(text=text).trace_print()
