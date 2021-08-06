#!/usr/bin/python

from bcc import BPF

text="""

#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME "bcc"
#endif
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/ip.h>
#include <uapi/linux/bpf.h>

#include "linux/netdev_features.h"

static inline bool net_gso_ok2(netdev_features_t features, int gso_type)
{
    netdev_features_t feature = gso_type << NETIF_F_GSO_SHIFT;

    return (features & feature) == feature;
}

int  kretprobe__tcp_current_mss(struct pt_regs *ctx) {
	struct sock *sk = (void *)PT_REGS_PARM1(ctx);
	u32 mss = PT_REGS_RC(ctx);

	bool can_gso = net_gso_ok(sk->sk_route_caps, sk->sk_gso_type);

	if (!sk) {
		return 0;
	}

	bpf_trace_printk("mss: %d, can gso %d\\n", mss, can_gso);

	return 0;
}
"""

BPF(text=text).trace_print()
