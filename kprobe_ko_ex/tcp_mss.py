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

int  kretprobe__tcp_current_mss(struct pt_regs *ctx) {
	struct sock *sk = (void *)PT_REGS_PARM1(ctx);
	u32 mss = PT_REGS_RC(ctx);

	if (!sk) {
		return 0;
	}

	bpf_trace_printk("sk 0x%lx mss: %d\\n", sk, mss);

	return 0;
}
"""

BPF(text=text).trace_print()
