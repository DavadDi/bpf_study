#include <linux/module.h>             // included for all kernel modules
#include <linux/kernel.h>             // included for KERN_INFO
#include <linux/init.h>               // included for __init and __exit macros
#include <linux/netdevice.h>          // struct net_device
#include <linux/skbuff.h>             // struct sk_buff
#include <linux/socket.h>             // AF_INET
#include <linux/if_ether.h>           // struct ethhdr
#include <linux/ip.h>                 // struct iphdr
#include <linux/tcp.h>                // struct tcphdr
#include <linux/kprobes.h>            // for bpf kprobe/kretprobe


#define MAX_ARGLEN 256
#define MAX_ARGS 20
#define NARGS 6
#define NULL ((void *)0)
typedef unsigned long args_t;


#define MAX_SYMBOL_LEN    64
static char symbol_tcp_conn_request[MAX_SYMBOL_LEN] = "tcp_conn_request";

/* For each probe you need to allocate a kprobe structure */
static struct kprobe kp_request = {
    .symbol_name    = symbol_tcp_conn_request,
};

/* kprobe pre_handler: called just before the probed instruction is executed */
static int kp_request_prehandler(struct kprobe *p, struct pt_regs *ctx)
{
    struct sk_buff *skb;
    struct iphdr *iphdr;
/* https://github.com/iovisor/bcc/blob/949a4e59175da289c2ed3dff1979da20b7aee953/src/cc/export/helpers.h
#elif defined(bpf_target_x86)
#define PT_REGS_PARM1(ctx)	((ctx)->di)
#define PT_REGS_PARM2(ctx)	((ctx)->si)
#define PT_REGS_PARM3(ctx)	((ctx)->dx)
#define PT_REGS_PARM4(ctx)	((ctx)->cx)
#define PT_REGS_PARM5(ctx)	((ctx)->r8)
#define PT_REGS_PARM6(ctx)	((ctx)->r9)
#define PT_REGS_RET(ctx)	((ctx)->sp)
*/
    skb = (void *)((ctx)->cx); // 获取 skb 参数
    iphdr = (struct iphdr *)(skb->head + skb->network_header);

    printk(KERN_INFO "[tcp_conn_request] src %x -> dst %x\n", iphdr->saddr, iphdr->daddr);

    return 0;
}


/*
 *  fault_handler: this is called if an exception is generated for any
 *   instruction within the pre- or post-handler, or when Kprobes
 *    single-steps the probed instruction.
*/
static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
    pr_info("kprobe fault_handler(%s): p->addr = 0x%p, trap #%d\n", p->symbol_name, p->addr, trapnr);
    /* Return 0 because we don't handle the fault. */
    return 0;
}

static int __init probe_init(void)
{
    int ret;
    kp_request.pre_handler = kp_request_prehandler;
    kp_request.fault_handler = handler_fault;

    ret = register_kprobe(&kp_request);
    if (ret < 0) {
        pr_err("register_kprobe tcp_conn_request failed, returned %d\n", ret);
        return ret;
    }

    pr_info("Planted kprobe tcp_conn_request at %p\n", kp_request.addr);
    return 0;
}

static void __exit probe_exit(void)
{
    pr_info("kprobe at %p unregistered\n", kp_request.addr);

    unregister_kprobe(&kp_request);
}

module_init(probe_init);
module_exit(probe_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DWH");
MODULE_DESCRIPTION("A kprobe_test Module");

