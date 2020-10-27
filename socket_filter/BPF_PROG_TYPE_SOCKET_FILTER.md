# BPF_PROG_TYPE_SOCKET_FILTER

[toc]

```bash
✗ ls -hl sockex*
-rw-r--r--  1 dwh0403  staff   661B Sep 21 22:22 sockex1_kern.c
-rw-r--r--  1 dwh0403  staff   1.1K Sep 21 22:22 sockex1_user.c
-rw-r--r--  1 dwh0403  staff   4.8K Sep 21 22:22 sockex2_kern.c
-rw-r--r--  1 dwh0403  staff   1.2K Sep 21 22:22 sockex2_user.c
-rw-r--r--  1 dwh0403  staff   6.1K Sep 21 22:22 sockex3_kern.c
-rw-r--r--  1 dwh0403  staff   2.5K Sep 21 22:22 sockex3_user.c
```

该程序类型可以访问的函数列表如下，参见 https://github.com/DavadDi/bpf_study/blob/master/bpf-prog-type.md

| `BPF_PROG_TYPE_SOCKET_FILTER` | `BPF_FUNC_skb_load_bytes()` <br />`BPF_FUNC_skb_load_bytes_relative()` <br />`BPF_FUNC_get_socket_cookie()`<br /> `BPF_FUNC_get_socket_uid()` <br />`BPF_FUNC_perf_event_output()` <br />`Base functions` |
| ----------------------------- | ------------------------------------------------------------ |
|                               |                                                              |
`Base functions` 分组

| `Base functions` | `BPF_FUNC_map_lookup_elem()` <br />`BPF_FUNC_map_update_elem()` <br />`BPF_FUNC_map_delete_elem()`<br /> `BPF_FUNC_map_peek_elem()` <br />`BPF_FUNC_map_pop_elem()`<br /> `BPF_FUNC_map_push_elem()` <br />`BPF_FUNC_get_prandom_u32()`<br /> `BPF_FUNC_get_smp_processor_id()`<br /> `BPF_FUNC_get_numa_node_id()`<br /> `BPF_FUNC_tail_call()`<br /> `BPF_FUNC_ktime_get_boot_ns()`<br /> `BPF_FUNC_ktime_get_ns()` <br />`BPF_FUNC_trace_printk()` <br />`BPF_FUNC_spin_lock()`<br />`BPF_FUNC_spin_unlock()` |
| ---------------- | ------------------------------------------------------------ |
|                  |                                                              |

最简单的样例 sock_example.c

```c
/* eBPF example program:
 * - creates arraymap in kernel with key 4 bytes and value 8 bytes
 *
 * - loads eBPF program:
 *   r0 = skb->data[ETH_HLEN + offsetof(struct iphdr, protocol)];
 *   *(u32*)(fp - 4) = r0;
 *   // assuming packet is IPv4, lookup ip->proto in a map
 *   value = bpf_map_lookup_elem(map_fd, fp - 4);
 *   if (value)
 *        (*(u64*)value) += 1;
 *
 * - attaches this program to loopback interface "lo" raw socket
 *
 * - every second user space reads map[tcp], map[udp], map[icmp] to see
 *   how many packets of given protocol were seen on "lo"
 */
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <linux/bpf.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <stddef.h>
#include <bpf/bpf.h>
#include "bpf_insn.h"
#include "sock_example.h"

char bpf_log_buf[BPF_LOG_BUF_SIZE];

static int test_sock(void)
{
	int sock = -1, map_fd, prog_fd, i, key;
	long long value = 0, tcp_cnt, udp_cnt, icmp_cnt;

	map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(key), sizeof(value),
				256, 0);
	if (map_fd < 0) {
		printf("failed to create map '%s'\n", strerror(errno));
		goto cleanup;
	}

	struct bpf_insn prog[] = {
		BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
		BPF_LD_ABS(BPF_B, ETH_HLEN + offsetof(struct iphdr, protocol) /* R0 = ip->proto */),
		BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4), /* *(u32 *)(fp - 4) = r0 */
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4), /* r2 = fp - 4 */
		BPF_LD_MAP_FD(BPF_REG_1, map_fd),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),
		BPF_MOV64_IMM(BPF_REG_1, 1), /* r1 = 1 */
		BPF_RAW_INSN(BPF_STX | BPF_XADD | BPF_DW, BPF_REG_0, BPF_REG_1, 0, 0), /* xadd r0 += r1 */
		BPF_MOV64_IMM(BPF_REG_0, 0), /* r0 = 0 */
		BPF_EXIT_INSN(),
	};
	size_t insns_cnt = sizeof(prog) / sizeof(struct bpf_insn);

	prog_fd = bpf_load_program(BPF_PROG_TYPE_SOCKET_FILTER, prog, insns_cnt,
				   "GPL", 0, bpf_log_buf, BPF_LOG_BUF_SIZE);
	if (prog_fd < 0) {
		printf("failed to load prog '%s'\n", strerror(errno));
		goto cleanup;
	}

	sock = open_raw_sock("lo"); // 在所有网卡上添加？ tcpdump -i any

	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd,
		       sizeof(prog_fd)) < 0) {
		printf("setsockopt %s\n", strerror(errno));
		goto cleanup;
	}

	for (i = 0; i < 10; i++) {
		key = IPPROTO_TCP;
		assert(bpf_map_lookup_elem(map_fd, &key, &tcp_cnt) == 0);

		key = IPPROTO_UDP;
		assert(bpf_map_lookup_elem(map_fd, &key, &udp_cnt) == 0);

		key = IPPROTO_ICMP;
		assert(bpf_map_lookup_elem(map_fd, &key, &icmp_cnt) == 0);

		printf("TCP %lld UDP %lld ICMP %lld packets\n",
		       tcp_cnt, udp_cnt, icmp_cnt);
		sleep(1);
	}

cleanup:
	/* maps, programs, raw sockets will auto cleanup on process exit */
	return 0;
}

int main(void)
{
	FILE *f;

	f = popen("ping -c5 localhost", "r");
	(void)f;

	return test_sock();
}
```



## 1. 基于协议的出口流量统计

sockex1_kern.c

```c
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <bpf/bpf_helpers.h>
#include "bpf_legacy.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, long);
	__uint(max_entries, 256);
} my_map SEC(".maps");

SEC("socket1")
int bpf_prog1(struct __sk_buff *skb)
{
	int index = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
	long *value;

	if (skb->pkt_type != PACKET_OUTGOING)
		return 0;

	value = bpf_map_lookup_elem(&my_map, &index);
	if (value)
		__sync_fetch_and_add(value, skb->len); // 同步获取并同步更新

	return 0;
}
char _license[] SEC("license") = "GPL";
```

sockex1_user.c

```c
// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <assert.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "sock_example.h"
#include <unistd.h>
#include <arpa/inet.h>

int main(int ac, char **argv)
{
	struct bpf_object *obj;
	int map_fd, prog_fd;
	char filename[256];
	int i, sock;
	FILE *f;

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	if (bpf_prog_load(filename, BPF_PROG_TYPE_SOCKET_FILTER,
			  &obj, &prog_fd))
		return 1;

	map_fd = bpf_object__find_map_fd_by_name(obj, "my_map");

	sock = open_raw_sock("lo");

	assert(setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd,
			  sizeof(prog_fd)) == 0);

	f = popen("ping -4 -c5 localhost", "r");
	(void) f;

	for (i = 0; i < 5; i++) {
		long long tcp_cnt, udp_cnt, icmp_cnt;
		int key;

		key = IPPROTO_TCP;
		assert(bpf_map_lookup_elem(map_fd, &key, &tcp_cnt) == 0);

		key = IPPROTO_UDP;
		assert(bpf_map_lookup_elem(map_fd, &key, &udp_cnt) == 0);

		key = IPPROTO_ICMP;
		assert(bpf_map_lookup_elem(map_fd, &key, &icmp_cnt) == 0);

		printf("TCP %lld UDP %lld ICMP %lld bytes\n",
		       tcp_cnt, udp_cnt, icmp_cnt);
		sleep(1);
	}

	return 0;
}
```

运行结果

```bash
./sockex1
TCP 0 UDP 0 ICMP 0 bytes
```



## 2. 基于 IP 地址的流量统计

sockex2_kern.c 

```c
#include <uapi/linux/bpf.h>
#include <uapi/linux/in.h>
#include <uapi/linux/if.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/if_tunnel.h>
#include <bpf/bpf_helpers.h>
#include "bpf_legacy.h"
#define IP_MF		0x2000
#define IP_OFFSET	0x1FFF

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

struct flow_key_record {
	__be32 src;
	__be32 dst;
	union {
		__be32 ports;
		__be16 port16[2];
	};
	__u16 thoff;
	__u8 ip_proto;
};

static inline int proto_ports_offset(__u64 proto)
{
	switch (proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_DCCP:
	case IPPROTO_ESP:
	case IPPROTO_SCTP:
	case IPPROTO_UDPLITE:
		return 0;
	case IPPROTO_AH:
		return 4;
	default:
		return 0;
	}
}

static inline int ip_is_fragment(struct __sk_buff *ctx, __u64 nhoff)
{
	return load_half(ctx, nhoff + offsetof(struct iphdr, frag_off))
		& (IP_MF | IP_OFFSET);
}

static inline __u32 ipv6_addr_hash(struct __sk_buff *ctx, __u64 off)
{
	__u64 w0 = load_word(ctx, off);
	__u64 w1 = load_word(ctx, off + 4);
	__u64 w2 = load_word(ctx, off + 8);
	__u64 w3 = load_word(ctx, off + 12);

	return (__u32)(w0 ^ w1 ^ w2 ^ w3);
}

static inline __u64 parse_ip(struct __sk_buff *skb, __u64 nhoff, __u64 *ip_proto,
			     struct flow_key_record *flow)
{
	__u64 verlen;

	if (unlikely(ip_is_fragment(skb, nhoff)))
		*ip_proto = 0;
	else
		*ip_proto = load_byte(skb, nhoff + offsetof(struct iphdr, protocol));

	if (*ip_proto != IPPROTO_GRE) {
		flow->src = load_word(skb, nhoff + offsetof(struct iphdr, saddr));
		flow->dst = load_word(skb, nhoff + offsetof(struct iphdr, daddr));
	}

	verlen = load_byte(skb, nhoff + 0/*offsetof(struct iphdr, ihl)*/);
	if (likely(verlen == 0x45))
		nhoff += 20;
	else
		nhoff += (verlen & 0xF) << 2;

	return nhoff;
}

static inline __u64 parse_ipv6(struct __sk_buff *skb, __u64 nhoff, __u64 *ip_proto,
			       struct flow_key_record *flow)
{
	*ip_proto = load_byte(skb,
			      nhoff + offsetof(struct ipv6hdr, nexthdr));
	flow->src = ipv6_addr_hash(skb,
				   nhoff + offsetof(struct ipv6hdr, saddr));
	flow->dst = ipv6_addr_hash(skb,
				   nhoff + offsetof(struct ipv6hdr, daddr));
	nhoff += sizeof(struct ipv6hdr);

	return nhoff;
}

static inline bool flow_dissector(struct __sk_buff *skb,
				  struct flow_key_record *flow)
{
	__u64 nhoff = ETH_HLEN;
	__u64 ip_proto;
	__u64 proto = load_half(skb, 12);
	int poff;

	if (proto == ETH_P_8021AD) {
		proto = load_half(skb, nhoff + offsetof(struct vlan_hdr,
							h_vlan_encapsulated_proto));
		nhoff += sizeof(struct vlan_hdr);
	}

	if (proto == ETH_P_8021Q) {
		proto = load_half(skb, nhoff + offsetof(struct vlan_hdr,
							h_vlan_encapsulated_proto));
		nhoff += sizeof(struct vlan_hdr);
	}

	if (likely(proto == ETH_P_IP))
		nhoff = parse_ip(skb, nhoff, &ip_proto, flow);
	else if (proto == ETH_P_IPV6)
		nhoff = parse_ipv6(skb, nhoff, &ip_proto, flow);
	else
		return false;

	switch (ip_proto) {
	case IPPROTO_GRE: {
		struct gre_hdr {
			__be16 flags;
			__be16 proto;
		};

		__u64 gre_flags = load_half(skb,
					    nhoff + offsetof(struct gre_hdr, flags));
		__u64 gre_proto = load_half(skb,
					    nhoff + offsetof(struct gre_hdr, proto));

		if (gre_flags & (GRE_VERSION|GRE_ROUTING))
			break;

		proto = gre_proto;
		nhoff += 4;
		if (gre_flags & GRE_CSUM)
			nhoff += 4;
		if (gre_flags & GRE_KEY)
			nhoff += 4;
		if (gre_flags & GRE_SEQ)
			nhoff += 4;

		if (proto == ETH_P_8021Q) {
			proto = load_half(skb,
					  nhoff + offsetof(struct vlan_hdr,
							   h_vlan_encapsulated_proto));
			nhoff += sizeof(struct vlan_hdr);
		}

		if (proto == ETH_P_IP)
			nhoff = parse_ip(skb, nhoff, &ip_proto, flow);
		else if (proto == ETH_P_IPV6)
			nhoff = parse_ipv6(skb, nhoff, &ip_proto, flow);
		else
			return false;
		break;
	}
	case IPPROTO_IPIP:
		nhoff = parse_ip(skb, nhoff, &ip_proto, flow);
		break;
	case IPPROTO_IPV6:
		nhoff = parse_ipv6(skb, nhoff, &ip_proto, flow);
		break;
	default:
		break;
	}

	flow->ip_proto = ip_proto;
	poff = proto_ports_offset(ip_proto);
	if (poff >= 0) {
		nhoff += poff;
		flow->ports = load_word(skb, nhoff);
	}

	flow->thoff = (__u16) nhoff;

	return true;
}

struct pair {
	long packets;
	long bytes;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __be32);
	__type(value, struct pair);
	__uint(max_entries, 1024);
} hash_map SEC(".maps");

SEC("socket2")
int bpf_prog2(struct __sk_buff *skb)
{
	struct flow_key_record flow = {};
	struct pair *value;
	u32 key;

	if (!flow_dissector(skb, &flow))
		return 0;

	key = flow.dst;
	value = bpf_map_lookup_elem(&hash_map, &key);
	if (value) {
		__sync_fetch_and_add(&value->packets, 1);
		__sync_fetch_and_add(&value->bytes, skb->len);
	} else {
		struct pair val = {1, skb->len};

		bpf_map_update_elem(&hash_map, &key, &val, BPF_ANY);
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
```

sockex2_user.c

```c
// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <assert.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "sock_example.h"
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/resource.h>

struct pair {
	__u64 packets;
	__u64 bytes;
};

int main(int ac, char **argv)
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	struct bpf_object *obj;
	int map_fd, prog_fd;
	char filename[256];
	int i, sock;
	FILE *f;

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	setrlimit(RLIMIT_MEMLOCK, &r);

	if (bpf_prog_load(filename, BPF_PROG_TYPE_SOCKET_FILTER,
			  &obj, &prog_fd))
		return 1;

	map_fd = bpf_object__find_map_fd_by_name(obj, "hash_map");

	sock = open_raw_sock("lo");

	assert(setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd,
			  sizeof(prog_fd)) == 0);

	f = popen("ping -4 -c5 localhost", "r");
	(void) f;

	for (i = 0; i < 5; i++) {
		int key = 0, next_key;
		struct pair value;

		while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
			bpf_map_lookup_elem(map_fd, &next_key, &value);
			printf("ip %s bytes %lld packets %lld\n",
			       inet_ntoa((struct in_addr){htonl(next_key)}),
			       value.bytes, value.packets);
			key = next_key;
		}
		sleep(1);
	}
	return 0;
}
```

运行结果

```bash
#./sockex2
ip 0.0.0.1 bytes 472 packets 4
ip 0.0.0.1 bytes 944 packets 8
ip 0.0.0.1 bytes 1416 packets 12
ip 0.0.0.1 bytes 1888 packets 16
```



## 3. 基于源 IP + 目的 IP 端口统计

sockex3_kern.c

```c
/* Copyright (c) 2015 PLUMgrid, http://plumgrid.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include <uapi/linux/bpf.h>
#include <uapi/linux/in.h>
#include <uapi/linux/if.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/if_tunnel.h>
#include <uapi/linux/mpls.h>
#include <bpf/bpf_helpers.h>
#include "bpf_legacy.h"
#define IP_MF		0x2000
#define IP_OFFSET	0x1FFF

#define PROG(F) SEC("socket/"__stringify(F)) int bpf_func_##F

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 8);
} jmp_table SEC(".maps");

#define PARSE_VLAN 1
#define PARSE_MPLS 2
#define PARSE_IP 3
#define PARSE_IPV6 4

/* protocol dispatch routine.
 * It tail-calls next BPF program depending on eth proto
 * Note, we could have used:
 * bpf_tail_call(skb, &jmp_table, proto);
 * but it would need large prog_array
 */
static inline void parse_eth_proto(struct __sk_buff *skb, u32 proto)
{
	switch (proto) {
	case ETH_P_8021Q:
	case ETH_P_8021AD:
		bpf_tail_call(skb, &jmp_table, PARSE_VLAN);
		break;
	case ETH_P_MPLS_UC:
	case ETH_P_MPLS_MC:
		bpf_tail_call(skb, &jmp_table, PARSE_MPLS);
		break;
	case ETH_P_IP:
		bpf_tail_call(skb, &jmp_table, PARSE_IP);
		break;
	case ETH_P_IPV6:
		bpf_tail_call(skb, &jmp_table, PARSE_IPV6);
		break;
	}
}

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

struct flow_key_record {
	__be32 src;
	__be32 dst;
	union {
		__be32 ports;
		__be16 port16[2];
	};
	__u32 ip_proto;
};

static inline int ip_is_fragment(struct __sk_buff *ctx, __u64 nhoff)
{
	return load_half(ctx, nhoff + offsetof(struct iphdr, frag_off))
		& (IP_MF | IP_OFFSET);
}

static inline __u32 ipv6_addr_hash(struct __sk_buff *ctx, __u64 off)
{
	__u64 w0 = load_word(ctx, off);
	__u64 w1 = load_word(ctx, off + 4);
	__u64 w2 = load_word(ctx, off + 8);
	__u64 w3 = load_word(ctx, off + 12);

	return (__u32)(w0 ^ w1 ^ w2 ^ w3);
}

struct globals {
	struct flow_key_record flow;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct globals);
	__uint(max_entries, 32);
} percpu_map SEC(".maps");

/* user poor man's per_cpu until native support is ready */
static struct globals *this_cpu_globals(void)
{
	u32 key = bpf_get_smp_processor_id();

	return bpf_map_lookup_elem(&percpu_map, &key);
}

/* some simple stats for user space consumption */
struct pair {
	__u64 packets;
	__u64 bytes;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct flow_key_record);
	__type(value, struct pair);
	__uint(max_entries, 1024);
} hash_map SEC(".maps");

static void update_stats(struct __sk_buff *skb, struct globals *g)
{
	struct flow_key_record key = g->flow;
	struct pair *value;

	value = bpf_map_lookup_elem(&hash_map, &key);
	if (value) {
		__sync_fetch_and_add(&value->packets, 1);
		__sync_fetch_and_add(&value->bytes, skb->len);
	} else {
		struct pair val = {1, skb->len};

		bpf_map_update_elem(&hash_map, &key, &val, BPF_ANY);
	}
}

static __always_inline void parse_ip_proto(struct __sk_buff *skb,
					   struct globals *g, __u32 ip_proto)
{
	__u32 nhoff = skb->cb[0];
	int poff;

	switch (ip_proto) {
	case IPPROTO_GRE: {
		struct gre_hdr {
			__be16 flags;
			__be16 proto;
		};

		__u32 gre_flags = load_half(skb,
					    nhoff + offsetof(struct gre_hdr, flags));
		__u32 gre_proto = load_half(skb,
					    nhoff + offsetof(struct gre_hdr, proto));

		if (gre_flags & (GRE_VERSION|GRE_ROUTING))
			break;

		nhoff += 4;
		if (gre_flags & GRE_CSUM)
			nhoff += 4;
		if (gre_flags & GRE_KEY)
			nhoff += 4;
		if (gre_flags & GRE_SEQ)
			nhoff += 4;

		skb->cb[0] = nhoff;
		parse_eth_proto(skb, gre_proto);
		break;
	}
	case IPPROTO_IPIP:
		parse_eth_proto(skb, ETH_P_IP);
		break;
	case IPPROTO_IPV6:
		parse_eth_proto(skb, ETH_P_IPV6);
		break;
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		g->flow.ports = load_word(skb, nhoff);
	case IPPROTO_ICMP:
		g->flow.ip_proto = ip_proto;
		update_stats(skb, g);
		break;
	default:
		break;
	}
}

PROG(PARSE_IP)(struct __sk_buff *skb)
{
	struct globals *g = this_cpu_globals();
	__u32 nhoff, verlen, ip_proto;

	if (!g)
		return 0;

	nhoff = skb->cb[0];

	if (unlikely(ip_is_fragment(skb, nhoff)))
		return 0;

	ip_proto = load_byte(skb, nhoff + offsetof(struct iphdr, protocol));

	if (ip_proto != IPPROTO_GRE) {
		g->flow.src = load_word(skb, nhoff + offsetof(struct iphdr, saddr));
		g->flow.dst = load_word(skb, nhoff + offsetof(struct iphdr, daddr));
	}

	verlen = load_byte(skb, nhoff + 0/*offsetof(struct iphdr, ihl)*/);
	nhoff += (verlen & 0xF) << 2;

	skb->cb[0] = nhoff;
	parse_ip_proto(skb, g, ip_proto);
	return 0;
}

PROG(PARSE_IPV6)(struct __sk_buff *skb)
{
	struct globals *g = this_cpu_globals();
	__u32 nhoff, ip_proto;

	if (!g)
		return 0;

	nhoff = skb->cb[0];

	ip_proto = load_byte(skb,
			     nhoff + offsetof(struct ipv6hdr, nexthdr));
	g->flow.src = ipv6_addr_hash(skb,
				     nhoff + offsetof(struct ipv6hdr, saddr));
	g->flow.dst = ipv6_addr_hash(skb,
				     nhoff + offsetof(struct ipv6hdr, daddr));
	nhoff += sizeof(struct ipv6hdr);

	skb->cb[0] = nhoff;
	parse_ip_proto(skb, g, ip_proto);
	return 0;
}

PROG(PARSE_VLAN)(struct __sk_buff *skb)
{
	__u32 nhoff, proto;

	nhoff = skb->cb[0];

	proto = load_half(skb, nhoff + offsetof(struct vlan_hdr,
						h_vlan_encapsulated_proto));
	nhoff += sizeof(struct vlan_hdr);
	skb->cb[0] = nhoff;

	parse_eth_proto(skb, proto);

	return 0;
}

PROG(PARSE_MPLS)(struct __sk_buff *skb)
{
	__u32 nhoff, label;

	nhoff = skb->cb[0];

	label = load_word(skb, nhoff);
	nhoff += sizeof(struct mpls_label);
	skb->cb[0] = nhoff;

	if (label & MPLS_LS_S_MASK) {
		__u8 verlen = load_byte(skb, nhoff);
		if ((verlen & 0xF0) == 4)
			parse_eth_proto(skb, ETH_P_IP);
		else
			parse_eth_proto(skb, ETH_P_IPV6);
	} else {
		parse_eth_proto(skb, ETH_P_MPLS_UC);
	}

	return 0;
}

SEC("socket/0")
int main_prog(struct __sk_buff *skb)
{
	__u32 nhoff = ETH_HLEN;
	__u32 proto = load_half(skb, 12);

	skb->cb[0] = nhoff;
	parse_eth_proto(skb, proto);
	return 0;
}

char _license[] SEC("license") = "GPL";
```

sockex3_user.c

```c
// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "sock_example.h"
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/resource.h>

struct flow_key_record {
	__be32 src;
	__be32 dst;
	union {
		__be32 ports;
		__be16 port16[2];
	};
	__u32 ip_proto;
};

struct pair {
	__u64 packets;
	__u64 bytes;
};

int main(int argc, char **argv)
{
	int i, sock, key, fd, main_prog_fd, jmp_table_fd, hash_map_fd;
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	struct bpf_program *prog;
	struct bpf_object *obj;
	char filename[256];
	const char *title;
	FILE *f;

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	setrlimit(RLIMIT_MEMLOCK, &r);

	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		return 0;
	}

	/* load BPF program */
	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}

	jmp_table_fd = bpf_object__find_map_fd_by_name(obj, "jmp_table");
	hash_map_fd = bpf_object__find_map_fd_by_name(obj, "hash_map");
	if (jmp_table_fd < 0 || hash_map_fd < 0) {
		fprintf(stderr, "ERROR: finding a map in obj file failed\n");
		goto cleanup;
	}

	bpf_object__for_each_program(prog, obj) {
		fd = bpf_program__fd(prog);

		title = bpf_program__title(prog, false);
		if (sscanf(title, "socket/%d", &key) != 1) {
			fprintf(stderr, "ERROR: finding prog failed\n");
			goto cleanup;
		}

		if (key == 0)
			main_prog_fd = fd;
		else
			bpf_map_update_elem(jmp_table_fd, &key, &fd, BPF_ANY);
	}

	sock = open_raw_sock("lo");

	/* attach BPF program to socket */
	assert(setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &main_prog_fd,
			  sizeof(__u32)) == 0);

	if (argc > 1)
		f = popen("ping -4 -c5 localhost", "r");
	else
		f = popen("netperf -l 4 localhost", "r");
	(void) f;

	for (i = 0; i < 5; i++) {
		struct flow_key_record key = {}, next_key;
		struct pair value;

		sleep(1);
		printf("IP     src.port -> dst.port               bytes      packets\n");
		while (bpf_map_get_next_key(hash_map_fd, &key, &next_key) == 0) {
			bpf_map_lookup_elem(hash_map_fd, &next_key, &value);
			printf("%s.%05d -> %s.%05d %12lld %12lld\n",
			       inet_ntoa((struct in_addr){htonl(next_key.src)}),
			       next_key.port16[0],
			       inet_ntoa((struct in_addr){htonl(next_key.dst)}),
			       next_key.port16[1],
			       value.bytes, value.packets);
			key = next_key;
		}
	}

cleanup:
	bpf_object__close(obj);
	return 0;
}
```

最终运行结果如下

```bash
# 依赖于 netperf
# wget http://repo.iotti.biz/CentOS/7/x86_64/netperf-2.7.0-1.el7.lux.x86_64.rpm
# rpm -ivh netperf-2.7.0-1.el7.lux.x86_64.rpm
#./sockex3
IP     src.port -> dst.port               bytes      packets
127.0.0.1.12865 -> 127.0.0.1.48537          148            2
127.0.0.1.48537 -> 127.0.0.1.12865          108            2
```



## 4. 内核中的结构

### 创建 socket-raw

```
sock = open_raw_sock("lo");
```

open_raw_sock 原型定义如下

```c
static inline int open_raw_sock(const char *name)
{
  // 数据链路层的头信息
  // 更多可以参考 https://www.cnblogs.com/zhangshenghui/p/6097492.html
	struct sockaddr_ll sll;
	int sock;

  // SOCK_DGRAM 不包含链路层头， SOCK_RAW 包含链路层头的完整数据包
  // 如果只要是 IPv4 可以这样写 htons(ETH_P_IP)，其他的还有 ETH_P_ARP 和 ETH_P_IPV6等
  // int socket(int domain, int type, int protocol);
  // protocol 是网络字节序，所以需要使用 htons 进行转换
	sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
	if (sock < 0) {
		printf("cannot create raw socket\n");
		return -1;
	}

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = if_nametoindex(name);  // interface索引，0 匹配所有的网络接口卡 man 3 if_nametoindex
	sll.sll_protocol = htons(ETH_P_ALL);
	if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		printf("bind to %s: %s\n", name, strerror(errno));
		close(sock);
		return -1;
	}

	return sock;
}
```

PF_PACKET 协议是专门用于抓包的，往系统网络层注册一个协议，分为两种方式：

* 通过套接字，打开指定的网卡，然后使用 recvmsg 读取，实际过程需要需要将报文从内核区拷贝到用户区。

* 使用 packet_mmap，使用共享内存方式，在内核空间中分配一块内核缓冲区，然后用户空间程序调用 mmap 映射到用户空间。将接收到的 skb 拷贝到那块内核缓冲区中，这样用户空间的程序就可以直接读到捕获的数据包了。PACKET_MMAP 减少了系统调用，不用 recvmsg 就可以读取到捕获的报文，相比原始套接字 + recvfrom的方式，减少了一次拷贝和一次系统调用。


libpcap 就是采用第二种方式。往外发的包和进来的包都会调到 [net/packet/af_packet.c](https://github.com/torvalds/linux/blob/master/net/packet/af_packet.c) 这个文件里面的 packet_rcv 函数（PACKET_MMAP调用的是 tpacket_rcv() 函数），其中 outgoing 方向（出去的包）会在 dev_queue_xmit_nit 里面遍历 ptype_all 链表进行所有网络协议处理的时候调用到 packet_rcv；incoming 方向（从外面其他机器进来的包）会在 __netif_receive_skb_core 函数里面同样办法遍历 ptype_all 进行处理的时候调用到 packet_rcv。

用两张图分别描述 tcpdump 两种实现方式：原始套接字 + recvfrom 的方式和 pcap_mmap 共享内存方式，包含用户空间和内核空间。

**raw socket + recvfrom的方式**

![image](https://jgsun.github.io/images/posts/network/tcpdump/pcap_recvfrom.png)

**pcap_mmap共享内存方式**

![image](https://jgsun.github.io/images/posts/network/tcpdump/pcap_mmap.png)

### 为 socket 设置 BPF 程序

```c
setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)
__sys_setsockopt
    sock_setsockopt(sock, level, optname, optval,
        sk_attach_bpf(ufd, sk)
            __sk_attach_prog(prog, sk)
```

`setsockopt` 函数完成 sock 与 bpf 程序的关联，在内核 3.19 中添加，提交记录 [`89aa075832b0`](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=89aa075832b0da4402acebd698d0411dcc82d03e)

```bash
introduce new setsockopt() command:

setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd))

where prog_fd was received from syscall bpf(BPF_PROG_LOAD, attr, ...)
and attr->prog_type == BPF_PROG_TYPE_SOCKET_FILTER

setsockopt() calls bpf_prog_get() which increments refcnt of the program,
so it doesn't get unloaded while socket is using the program.

The same eBPF program can be attached to multiple sockets.

User task exit automatically closes socket which calls sk_filter_uncharge()
which decrements refcnt of eBPF program
```

相关文件 net/core/filter.c

```c
1539 int sk_attach_bpf(u32 ufd, struct sock *sk)
1540 {
1541         struct bpf_prog *prog = __get_bpf(ufd, sk);
1542         int err;
1543
1544         if (IS_ERR(prog))
1545                 return PTR_ERR(prog);
1546
1547         err = __sk_attach_prog(prog, sk);
1548         if (err < 0) {
1549                 bpf_prog_put(prog); 
1550                 return err;
1551         }
1552
1553         return 0;
1554 }

1421 static int __sk_attach_prog(struct bpf_prog *prog, struct sock *sk)
1422 {
1423         struct sk_filter *fp, *old_fp;
1424
1425         fp = kmalloc(sizeof(*fp), GFP_KERNEL);
1426         if (!fp)
1427                 return -ENOMEM;
1428
1429         fp->prog = prog;
1430
1431         if (!__sk_filter_charge(sk, fp)) {
1432                 kfree(fp);
1433                 return -ENOMEM;
1434         }
1435         refcount_set(&fp->refcnt, 1);
1436
1437         old_fp = rcu_dereference_protected(sk->sk_filter,
1438                                            lockdep_sock_is_held(sk));
1439         rcu_assign_pointer(sk->sk_filter, fp);
1440
1441         if (old_fp)
1442                 sk_filter_uncharge(sk, old_fp);
1443
1444         return 0;
1445 }
```

`sock` 结构中的 `sk_filter` 字段定义了 bpf prog 相关的信息。

```c
// include/net/sock.h
 346 struct sock {
 347         /*
 						 // ..
 416         struct sk_filter __rcu  *sk_filter;
             // ...
 }

 // include/linux/filter.h
 552 struct sk_filter {
 553         refcount_t      refcnt;
 554         struct rcu_head rcu;
 555         struct bpf_prog *prog;
 556 };
 
 
 521 struct bpf_binary_header {
 522         u32 pages;
 523         u8 image[] __aligned(BPF_IMAGE_ALIGNMENT);
 524 };
 
 // BPF_PROG_RUN(filter, ctx)
 526 struct bpf_prog {
 527         u16                     pages;          /* Number of allocated pages */
 528         u16                     jited:1,        /* Is our filter JIT'ed? */
 529                                 jit_requested:1,/* archs need to JIT the prog */
 530                                 gpl_compatible:1, /* Is filter GPL compatible? */
 531                                 cb_access:1,    /* Is control block accessed? */
 532                                 dst_needed:1,   /* Do we need dst entry? */
 533                                 blinded:1,      /* Was blinded */
 534                                 is_func:1,      /* program is a bpf function */
 535                                 kprobe_override:1, /* Do we override a kprobe? */
 536                                 has_callchain_buf:1, /* callchain buffer allocated? */
 537                                 enforce_expected_attach_type:1; /* Enforce expected_attach_type checking at attach time */
 538         enum bpf_prog_type      type;           /* Type of BPF program */
 539         enum bpf_attach_type    expected_attach_type; /* For some prog types */
 540         u32                     len;            /* Number of filter blocks */
 541         u32                     jited_len;      /* Size of jited insns in bytes */
 542         u8                      tag[BPF_TAG_SIZE];
 543         struct bpf_prog_aux     *aux;           /* Auxiliary fields */
 544         struct sock_fprog_kern  *orig_prog;     /* Original BPF program */
 545         unsigned int            (*bpf_func)(const void *ctx,
 546                                             const struct bpf_insn *insn);
 547         /* Instructions for interpreter */
 548         struct sock_filter      insns[0];
 549         struct bpf_insn         insnsi[];
 550 };
 551
```

`bpf_prog_put` 实现对于 prog 程序的管理，定义在 kernel/bpf/syscall.c

```c
1748 void bpf_prog_put(struct bpf_prog *prog)
1749 {
1750         __bpf_prog_put(prog, true);
1751 }

1714 static void __bpf_prog_put_rcu(struct rcu_head *rcu)
1715 {
1716         struct bpf_prog_aux *aux = container_of(rcu, struct bpf_prog_aux, rcu);
1717
1718         kvfree(aux->func_info);
1719         kfree(aux->func_info_aux);
1720         bpf_prog_uncharge_memlock(aux->prog);
1721         security_bpf_prog_free(aux);
1722         bpf_prog_free(aux->prog);
1723 }
```

### 触发 BPF 程序

触发逻辑 net/packet/af_packet.c，对于出口和入口流量最终都会调用 packet_rcv 函数。

```c
2033 /*
2034  * This function makes lazy skb cloning in hope that most of packets
2035  * are discarded by BPF.
2036  *
2037  * Note tricky part: we DO mangle shared skb! skb->data, skb->len
2038  * and skb->cb are mangled. It works because (and until) packets
2039  * falling here are owned by current CPU. Output packets are cloned
2040  * by dev_queue_xmit_nit(), input packets are processed by net_bh
2041  * sequencially, so that if we return skb to original state on exit,
2042  * we will not harm anyone.
2043  */
2044
2045 static int packet_rcv(struct sk_buff *skb, struct net_device *dev,
2046                       struct packet_type *pt, struct net_device *orig_dev)
2047 {
2048         struct sock *sk;
2049         struct sockaddr_ll *sll;
2050         struct packet_sock *po;
2051         u8 *skb_head = skb->data;
2052         int skb_len = skb->len;
2053         unsigned int snaplen, res;
2054         bool is_drop_n_account = false;
2055
2056         if (skb->pkt_type == PACKET_LOOPBACK)
2057                 goto drop;
2058
2059         sk = pt->af_packet_priv;
2060         po = pkt_sk(sk);
2061
2062         if (!net_eq(dev_net(dev), sock_net(sk)))
2063                 goto drop;
2064
2065         skb->dev = dev;
2066
2067         if (dev->header_ops) {
2068                 /* The device has an explicit notion of ll header,
2069                  * exported to higher levels.
2070                  *
2071                  * Otherwise, the device hides details of its frame
2072                  * structure, so that corresponding packet head is
2073                  * never delivered to user.
2074                  */
2075                 if (sk->sk_type != SOCK_DGRAM)
2076                         skb_push(skb, skb->data - skb_mac_header(skb));
2077                 else if (skb->pkt_type == PACKET_OUTGOING) {
2078                         /* Special case: outgoing packets have ll header at head */
2079                         skb_pull(skb, skb_network_offset(skb));
2080                 }
2081         }
2082
2083         snaplen = skb->len;
2084
2085         res = run_filter(skb, sk, snaplen);  // 调用 sock 上的 BPF Prog
2086         if (!res)
2087                 goto drop_n_restore;
2088         if (snaplen > res)
2089                 snaplen = res;
2090
2091         if (atomic_read(&sk->sk_rmem_alloc) >= sk->sk_rcvbuf)
2092                 goto drop_n_acct;
2093
2094         if (skb_shared(skb)) {
2095                 struct sk_buff *nskb = skb_clone(skb, GFP_ATOMIC);
2096                 if (nskb == NULL)
2097                         goto drop_n_acct;
2098
2099                 if (skb_head != skb->data) {
2100                         skb->data = skb_head;
2101                         skb->len = skb_len;
2102                 }
2103                 consume_skb(skb);
2104                 skb = nskb;
2105         }
2106
2107         sock_skb_cb_check_size(sizeof(*PACKET_SKB_CB(skb)) + MAX_ADDR_LEN - 8);
2108
2109         sll = &PACKET_SKB_CB(skb)->sa.ll;
2110         sll->sll_hatype = dev->type;
2111         sll->sll_pkttype = skb->pkt_type;
2112         if (unlikely(po->origdev))
2113                 sll->sll_ifindex = orig_dev->ifindex;
2114         else
2115                 sll->sll_ifindex = dev->ifindex;
2116
2117         sll->sll_halen = dev_parse_header(skb, sll->sll_addr);
2118
2119         /* sll->sll_family and sll->sll_protocol are set in packet_recvmsg().
2120          * Use their space for storing the original skb length.
2121          */
2122         PACKET_SKB_CB(skb)->sa.origlen = skb->len;
2123
2124         if (pskb_trim(skb, snaplen))
2125                 goto drop_n_acct;
2126
2127         skb_set_owner_r(skb, sk);
2128         skb->dev = NULL;
2129         skb_dst_drop(skb);
2130
2131         /* drop conntrack reference */
2132         nf_reset_ct(skb);
2133
2134         spin_lock(&sk->sk_receive_queue.lock);
2135         po->stats.stats1.tp_packets++;
2136         sock_skb_set_dropcount(sk, skb);
2137         __skb_queue_tail(&sk->sk_receive_queue, skb);
2138         spin_unlock(&sk->sk_receive_queue.lock);
2139         sk->sk_data_ready(sk);
2140         return 0;
2141
2142 drop_n_acct:
2143         is_drop_n_account = true;
2144         atomic_inc(&po->tp_drops);
2145         atomic_inc(&sk->sk_drops);
2146
2147 drop_n_restore:
2148         if (skb_head != skb->data && skb_shared(skb)) {
2149                 skb->data = skb_head;
2150                 skb->len = skb_len;
2151         }
2152 drop:
2153         if (!is_drop_n_account)
2154                 consume_skb(skb);
2155         else
2156                 kfree_skb(skb);
2157         return 0;
2158 }  
  
  
2003 static unsigned int run_filter(struct sk_buff *skb,
2004                                const struct sock *sk,
2005                                unsigned int res)
2006 {
2007         struct sk_filter *filter;
2008
2009         rcu_read_lock();
2010         filter = rcu_dereference(sk->sk_filter);
2011         if (filter != NULL)
2012                 res = bpf_prog_run_clear_cb(filter->prog, skb); // 运行 bpf 程序
2013         rcu_read_unlock();
2014
2015         return res;
2016 }
```



## 参考

* [图解linux tcpdump](https://jgsun.github.io/2019/01/21/linux-tcpdump/)