# 通过内核模块获取 tcphash_info 信息

## 介绍

在网络问题排查的过程中，有时候需要了解内核中保存的 tcphash_info 信息，仅仅通过 BPF 还是缺少更加细致的分析，这种情况下可以通过 kernel 模块访问到 tcphash_info 的结构体，由于是遍历会获取 lock，因此只能用于学习。

如果在生产环境排查问题，具体的写法可以参考 `__inet_lookup_established` 函数，通过参入 5 元组来进行读取，避免整个遍历带来的性能开销。

```c
static inline struct sock *
	inet_lookup_established(struct net *net, struct inet_hashinfo *hashinfo,
				const __be32 saddr, const __be16 sport,
				const __be32 daddr, const __be16 dport,
				const int dif)
{
	return __inet_lookup_established(net, hashinfo, saddr, sport, daddr,
					 ntohs(dport), dif);
}

struct sock *__inet_lookup_established(struct net *net,
				  struct inet_hashinfo *hashinfo,
				  const __be32 saddr, const __be16 sport,
				  const __be32 daddr, const u16 hnum,
				  const int dif)
{
	INET_ADDR_COOKIE(acookie, saddr, daddr)
	const __portpair ports = INET_COMBINED_PORTS(sport, hnum);
	struct sock *sk;
	const struct hlist_nulls_node *node;
	/* Optimize here for direct hit, only listening connections can
	 * have wildcards anyways.
	 */
	unsigned int hash = inet_ehashfn(net, daddr, hnum, saddr, sport);
	unsigned int slot = hash & hashinfo->ehash_mask;
	struct inet_ehash_bucket *head = &hashinfo->ehash[slot];

	rcu_read_lock();
begin:
	sk_nulls_for_each_rcu(sk, node, &head->chain) {
		if (sk->sk_hash != hash)
			continue;
		if (likely(INET_MATCH(sk, net, acookie,
				      saddr, daddr, ports, dif))) {
			if (unlikely(!atomic_inc_not_zero(&sk->sk_refcnt)))
				goto out;
			if (unlikely(!INET_MATCH(sk, net, acookie,
						 saddr, daddr, ports, dif))) {
				sock_gen_put(sk);
				goto begin;
			}
			goto found;
		}
	}
	/*
	 * if the nulls value we got at the end of this lookup is
	 * not the expected one, we must restart lookup.
	 * We probably met an item that was moved to another chain.
	 */
	if (get_nulls_value(node) != slot)
		goto begin;
out:
	sk = NULL;
found:
	rcu_read_unlock();
	return sk;
}
EXPORT_SYMBOL_GPL(__inet_lookup_established);
```



## 使用

```bash
# make
# inmod tcphash.ko
# dmesg -T
...
[Wed Jan 27 16:57:30 2021] --- Established ---
[Wed Jan 27 16:57:30 2021] 89.30.135.163:512 ---> 100.100.120.13:80
[Wed Jan 27 16:57:30 2021] 0.0.0.0:0 ---> 127.0.0.1:9099
[Wed Jan 27 16:57:30 2021] 162.216.6.93:512 ---> 100.100.120.57:80
[Wed Jan 27 16:57:30 2021] 3.136.144.7:8307 ---> 100.100.105.70:80
[Wed Jan 27 16:57:30 2021] 178.13.170.109:512 ---> 100.100.105.70:80

# rmmode tcphash
```

## 其他
关于 `tcp_rcv.py` 文件是我排查 tcp_reset 过程中使用的脚本，分析过程中有比较多的干扰因素，因此我在代码中写死了源地址和目标端口，实现思路仅供参考，不是能够按照帮助说明自由组合的脚本，因为有些函数返回值不同。

