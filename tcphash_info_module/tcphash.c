#include <linux/init.h>
#include <linux/module.h>
#include <net/inet_hashtables.h>


#define NIPQUAD(addr) \\
    ((unsigned char *)&addr)[0], \\
    ((unsigned char *)&addr)[1], \\
    ((unsigned char *)&addr)[2], \\
    ((unsigned char *)&addr)[3]

#define NIPQUAD_FMT "%u.%u.%u.%u"


extern struct inet_hashinfo tcp_hashinfo;

/* Decides whether a bucket has any sockets in it. */
static inline bool empty_bucket(int i)
{
    return hlist_nulls_empty(&tcp_hashinfo.ehash[i].chain);
}

void print_tcp_socks(void)
{
    int i = 0;
    struct inet_sock *inet;

    /* Walk hash array and lock each if not empty. */
    printk("--- Established ---");
    for (i = 0; i <= tcp_hashinfo.ehash_mask; i++) {
        struct sock *sk;
        struct hlist_nulls_node *node;
        spinlock_t *lock = inet_ehash_lockp(&tcp_hashinfo, i);

        /* Lockless fast path for the common case of empty buckets */
        if (empty_bucket(i))
            continue;

        spin_lock_bh(lock);
        sk_nulls_for_each(sk, node, &tcp_hashinfo.ehash[i].chain) {
            if (sk->sk_family != PF_INET)
                continue;

            inet = inet_sk(sk);

            printk("%u.%u.%u.%u:%hu ---> %u.%u.%u.%u:%hu\n",
    		 ((unsigned char *)&inet->inet_saddr)[0], 
   		 ((unsigned char *)&inet->inet_saddr)[1],
    		 ((unsigned char *)&inet->inet_saddr)[2],
    		 ((unsigned char *)&inet->inet_saddr)[3],
		ntohs(inet->inet_sport), 
                 ((unsigned char *)&inet->inet_daddr)[0],
                 ((unsigned char *)&inet->inet_daddr)[1],
                 ((unsigned char *)&inet->inet_daddr)[2],
                 ((unsigned char *)&inet->inet_daddr)[3],
            	ntohs(inet->inet_dport));
        }
        spin_unlock_bh(lock);
	
    }
}

static int __init tcphash_init(void)
{
    printk("tcphash_info Module Init\n");

    print_tcp_socks();

    printk("tcphash_info Module  End");
    return 0;
}
module_init(tcphash_init);


static void __exit tcphash_exit(void)
{
    printk("tcphash_info Module Exit\n");
}
module_exit(tcphash_exit);


MODULE_LICENSE("GPL");
MODULE_AUTHOR("dwh0403");
MODULE_DESCRIPTION("print tcphash_info module");
MODULE_ALIAS("tcphash_module");
