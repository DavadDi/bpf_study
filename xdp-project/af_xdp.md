AF_XDP是一个针对高性能数据包处理而优化的地址系列。

本文档假设读者熟悉BPF和XDP。如果不熟悉，Cilium项目有一个很好的参考指南，网址是http://cilium.readthedocs.io/en/latest/bpf/。

使用XDP程序中的XDP_REDIRECT操作，程序可以使用bpf_redirect_map()函数将入口帧重定向到其他启用XDP的netdevs。AF_XDP套接字使XDP程序可以将帧重定向到用户空间应用程序的内存缓冲区。

一个AF_XDP套接字(XSK)是通过正常的socket()系统调用创建的。与每个XSK相关联的是两个环：RX环和TX环。一个套接字可以在RX环上接收数据包，也可以在TX环上发送数据包。这些环分别用setockopts XDP_RX_RING和XDP_TX_RING注册和确定大小。每个套接字必须至少有一个这样的环。一个RX或TX描述符环指向内存区域中的一个数据缓冲区，称为UMEM。RX和TX可以共享同一个UMEM，这样一个数据包就不必在RX和TX之间复制。此外，如果一个数据包由于可能的重发而需要保留一段时间，可以将指向该数据包的描述符改为指向另一个数据包，并立即重新使用。这又避免了数据的复制。

UMEM由许多大小相等的块组成。其中一个环中的描述符通过引用其addr来引用一个帧。addr只是整个UMEM区域内的一个偏移。用户空间使用任何它认为最合适的手段（malloc、mmap、巨页等）为这个UMEM分配内存。然后使用新的setockopt XDP_UMEM_REG向内核注册这个内存区域。UMEM也有两个环：FILL环和COMPLETION环。FILL环由应用程序用来发送addr给内核，让内核填入RX数据包。一旦收到每个数据包，这些帧的引用就会出现在RX环中。另一方面，COMPLETION环包含了内核已经完全传输的帧addr，现在可以被用户空间再次使用，用于TX或RX。因此，出现在COMPLETION环中的帧addr是之前使用TX环传输的addr。总之，RX和FILL环用于RX路径，TX和COMPLETION环用于TX路径。

然后通过bind()调用将套接字最后绑定到一个设备上，并在该设备上绑定一个特定的队列id，直到绑定完成后，流量才开始流动。

如果需要，UMEM可以在进程之间共享。如果一个进程想这样做，它只需跳过UMEM及其对应的两个环的注册，在绑定调用中设置XDP_SHARED_UMEM标志，并提交它想与之共享UMEM的进程的XSK以及自己新创建的XSK套接字。然后，新进程将在自己的RX环中接收指向这个共享UMEM的帧addr引用。请注意，由于环结构是单消费者/单生产者（出于性能考虑），新进程必须创建自己的套接字和相关的RX和TX环，因为它不能与其他进程共享。这也是每个UMEM只有一组FILL和COMPLETION环的原因。处理UMEM是一个进程的责任。

那么数据包是如何从XDP程序分发到XSK的呢？有一个叫做XSKMAP的BPF映射（或BPF_MAP_TYPE_XSKMAP全称）。用户空间程序可以在这个映射中的任意位置放置一个XSK。然后，XDP程序可以将一个数据包重定向到这个映射中的特定索引，此时XDP会验证该映射中的XSK是否确实与该设备和环号绑定。如果没有，则丢弃该数据包。如果该索引处地图为空，则数据包也会被丢弃。这也就意味着目前必须加载一个XDP程序（并且在XSKMAP里有一个XSK），才能通过XSK获得任何流量到用户空间。

AF_XDP可以在两种不同的模式下工作。XDP_SKB和XDP_DRV。如果驱动程序不支持XDP，或者在加载XDP程序时明确选择了XDP_SKB，则会采用XDP_SKB模式，该模式使用SKB与通用的XDP支持一起使用，并将数据复制到用户空间。这是一种适用于任何网络设备的后备模式。另一方面，如果驱动程序对XDP有支持，则会被AF_XDP代码使用，以提供更好的性能，但仍有一份数据拷贝到用户空间。



概念
为了使用AF_XDP套接字，需要设置一些相关的对象。这些对象及其选项将在下面的章节中解释。

要想了解AF_XDP的工作原理，你也可以看看2018年的Linux Plumbers关于这个主题的论文：http://vger.kernel.org/lpc_net2018_talks/lpc18_paper_af_xdp_perf-v2.pdf。不要参考2017年关于 "AF_PACKET v4 "的论文，这是AF_XDP的第一次尝试。从那时起，几乎所有的东西都改变了。Jonathan Corbet还写了一篇关于LWN的优秀文章，"用AF_XDP加速联网"。它可以在 https://lwn.net/Articles/750845/ 找到。

UMEM
UMEM是一个虚拟连续内存的区域，被分割成大小相等的帧。一个UMEM与一个netdev和该netdev的一个特定的队列id相关联，它是通过使用XDP_UMEM_REG setock来创建和配置的（分块大小、净空、起始地址和大小）。它是通过使用XDP_UMEM_REG setockopt系统调用来创建和配置的（分块大小、净空、起始地址和大小）。一个UMEM通过bind()系统调用与netdev和队列id绑定。

一个AF_XDP是连接到单个UMEM的套接字，但一个UMEM可以有多个AF_XDP套接字。要共享通过一个套接字A创建的UMEM，下一个套接字B可以通过设置struct sockaddr_xdp成员sxdp_flags中的XDP_SHARED_UMEM标志，并将A的文件描述符传递给struct sockaddr_xdp成员sxdp_shared_umem_fd。

UMEM有两个单生产者/单消费者环，用于在内核和用户空间应用之间转移UMEM帧的所有权。

环
有四种不同的环。FILL、COMPLETION、RX和TX。所有的环都是单生产者/单消费者，所以用户空间的应用需要显式同步多个进程/线程的读写。

UMEM使用两个环。FILL和COMPLETION。每一个与UMEM相关联的socket必须有一个RX队列、TX队列或两者兼有。比如说，有一个设置有四个socket（都是做TX和RX）。那么就会有一个FILL环，一个COMPLETION环，四个TX环和四个RX环。

这些环是基于头部（生产者）/尾部（消费者）的环。生产者在结构xdp_ring producer成员指出的索引处写入数据环，并增加生产者索引。消费者在 struct xdp_ring consumer member 指明的索引处读取数据环，并增加消费者索引。

环通过_RING setockopt系统调用进行配置和创建，并使用适当的偏移量向mmap()映射到用户空间(XDP_PGOFF_RX_RING、XDP_PGOFF_TX_RING、XDP_UMEM_PGOFF_FILL_RING和XDP_UMEM_PGOFF_COMPLETION_RING)。

环的大小需要是2的幂。

UMEM 填充环
FILL环用于将UMEM帧的所有权从用户空间转移到内核空间。UMEM的addrs是在环中传递的。举个例子，如果UMEM是64k，每个chunk是4k，那么UMEM有16个chunk，可以传递0到64k之间的addrs。

传递给内核的帧用于入口路径（RX环）。

用户应用程序产生UMEM addrs到这个环。需要注意的是，如果在对齐的分块模式下运行应用程序，内核会屏蔽传入的addr。例如，对于一个2k大小的chunk，addr的log2(2048)LSB将被屏蔽掉，这意味着2048、2050和3000指的是同一个chunk。如果用户应用在不对齐的chunks模式下运行，那么传入的addr将不被触动。

UMEM完成环
COMPLETION环用于将UMEM帧的所有权从内核空间转移到用户空间。就像FILL环一样，使用UMEM索引。

从内核传递到用户空间的帧是已经发送的帧（TX环），可以被用户空间再次使用。

用户应用从这个环消耗UMEM addrs。

RX环
RX环是套接字的接收端。环中的每个条目是一个xdp_desc描述符结构。描述符包含UMEM偏移量(addr)和数据的长度(len)。

如果没有帧通过FILL环传递给内核，那么在RX环上就不会（或可以）出现描述符。

用户应用程序从这个环消耗xdp_desc描述符结构。

TX环
TX环用于发送帧。结构xdp_desc描述符被填入（索引、长度和偏移量）并传递到环中。

为了开始传输，需要一个sendmsg()系统调用。这一点将来可能会被放宽。

用户应用程序会产生结构xdp_desc描述符到这个环中。



Libbpf
Libbpf是一个用于eBPF和XDP的帮助库，它使这些技术的使用变得更加简单。它还在 tools/lib/bpf/xsk.h 中包含了特定的帮助函数，以方便AF_XDP的使用。它包含两种类型的函数：那些可以用来使AF_XDP套接字的设置变得更简单的函数，以及那些可以在数据平面上安全快速地访问环的函数。要查看如何使用这个API的例子，请看samples/bpf/xdpsock_usr.c中的示例应用程序，它使用libbpf进行设置和数据平面操作。

我们建议你使用这个库，除非你已经成为一个强大的用户。它将使你的程序变得更简单。

XSKMAP / BPF_MAP_TYPE_XSKMAP.
在XDP侧有一个BPF映射类型BPF_MAP_TYPE_XSKMAP (XSKMAP)，它与bpf_redirect_map()一起使用，将入口帧传递给socket。

用户应用程序通过bpf()系统调用将套接字插入到映射中。

请注意，如果一个XDP程序试图重定向到一个与队列配置和netdev不匹配的套接字，该帧将被丢弃。例如，AF_XDP套接字被绑定到netdev eth0和队列17。只有针对eth0和队列17执行的XDP程序才能成功地将数据传递到套接字。请参考示例应用程序(samples/bpf/)中的例子。

配置标志和套接字选项
这些是各种配置标志，可以用来控制和监视AF_XDP套接字的行为。

XDP和XDP_ZERO的绑定标志。
当你绑定到一个socket时，内核会首先尝试使用零拷贝。如果不支持零拷贝，它将回到使用拷贝模式，即把所有数据包复制到用户空间。但是如果你想强制使用某种模式，你可以使用以下标志。如果你把XDP标志传递给绑定调用，内核将强制套接字进入复制模式。如果它不能使用复制模式，绑定调用将以错误的方式失败。反之，XDP_ZERO_XXX标志将强制套接字进入零拷贝模式或失败。

XDP_SHARED_UMEM绑定标志
该标志使您能够将多个套接字绑定到同一个UMEM上，但前提是它们共享同一个队列id。在这种模式下，每个套接字都有自己的RX和TX环，但UMEM（与创建的第一个套接字绑定）只有一个FILL环和一个COMPLETION环。要使用这种模式，请创建第一个套接字，并以正常方式进行绑定。创建第二个套接字，并创建一个RX和一个TX环，或至少创建其中一个，但不使用FILL或COMPLETION环，因为将使用第一个套接字的环。在绑定调用中，设置XDP_SHARED_UMEM选项，并在sxdp_shared_umem_fd字段中提供初始socket的fd。你可以用这种方式附加任意数量的额外套接字。

那么一个数据包将到达哪个套接字呢？这是由XDP程序决定的。把所有的套接字都放在XSK_MAP中，只需指明你想把每个数据包发送到数组中的哪个索引。下面是一个简单的循环分发数据包的例子。

```c
#include <linux/bpf.h>
#include "bpf_helpers.h"

#define MAX_SOCKS 16

struct {
     __uint(type, BPF_MAP_TYPE_XSKMAP);
     __uint(max_entries, MAX_SOCKS);
     __uint(key_size, sizeof(int));
     __uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

static unsigned int rr;

SEC("xdp_sock") int xdp_sock_prog(struct xdp_md *ctx)
{
     rr = (rr + 1) & (MAX_SOCKS - 1);

     return bpf_redirect_map(&xsks_map, rr, XDP_DROP);
}
```

需要注意的是，由于FILL和COMPLETION环只有一组，而且是单个生产者、单个消费者环，所以需要确保多个进程或线程不会并发使用这些环。在libbpf代码中，目前还没有保护多个用户的同步基元。

如果你创建了多个绑定在同一个umem上的socket，Libbpf就会使用这种模式。然而，请注意，你需要在xsk_socket__create调用中提供XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD libbpf_flag，并加载你自己的XDP程序，因为libbpf中没有内置的程序会为你路由流量。



XDP_USE_NEED_WAKEUP 绑定标志.
这个选项增加了对一个名为need_wakeup的新标志的支持，这个标志存在于FILL环和TX环，用户空间是生产者的环。当在绑定调用中设置这个选项时，如果内核需要被syscall显式唤醒才能继续处理数据包，那么就会设置need_wakeup标志。如果该标志为0，则不需要系统调用。

如果在FILL环上设置了标志，应用程序需要调用poll()才能在RX环上继续接收数据包。例如，当内核检测到 FILL 环上没有缓冲区了，而 NIC 的 RX HW 环上也没有缓冲区了，就会发生这种情况。在这种情况下，中断会被关闭，因为网卡不能接收任何数据包（因为没有缓冲区可以放），设置 need_wakeup 标志，这样用户空间就可以在 FILL 环上放缓冲区，然后调用 poll()，这样内核驱动就可以在 HW 环上放这些缓冲区，开始接收数据包。

如果为TX环设置了标志，则意味着应用程序需要明确地通知内核发送任何放在TX环上的数据包。这可以通过poll()调用来实现，就像在RX路径中一样，或者通过调用sendto()来实现。

关于如何使用这个标志的例子可以在 samples/bpf/xdpsock_user.c中找到，一个使用libbpf helpers的例子在TX路径中是这样的。

```c
if (xsk_ring_prod__needs_wakeup(&my_tx_ring))
   sendto(xsk_socket__fd(xsk_handle), NULL, 0, MSG_DONTWAIT, NULL, 0);
```

即，只有在设置了标志的情况下才使用syscall。

我们建议您总是启用这个模式，因为它通常会带来更好的性能，特别是当您在同一个内核上运行应用程序和驱动程序时，但如果您为应用程序和内核驱动程序使用不同的内核，也是如此，因为它减少了TX路径所需的syscall数量。



XDP_{RX|TX|UMEM_FILL|UMEM_COMPLETION}_RING setockopts
这些setockopts设置了RX、TX、FILL和COMPLETION环分别应该拥有的描述符数量。RX和TX环中至少有一个环的大小是必须设置的。如果同时设置了这两个环，就可以同时接收和发送应用程序的流量，但如果只想做其中的一个环，可以只设置其中一个环来节省资源。FILL环和COMPLETION环都是必须的，因为你需要有一个UMEM与你的socket绑定。但是如果使用了XDP_SHARED_UMEM标志，那么在第一个套接字之后的任何套接字都没有UMEM，在这种情况下，不应该创建任何FILL或COMPLETION环，因为共享UMEM中的环将被使用。注意，这些环是单生产者单消费者的，所以不要试图同时从多个进程访问它们。参见XDP_SHARED_UMEM部分。

在 libbpf 中，您可以通过向 xsk_socket__create 函数的 rx 和 tx 参数分别提供 NULL 来创建 Rx-only 和 Tx-only 套接字。

如果您创建了一个仅有Tx的套接字，我们建议您不要在填充环上放置任何数据包。如果您这样做，驱动程序可能会认为您将收到一些东西，而事实上您不会收到，这可能会对性能产生负面影响。

XDP_UMEM_REG setockopt
这个setockopt注册一个UMEM到socket。这是一个包含所有缓冲区的区域，数据包可以在这个区域中找到。这个调用需要一个指向这个区域起始的指针和它的大小。此外，它还有一个参数chunk_size，是UMEM被分割成的大小。目前只能是2K或4K。如果你的UMEM区域是128K，chunk大小是2K，这意味着你的UMEM区域最多只能容纳128K / 2K = 64个数据包，而你最大的数据包大小可以是2K。

还有一个选项可以设置UMEM中每个单个缓冲区的净空。如果你把它设置为N个字节，意味着数据包将从N个字节开始进入缓冲区，留下前N个字节供应用程序使用。最后一个选项是flags字段，但它将在每个UMEM标志的单独章节中处理。

XDP_STATISTICS getsockopt
获取一个套接字的drop统计信息，这些信息对调试很有用。支持的统计数据如下所示。

```
struct xdp_statistics {
       __u64 rx_dropped; /* Dropped for reasons other than invalid desc */
       __u64 rx_invalid_descs; /* Dropped due to invalid descriptor */
       __u64 tx_invalid_descs; /* Dropped due to invalid descriptor */
};
```

XDP_OPTIONS getsockopt.
从 XDP 套接字中获取选项。目前唯一支持的是XDP_OPTIONS_ZEROCOPY，它告诉你零拷贝是否开启。

用法
为了使用AF_XDP套接字，需要两个部分。用户空间应用程序和XDP程序。关于完整的设置和使用示例，请参考示例程序。用户空间程序是xdpsock_user.c，XDP程序是libbpf的一部分。

工具/lib/bpf/xsk.c中包含的XDP代码示例如下。

```
SEC("xdp_sock") int xdp_sock_prog(struct xdp_md *ctx)
{
    int index = ctx->rx_queue_index;

    // A set entry here means that the corresponding queue_id
    // has an active AF_XDP socket bound to it.
    if (bpf_map_lookup_elem(&xsks_map, &index))
        return bpf_redirect_map(&xsks_map, index, 0);

    return XDP_PASS;
}
```

一个简单但性能不高的环形dequeue和enqueue可以是这样的。

```
// struct xdp_rxtx_ring {
//  __u32 *producer;
//  __u32 *consumer;
//  struct xdp_desc *desc;
// };

// struct xdp_umem_ring {
//  __u32 *producer;
//  __u32 *consumer;
//  __u64 *desc;
// };

// typedef struct xdp_rxtx_ring RING;
// typedef struct xdp_umem_ring RING;

// typedef struct xdp_desc RING_TYPE;
// typedef __u64 RING_TYPE;

int dequeue_one(RING *ring, RING_TYPE *item)
{
    __u32 entries = *ring->producer - *ring->consumer;

    if (entries == 0)
        return -1;

    // read-barrier!

    *item = ring->desc[*ring->consumer & (RING_SIZE - 1)];
    (*ring->consumer)++;
    return 0;
}

int enqueue_one(RING *ring, const RING_TYPE *item)
{
    u32 free_entries = RING_SIZE - (*ring->producer - *ring->consumer);

    if (free_entries == 0)
        return -1;

    ring->desc[*ring->producer & (RING_SIZE - 1)] = *item;

    // write-barrier!

    (*ring->producer)++;
    return 0;
}
```

但请使用libbpf函数，因为它们是优化过的，并可随时使用。会让你的生活更轻松。

申请书样本
其中包含了一个xdpsock基准/测试程序，演示了如何在私有UMEM中使用AF_XDP套接字。假设你想让来自4242端口的UDP流量最终进入队列16，我们将启用AF_XDP。在这里，我们使用ethtool来实现。

```
ethtool -N p3p2 rx-flow-hash udp4 fn
ethtool -N p3p2 flow-type udp4 src-port 4242 dst-port 4242 \
    action 16
```

然后在XDP_DRV模式下运行rxdrop基准可以使用。

```
samples/bpf/xdpsock -i p3p2 -q 16 -r -N
```

对于XDP_SKB模式，使用开关"-S "代替"-N"，所有的选项可以像往常一样用"-h "来显示。

这个示例程序使用libbpf来简化AF_XDP的设置和使用。如果你想知道AF_XDP的原始uapi到底是如何被用来做一些更高级的东西，可以看看工具/lib/bpf/xsk.[ch]中的libbpf代码。



常见问题
问：我在插座上没有看到任何流量。我做错了什么？

答：当物理网卡的netdev被初始化时，Linux通常会将该物理网卡的netdev设置为
为每个核分配一个RX和TX队列对，所以在8核系统中，队列ID 0到7将被分配，每个核分配一个。所以在8核系统中，队列id 0到7将被分配，每个核分配一个。在AF_XDP绑定调用或xsk_socket__create libbpf函数调用中，你指定了一个特定的队列id来绑定，你将在你的套接字上得到的只是朝向该队列的流量。因此，在上面的例子中，如果你绑定到队列0，你不会得到任何分配到队列1到7的流量。如果你很幸运，你会看到流量，但通常它最终会出现在你没有绑定的队列中。

有很多方法可以解决把你想要的流量送到你绑定的队列id上的问题。如果你想看到所有的流量，你可以强制netdev只有1个队列，队列id 0，然后绑定到队列0。你可以使用 ethtool 来完成这个任务。

```
sudo ethtool -L <接口> combined 1
```


如果你想只看到部分流量，你可以通过 ethtool 对 NIC 进行编程，将流量过滤到一个单一的队列 id 上，你可以将 XDP 套接字绑定到这个队列上。下面是一个例子，在这个例子中，进出端口4242的UDP流量被发送到队列2。

```
sudo ethtool -N <interface> rx-flow-hash udp4 fn
sudo ethtool -N <interface> flow-type udp4 src-port 4242 dst-port \
4242 action 2
```


其他一些方法也是可能的，都取决于你的网卡的能力。

问：我可以用XSKMAP来实现不同内存的切换吗？
在复制模式下？
答：简短的回答是否定的，目前不支持这种方式。该
XSKMAP只能用于将从队列id X进入的流量切换到绑定在同一队列id X上的套接字。XSKMAP可以包含绑定在不同队列id上的套接字，例如X和Y，但只有从队列id Y进入的流量才能被引导到绑定在同一队列id Y上的套接字上。



## 参考

1. [什么是AF_XDP Socket](https://decodezp.github.io/2019/03/26/quickwords22-af-xdp/)