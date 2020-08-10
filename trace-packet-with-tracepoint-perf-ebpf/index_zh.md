# [译] 使用 Linux tracepoint、perf 和 eBPF 跟踪数据包 (2017)

> 本文来自： http://arthurchiao.art/blog/trace-packet-with-tracepoint-perf-ebpf-zh/

### 译者序

本文翻译自 2017 年的一篇英文博客 [Tracing a packet’s journey using Linux tracepoints, perf and eBPF](https://blog.yadutaf.fr/2017/07/28/tracing-a-packet-journey-using-linux-tracepoints-perf-ebpf/) 。为方便阅读，对其添加了适当的章节号。

为避免过于生硬，本文不会逐词逐句翻译，技术领域的过度翻译会带来交流障碍。**如果能 看懂英文，我建议你阅读原文，或者和本文对照看。**

**由于译者水平有限，本文不免存在遗漏或错误之处。如有疑问，请查阅原文。**

以下是译文。

------

一段时间以来，我一直在寻找 Linux 上的底层网络调试（debug）工具。

Linux 允许在主机上用**虚拟网卡**（virtual interface）和**网络命名空间**（network namespace）构建复杂的网络。但出现故障时，排障（troubleshooting）相当痛苦。如果是 3 层路由问题，`mtr` 可以排上用场。但如果是更底层的问题，我通常只能手动检查每个网 卡/网桥/网络命名空间/iptables 规则，用 tcpdump 抓一些包，以确定到底是什么状况。如 果不了解故障之前的网络设置，那感觉就像在走迷宫。

## 1 开篇

### 1.1 逃离迷宫：上帝视角

逃离迷宫的一种方式是在**迷宫内**不断左右尝试（exploring），寻找通往出口的路 。当你在玩迷宫游戏（置身迷宫内）时，你只能如此。不过，如果不是在游戏内，那还有另 一种方式：**转换视角，高空俯视**。

用 Linux 术语来说，就是转换到**内核视角**（the kernel point of view）。在这种视 角下，**网络命名空间不再是容器（”containers”），而只是一些标签（labels）。内核、 数据包、网卡等此时都是“肉眼可见”的对象（objects）**。

> **原文注**：上面的 “containers” 我加了引号，因为从技术上说，网络命名空间是 构成 Linux 容器的核心部件之一。

### 1.2 网络跟踪：渴求利器

所以我想要的是这样一个工具，它可以直接告诉我 “嗨，我看到你的包了：它从**属于这个 网络命名空间**的**这个网卡**上发出来，然后**依次经过这些函数**”。

本质上，我想要的是一个 **2 层的 `mtr`**。这样的工具存在吗？不存在我们就造一个！

本文结束时，我们将拥有一个简单、易于使用的底层**网络包跟踪器**（packet tracker ）。如果你 ping 本机上的一个 Docker 容器，它会显示类似如下信息：

```
# ping -4 172.17.0.2
[  4026531957]          docker0 request #17146.001 172.17.0.1 -> 172.17.0.2
[  4026531957]      vetha373ab6 request #17146.001 172.17.0.1 -> 172.17.0.2
[  4026532258]             eth0 request #17146.001 172.17.0.1 -> 172.17.0.2
[  4026532258]             eth0   reply #17146.001 172.17.0.2 -> 172.17.0.1
[  4026531957]      vetha373ab6   reply #17146.001 172.17.0.2 -> 172.17.0.1
[  4026531957]          docker0   reply #17146.001 172.17.0.2 -> 172.17.0.1
```

### 1.3 巨人肩膀：perf/eBPF

在本文中，我将聚焦两个跟踪工具：`perf` 和 `eBPF`。

`perf` 是 Linux 上的最重要的性能分析工具之一。它和内核出自同一个源码树（source tree），但编译需要针对指定的内核版本。`perf` 可以跟踪内核，也可以跟踪用户程序， 还可用于采样或者设置跟踪点。**可以把它想象成开销更低，但功能更强大的 `strace`**。 本文只会使用非常简单的 `perf` 命令。想了解更多，强烈建议访问 [Brendan Gregg](http://www.brendangregg.com/perf.html)的博客。

`eBPF` 是 Linux 内核新近加入的，其中 e 是 `extended` 的缩写。从名字可以看出，它 是 BPF（Berkeley Packet Filter）字节码过滤器的增强版，后者是 BSD family 的网络包 过滤工具。在 Linux 上，eBPF 可以在运行中的内核（live kernel）中安全地执行任何平 台无关（platform independent）代码，只要这些代码满足一些安全前提。例如，在程序执 行之前必须验证内存访问合法性，而且要能证明程序会在有限时间内退出。如果内核无法验 证这些条件，那即使 eBPF 代码是安全的并且确定会退出，它也仍然会被拒绝。

eBPF 程序可用于 **QOS 网络分类器**（network classifier）、**XDP**（eXpress Data Plane） 很底层的网络功能和过滤功能组件、**跟踪代理**（tracing agent），以及其他很多方面。 **任何在 `/proc/kallsyms` 导出的符号（内核函数）或者跟踪点（tracepoints）， 都可以插入 eBPF 跟踪点**（tracing probes）。

本文将主要关注 attach 到 tracepoints 的跟踪代理（tracing agents attached to tracepoints）。如果想看一些在内核函数埋点进行跟踪的例子，或者入门级介绍，建议阅 读我之前的 eBPF 文章[英文 ](https://blog.yadutaf.fr/2016/03/30/turn-any-syscall-into-event-introducing-ebpf-kernel-probes/)，[中文翻译](http://arthurchiao.art/blog/ebpf-turn-syscall-to-event-zh)。

## 2 Perf

本文只会使用 perf 做非常简单的内核跟踪。

### 2.1 安装 perf

我的环境基于 Ubuntu 17.04 （Zesty）：

```
$ sudo apt install linux-tools-generic
$ perf # test perf
```

### 2.2 测试环境

我们将使用 4 个 IP，其中 2 个为外部可路由网段（`192.168`）：

1. localhost，IP `127.0.0.1`
2. 一个干净的容器，IP `172.17.0.2`
3. 我的手机，通过 USB 连接，IP `192.168.42.129`
4. 我的手机，通过 WiFi 连接，IP `192.168.43.1`

### 2.3 初体验：跟踪 ping 包

`perf trace` 是 `perf` 子命令，能够跟踪 packet 路径，默认输出类似于 `strace`（头 信息少很多）。

跟踪 ping 向 `172.17.0.2` 容器的包，这里我们只关心 `net` 事件，忽略系统调用信息：

```
$ sudo perf trace --no-syscalls --event 'net:*' ping 172.17.0.2 -c1 > /dev/null
     0.000 net:net_dev_queue:dev=docker0 skbaddr=0xffff96d481988700 len=98)
     0.008 net:net_dev_start_xmit:dev=docker0 queue_mapping=0 skbaddr=0xffff96d481988700 vlan_tagged=0 vlan_proto=0x0000 vlan_tci=0x0000 protocol=0x0800 ip_summed=0 len=98 data_len=0 network_offset=14 transport_offset_valid=1 transport_offset=34 tx_flags=0 gso_size=0 gso_segs=0 gso_type=0)
     0.014 net:net_dev_queue:dev=veth79215ff skbaddr=0xffff96d481988700 len=98)
     0.016 net:net_dev_start_xmit:dev=veth79215ff queue_mapping=0 skbaddr=0xffff96d481988700 vlan_tagged=0 vlan_proto=0x0000 vlan_tci=0x0000 protocol=0x0800 ip_summed=0 len=98 data_len=0 network_offset=14 transport_offset_valid=1 transport_offset=34 tx_flags=0 gso_size=0 gso_segs=0 gso_type=0)
     0.020 net:netif_rx:dev=eth0 skbaddr=0xffff96d481988700 len=84)
     0.022 net:net_dev_xmit:dev=veth79215ff skbaddr=0xffff96d481988700 len=98 rc=0)
     0.024 net:net_dev_xmit:dev=docker0 skbaddr=0xffff96d481988700 len=98 rc=0)
     0.027 net:netif_receive_skb:dev=eth0 skbaddr=0xffff96d481988700 len=84)
     0.044 net:net_dev_queue:dev=eth0 skbaddr=0xffff96d481988b00 len=98)
     0.046 net:net_dev_start_xmit:dev=eth0 queue_mapping=0 skbaddr=0xffff96d481988b00 vlan_tagged=0 vlan_proto=0x0000 vlan_tci=0x0000 protocol=0x0800 ip_summed=0 len=98 data_len=0 network_offset=14 transport_offset_valid=1 transport_offset=34 tx_flags=0 gso_size=0 gso_segs=0 gso_type=0)
     0.048 net:netif_rx:dev=veth79215ff skbaddr=0xffff96d481988b00 len=84)
     0.050 net:net_dev_xmit:dev=eth0 skbaddr=0xffff96d481988b00 len=98 rc=0)
     0.053 net:netif_receive_skb:dev=veth79215ff skbaddr=0xffff96d481988b00 len=84)
     0.060 net:netif_receive_skb_entry:dev=docker0 napi_id=0x3 queue_mapping=0 skbaddr=0xffff96d481988b00 vlan_tagged=0 vlan_proto=0x0000 vlan_tci=0x0000 protocol=0x0800 ip_summed=2 hash=0x00000000 l4_hash=0 len=84 data_len=0 truesize=768 mac_header_valid=1 mac_header=-14 nr_frags=0 gso_size=0 gso_type=0)
     0.061 net:netif_receive_skb:dev=docker0 skbaddr=0xffff96d481988b00 len=84)
```

只保留事件名和 `skbaddr`，看起来清晰很多：

```
net_dev_queue           dev=docker0     skbaddr=0xffff96d481988700
net_dev_start_xmit      dev=docker0     skbaddr=0xffff96d481988700
net_dev_queue           dev=veth79215ff skbaddr=0xffff96d481988700
net_dev_start_xmit      dev=veth79215ff skbaddr=0xffff96d481988700
netif_rx                dev=eth0        skbaddr=0xffff96d481988700
net_dev_xmit            dev=veth79215ff skbaddr=0xffff96d481988700
net_dev_xmit            dev=docker0     skbaddr=0xffff96d481988700
netif_receive_skb       dev=eth0        skbaddr=0xffff96d481988700

net_dev_queue           dev=eth0        skbaddr=0xffff96d481988b00
net_dev_start_xmit      dev=eth0        skbaddr=0xffff96d481988b00
netif_rx                dev=veth79215ff skbaddr=0xffff96d481988b00
net_dev_xmit            dev=eth0        skbaddr=0xffff96d481988b00
netif_receive_skb       dev=veth79215ff skbaddr=0xffff96d481988b00
netif_receive_skb_entry dev=docker0     skbaddr=0xffff96d481988b00
netif_receive_skb       dev=docker0     skbaddr=0xffff96d481988b00
```

这里面有很多信息。

首先注意，**`skbaddr` 在中间变了**（`0xffff96d481988700 -> 0xffff96d481988b00`） 。变的这里，就是**生成了 ICMP echo reply 包**，并作为应答包发送的地方。接下来的 时间，这个包的 `skbaddr` 保持不变，说明没有 copy。copy 非常耗时。

其次，我们可以清楚地看到 **packet 在内核的传输路径**：

1. `docker0` 网桥
2. veth pair 的宿主机端（`veth79215ff`)
3. veth pair 的容器端（容器里的 `eth0`）
4. 接下来是相反的返回路径

**至此，虽然我们还没有看到网络命名空间，但已经得到了一个不错的全局视图。**

### 2.4 进阶：选择跟踪点

上面的信息有些杂，还有很多重复。我们可以选择几个最合适的跟踪点，使得输出看起来 更清爽。要查看所有可用的网络跟踪点，执行 `perf list`：

```
$ sudo perf list 'net:*'
```

这个命令会列出 `tracepoint` 列表，名字类似于 `net:netif_rx`。**冒号前面是事件类型 ，后面是事件名字**。这里我选择了 4 个：

- `net_dev_queue`
- `netif_receive_skb_entry`
- `netif_rx`
- `napi_gro_receive_entry`

效果：

```
$ sudo perf trace --no-syscalls           \
    --event 'net:net_dev_queue'           \
    --event 'net:netif_receive_skb_entry' \
    --event 'net:netif_rx'                \
    --event 'net:napi_gro_receive_entry'  \
    ping 172.17.0.2 -c1 > /dev/null
       0.000 net:net_dev_queue:dev=docker0 skbaddr=0xffff8e847720a900 len=98)
       0.010 net:net_dev_queue:dev=veth7781d5c skbaddr=0xffff8e847720a900 len=98)
       0.014 net:netif_rx:dev=eth0 skbaddr=0xffff8e847720a900 len=84)
       0.034 net:net_dev_queue:dev=eth0 skbaddr=0xffff8e849cb8cd00 len=98)
       0.036 net:netif_rx:dev=veth7781d5c skbaddr=0xffff8e849cb8cd00 len=84)
       0.045 net:netif_receive_skb_entry:dev=docker0 napi_id=0x1 queue_mapping=0
```

漂亮！

## 3 eBPF

前面介绍的内容已经可以满足大部分 tracing 场景的需求了。如果你只是想学习如何在 Linux 上跟踪一个 packet 的传输路径，那到此已经足够了。但如果想跟更进一步，学习如 何写一个自定义的过滤器，跟踪网络命名空间、源 IP、目的 IP 等信息，请继续往下读。

### 3.1 eBPF 和 kprobes

从 Linux 内核 4.7 开始，eBPF 程序可以 attach 到内核跟踪点（kernel tracepoints） 。在此之前，要完成类似的工作，只能用 kprobes 之类的工具 attach 到**导出的内核函 数**（exported kernel sysbols）。后者虽然可以完成工作，但存在很多不足：

1. 内核的内部（internal）API 不稳定
2. 出于性能考虑，大部分网络相关的内层函数（inner functions）都是内联或者静态的（ inlined or static），两者都不可探测
3. 找出调用某个函数的所有地方是相当乏味的，有时所需的字段数据不全具备

这篇博客的早期版本使用了 kprobes，但结果并不是太好。 现在，诚实地说，通过内核 tracepoints 访问数据比通过 kprobe 要更加乏味。我尽量保 持本文简洁，如果你想了解本文稍老的版本，可以访问这里[英文 ](https://blog.yadutaf.fr/2016/03/30/turn-any-syscall-into-event-introducing-ebpf-kernel-probes/)，[中文翻译](http://arthurchiao.art/blog/ebpf-turn-syscall-to-event-zh)。

### 3.2 安装

我不是徒手汇编控（fans of handwritten assembly），因此接下来将使用 `bcc`。`bcc` 是一个灵活强大的工具，允许用受限的 C 语法（restricted C）写内核探测代码，然后用 Python 在用户态做控制。这种方式对于生产环境算是重量级，但对开发来说非常完美。

**注意：eBPF 需要 Linux Kernel 4.7+。**

Ubuntu 17.04 [安装 (GitHub)](https://github.com/iovisor/bcc/blob/master/INSTALL.md) `bcc`:

```
# Install dependencies
$ sudo apt install bison build-essential cmake flex git libedit-dev python zlib1g-dev libelf-dev libllvm4.0 llvm-dev libclang-dev luajit luajit-5.1-dev

# Grab the sources
$ git clone https://github.com/iovisor/bcc.git
$ mkdir bcc/build
$ cd bcc/build
$ cmake .. -DCMAKE_INSTALL_PREFIX=/usr
$ make
$ sudo make install
```

### 3.3 自定义跟踪器：Hello World

接下来我们从一个简单的 hello world 例子展示如何在底层打点。我们还是用上一篇 文章里选择的四个点：

- `net_dev_queue`
- `netif_receive_skb_entry`
- `netif_rx`
- `napi_gro_receive_entry`

每当网络包经过这些点，我们的处理逻辑就会触发。为保持简单，我们的处理逻辑只是将程 序的 `comm` 字段（16 字节）发送出来（到用户空间程序），这个字段里存的是发 送相应的网络包的程序的名字。

```
#include <bcc/proto.h>
#include <linux/sched.h>

// Event structure
struct route_evt_t {
        char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(route_evt);

static inline int do_trace(void* ctx, struct sk_buff* skb)
{
    // Built event for userland
    struct route_evt_t evt = {};
    bpf_get_current_comm(evt.comm, TASK_COMM_LEN);

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

TRACEPOINT_PROBE(net, napi_gro_receive_entry) {
    return do_trace(args, (struct sk_buff*)args->skbaddr);
}

TRACEPOINT_PROBE(net, netif_receive_skb_entry) {
    return do_trace(args, (struct sk_buff*)args->skbaddr);
}
```

可以看到，程序 attach 到 4 个 tracepoint，并会访问 `skbaddr` 字段，将其传给处理 逻辑函数，这个函数现在只是将程序名字发送出来。你可能会有疑问，`args->skbaddr` 是 哪里来的？答案是，每次用 `TRACEPONT_PROBE` 定义一个 tracepoint，`bcc` 就会为其自 动生成 `args` 参数，由于它是动态生成的，因此要查看它的定义不太容易。

不过，有另外一种简单的方式可以查看。在 Linux 上每个 tracepoint 都对应一个 `/sys/kernel/debug/tracing/events` 条目。例如，查看 `net:netif_rx`：

```
$ cat /sys/kernel/debug/tracing/events/net/netif_rx/format
name: netif_rx
ID: 1183
format:
	field:unsigned short common_type;         offset:0; size:2; signed:0;
	field:unsigned char common_flags;         offset:2; size:1; signed:0;
	field:unsigned char common_preempt_count; offset:3; size:1; signed:0;
	field:int common_pid;                     offset:4; size:4; signed:1;

	field:void * skbaddr;         offset:8;  size:8; signed:0;
	field:unsigned int len;       offset:16; size:4; signed:0;
	field:__data_loc char[] name; offset:20; size:4; signed:1;

print fmt: "dev=%s skbaddr=%p len=%u", __get_str(name), REC->skbaddr, REC->len
```

注意最后一行 `print fmt`，这正是 `perf trace` 打印相应消息的格式。

在底层插入这样的探测点之后，我们再写个 Python 脚本，接收内核发出来的消息，每个 eBPF 发出的数据都打印一行：

```
#!/usr/bin/env python
# coding: utf-8

from socket import inet_ntop
from bcc import BPF
import ctypes as ct

bpf_text = '''<SEE CODE SNIPPET ABOVE>'''

TASK_COMM_LEN = 16 # linux/sched.h

class RouteEvt(ct.Structure):
    _fields_ = [
        ("comm",    ct.c_char * TASK_COMM_LEN),
    ]

def event_printer(cpu, data, size):
    # Decode event
    event = ct.cast(data, ct.POINTER(RouteEvt)).contents

    # Print event
    print "Just got a packet from %s" % (event.comm)

if __name__ == "__main__":
    b = BPF(text=bpf_text)
    b["route_evt"].open_perf_buffer(event_printer)

    while True:
        b.kprobe_poll()
```

现在可以测试了，注意需要 root 权限。

**注意：现在的代码没有对包做任何过滤，因此即便你的机器网络流量很小，输出也很可能刷屏。**

```
$> sudo python ./tracepkt.py
...
Just got a packet from ping6
Just got a packet from ping6
Just got a packet from ping
Just got a packet from irq/46-iwlwifi
...
```

上面的输出显示，我正在使用 ping 和 ping6，另外 WiFi 驱动也收到了一些包。

### 3.4 自定义跟踪器：改进

接下来添加一些有用的数据/过滤条件。

#### 3.4.1 添加网卡信息

首先，可以安全地删除前面代码中的 `comm` 字段，它在这里没什么用处。然后，include `net/inet_sock.h` 头文件，这里有我们所需要的函数声明。最后给 `event` 结构体添加 `char ifname[IFNAMSIZ]` 字段。

现在可以从 `device` 结构体中访问 device name 字段。这里开始展示出**代码的强 大之处：我们可以访问任何受控范围内的字段。**

```
// Get device pointer, we'll need it to get the name and network namespace
struct net_device *dev;
bpf_probe_read(&dev, sizeof(skb->dev), ((char*)skb) + offsetof(typeof(*skb), dev));

// Load interface name
bpf_probe_read(&evt.ifname, IFNAMSIZ, dev->name);
```

现在你可以测试一下，这样是能工作的。注意相应地修改一下 Python 部分。那么，它是怎 么工作的呢？

我们引入了 `net_device` 结构体来访问**网卡名字**字段。第一个 `bpf_probe_read` 从内核 的网络包中将网卡名字拷贝到 `dev`，第二个将其接力复制到 `evt.ifname`。

不要忘了，eBPF 的目标是允许安全地编写在内核运行的脚本。这意味着，随机内存访问是绝 对不允许的。所有的内存访问都要经过验证。除非你要访问的内存在协议栈，否则你需要通 过 `bpf_probe_read` 读取数据。这会使得代码看起来很繁琐，但非常安全。`bpf_probe_read` 像是 `memcpy` 的一个更安全的版本，它定义在内核源文件 [bpf_trace.c](http://elixir.free-electrons.com/linux/v4.10.17/source/kernel/trace/bpf_trace.c#L64) 中:

1. 它和 memcpy 类似，因此注意内存拷贝的代价
2. 如果遇到错误，它会返回一个错误和一个初始化为 0 的缓冲区，而不会造成程序崩溃或停 止运行

接下来为使代码看起来更加简洁，我将使用如下宏：

```
#define member_read(destination, source_struct, source_member)                 \
  do{                                                                          \
    bpf_probe_read(                                                            \
      destination,                                                             \
      sizeof(source_struct->source_member),                                    \
      ((char*)source_struct) + offsetof(typeof(*source_struct), source_member) \
    );                                                                         \
  } while(0)
```

这样上面的例子就可以写成：

```
member_read(&dev, skb, dev);
```

#### 3.4.2 添加网络命名空间 ID

采集网络命名空间信息非常有用，但是实现起来要复杂一些。原理上可以从两个地方访问：

1. socket 结构体 `sk`
2. device 结构体 `dev`

当我在写 [`solisten.py`](https://github.com/iovisor/bcc/blob/master/tools/solisten.py)时 ，我使用的时 socket 结构体。不幸的是，不知道为什么，网络命名空间 ID 在跨命名空间的地 方消失了。这个字段全是 0，很明显是有非法内存访问时的返回值（回忆前面介绍的 `bpf_probe_read` 如何处理错误）。

幸好，device 结构体工作正常。想象一下，我们可以问一个 `packet` 它在哪个`网卡`，进而 问这个网卡它在哪个`网络命名空间`。

```
struct net* net;

// Get netns id. Equivalent to: evt.netns = dev->nd_net.net->ns.inum
possible_net_t *skc_net = &dev->nd_net;
member_read(&net, skc_net, net);
struct ns_common* ns = member_address(net, ns);
member_read(&evt.netns, ns, inum);
```

其中的宏定义如下：

```
#define member_address(source_struct, source_member) \
({                                                   \
  void* __ret;                                       \
  __ret = (void*) (((char*)source_struct) + offsetof(typeof(*source_struct), source_member)); \
  __ret;                                             \
})
```

这个宏还可以用于简化 `member_read`，这个就留给读者作为练习了。

好了，有了以上实现，我们再运行的效果就是：

```
$> sudo python ./tracepkt.py
[  4026531957]          docker0
[  4026531957]      vetha373ab6
[  4026532258]             eth0
[  4026532258]             eth0
[  4026531957]      vetha373ab6
[  4026531957]          docker0
```

如果 ping 一个容器，你看到的就是类似上面的输出。packet 首先经过本地的 docker0 网桥， 然后经 veth pair 跨过网络命名空间，最后到达容器的 eth0 网卡。应答包沿着相反的路径回 到宿主机。

至此，功能是实现了，不过还太粗糙，继续改进。

#### 3.4.3 只跟踪 ICMP echo request/reply 包

这次我们将读取包的 IP 信息，这里我只展示 IPv4 的例子，IPv6 的与此类似。

不过，事情也并没有那么简单。我们是在和 kernel 的网络部分打交道。一些包可能还没被打 开，这意味着，变量的很多字段是没有初始化的。我们只能从 MAC 头开始，用 offset 的方式 计算 IP 头和 ICMP 头的位置。

首先从 MAC 头地址推导 IP 头地址。这里我们不(从 `skb` 的相应字段)加载 MAC 头长度信息，就认为 它是固定的 14 字节。

```
// Compute MAC header address
char* head;
u16 mac_header;

member_read(&head,       skb, head);
member_read(&mac_header, skb, mac_header);

// Compute IP Header address
#define MAC_HEADER_SIZE 14;
char* ip_header_address = head + mac_header + MAC_HEADER_SIZE;
```

这表示我们假设 IP 头开始的地方在：`skb->head + skb->mac_header + MAC_HEADER_SIZE` 。 现在，我们可以解析 IP 头第一个字节的前 4 个 bit：

```
// Load IP protocol version
u8 ip_version;
bpf_probe_read(&ip_version, sizeof(u8), ip_header_address);
ip_version = ip_version >> 4 & 0xf;

// Filter IPv4 packets
if (ip_version != 4) {
    return 0;
}
```

然后加载整个 IP 头，获取 IP 地址，以使得 Python 程序的输出看起来更有意义。另外注意，IP 包内的下一个头就是 ICMP 头。

```
// Load IP Header
struct iphdr iphdr;
bpf_probe_read(&iphdr, sizeof(iphdr), ip_header_address);

// Load protocol and address
u8 icmp_offset_from_ip_header = iphdr.ihl * 4;
evt.saddr[0] = iphdr.saddr;
evt.daddr[0] = iphdr.daddr;

// Filter ICMP packets
if (iphdr.protocol != IPPROTO_ICMP) {
    return 0;
}
```

最后，我们加载 ICMP 头，如果是 ICMP echo request 或 reply，就读取序列号：

```
// Compute ICMP header address and load ICMP header
char* icmp_header_address = ip_header_address + icmp_offset_from_ip_header;
struct icmphdr icmphdr;
bpf_probe_read(&icmphdr, sizeof(icmphdr), icmp_header_address);

// Filter ICMP echo request and echo reply
if (icmphdr.type != ICMP_ECHO && icmphdr.type != ICMP_ECHOREPLY) {
    return 0;
}

// Get ICMP info
evt.icmptype = icmphdr.type;
evt.icmpid   = icmphdr.un.echo.id;
evt.icmpseq  = icmphdr.un.echo.sequence;

// Fix endian
evt.icmpid  = be16_to_cpu(evt.icmpid);
evt.icmpseq = be16_to_cpu(evt.icmpseq);
```

这就是全部工作了。

如果你想过滤特定的 ping 进程的包，你可以认为 `evt.icmpid` 就是相应 ping 进程的进程号， 至少 Linux 上如此。

### 3.5 最终效果

再写一些比较简单的 Python 程序配合，我们就可以测试我们的跟踪器在多种场景下的用途。 以 root 权限启动这个程序，在不同终端发起几个 ping 进程，就会看到：

```
# ping -4 localhost
[  4026531957]               lo request #20212.001 127.0.0.1 -> 127.0.0.1
[  4026531957]               lo request #20212.001 127.0.0.1 -> 127.0.0.1
[  4026531957]               lo   reply #20212.001 127.0.0.1 -> 127.0.0.1
[  4026531957]               lo   reply #20212.001 127.0.0.1 -> 127.0.0.1
```

这个 ICMP 请求是进程 20212（Linux ping 的 ICMP ID）在 loopback 网卡发出的，最后的 reply 原路回到了这个 loopback。这个环回接口既是发送网卡又是接收网卡。

如果是我的 WiFi 网关会是什么样子内？

```
# ping -4 192.168.43.1
[  4026531957]           wlp2s0 request #20710.001 192.168.43.191 -> 192.168.43.1
[  4026531957]           wlp2s0   reply #20710.001 192.168.43.1 -> 192.168.43.191
```

可以看到，这种情况下走的是 WiFi 网卡，也没问题。

另外，让我们的话题稍微偏一下，还记得刚开始我们只打印程序名字的版本吗？在 上面这种情况下，ICMP 请求的程序名字会是 ping，而应答包的程序的名字会是 WiFi 驱动，因 为是驱动发的应答包，至少 Linux 上是如此。

最后还是拿我最喜欢的例子：ping 容器。之所以最喜欢并不是因为 Docker，而是它展示了 eBPF 的强大，**就像给 ping 过程做了一次 X 射线检查**。

```
# ping -4 172.17.0.2
[  4026531957]          docker0 request #17146.001 172.17.0.1 -> 172.17.0.2
[  4026531957]      vetha373ab6 request #17146.001 172.17.0.1 -> 172.17.0.2
[  4026532258]             eth0 request #17146.001 172.17.0.1 -> 172.17.0.2
[  4026532258]             eth0   reply #17146.001 172.17.0.2 -> 172.17.0.1
[  4026531957]      vetha373ab6   reply #17146.001 172.17.0.2 -> 172.17.0.1
[  4026531957]          docker0   reply #17146.001 172.17.0.2 -> 172.17.0.1
```

来点 ASCII 艺术，就变成：

```
       Host netns           | Container netns
+---------------------------+-----------------+
| docker0 ---> veth0e65931 ---> eth0          |
+---------------------------+-----------------+
```

## 4 结束语

在 eBPF/bcc 出现之前，要深入的排查和追踪很多网络问题，只能靠给内核打补丁。现在，我 们可以比较方便地用 eBPF/bcc 编写一些工具来完成这些事情。跟踪点(tracepoint)也很方便 ，它们提示了我们可以在哪些地方进行探测，避免了去看繁杂的内核代码。kprobe 无法探测 的一些地方，例如一些内联函数和静态函数，eBPF/bcc 也可以探测。

本文的例子要添加对 IPv6 的支持也非常简单，我就留给读者作为练习。

如果要使本文更加完善的话，我需要对我们的程序做性能测试。但考虑到文章本身已经非常 长，这里就不做了。

对我们的代码进行改进，用在跟踪路由和 iptables 判决，或是 ARP 包，也是很有意思的。 这将会把它变成一个完美的 X 射线跟踪器，对像我这样需要经常处理复杂网络问题的 人来说将非常有用。

完整的（包含 IPv6 支持）代码可以访问： https://github.com/yadutaf/tracepkt。

最后，我要感谢 [@fcabestre](https://twitter.com/fcabestre)帮我将这篇文章的草稿从 一个异常的硬盘上恢复出来，感谢[@bluxte](https://twitter.com/bluxte)的耐心审读， 以及技术上使得本文成为可能的[bcc](https://github.com/iovisor/bcc)团队。
