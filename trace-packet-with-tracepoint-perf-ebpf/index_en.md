# Tracing a packet journey using Linux tracepoints, perf and eBPF

> 原文来自：https://blog.yadutaf.fr/2017/07/28/tracing-a-packet-journey-using-linux-tracepoints-perf-ebpf/

Jul 28, 2017  #[linux](https://blog.yadutaf.fr/tags/linux) #[netns](https://blog.yadutaf.fr/tags/netns) #[docker](https://blog.yadutaf.fr/tags/docker) #[ebpf](https://blog.yadutaf.fr/tags/ebpf) 

I’ve been looking for a low level Linux network debugging tool for quite some time. Linux allows to build complex networks running directly on the host, using a combination of virtual interfaces and [network namespaces](https://blog.yadutaf.fr/2014/01/19/introduction-to-linux-namespaces-part-5-net/). When something goes wrong, troubleshooting is rather tedious. If this is a L3 routing issue, `mtr` has a good chance of being of some help. But if this is a lower level issue, I typically end up manually checking each interface / bridge / network namespace / iptables and firing up a couple of tcpdumps as an attempt to get a sense of what’s going on. If you have no prior knowledge of the network setup, this may feel like a maze.

What I’d need is a tool which could tell me “Hey, I’ve seen your packet: It’s gone this way, on this interface, in this network namespace”.

Basically, what I’d need is a `mtr` for L2.

Does not exist? Let’s build one!

At the end of this post, we’ll have a simple and easy to use low level packet tracer. If you ping a local Docker container, it will show something like:

```
# ping -4 172.17.0.2
[  4026531957]          docker0 request #17146.001 172.17.0.1 -> 172.17.0.2
[  4026531957]      vetha373ab6 request #17146.001 172.17.0.1 -> 172.17.0.2
[  4026532258]             eth0 request #17146.001 172.17.0.1 -> 172.17.0.2
[  4026532258]             eth0   reply #17146.001 172.17.0.2 -> 172.17.0.1
[  4026531957]      vetha373ab6   reply #17146.001 172.17.0.2 -> 172.17.0.1
[  4026531957]          docker0   reply #17146.001 172.17.0.2 -> 172.17.0.1
```

### Tracing to the rescue

One way to get out of a maze, is by exploring. This is what you do when getting out of the maze is part of a game. Another way to get out is to shift your point of view, looking from above, and observing the path taken by those who know the path.

In Linux terms, that would mean shifting to the kernel point of view, where network namespaces are just labels, instead of “containers”[1](https://blog.yadutaf.fr/2017/07/28/tracing-a-packet-journey-using-linux-tracepoints-perf-ebpf/#fn:722df47ecbedbece281b05064cb93eb9:containers). In the kernel, packets, interfaces and so on are plain observable objects.

In this post, I’ll focus on 2 tracing tools. `perf` and `eBPF`.

### Introducing `perf` and `eBPF`

`perf` is a the baseline tool for every performance related analysis on Linux. It is developed in the same source tree as the Linux kernel and must be specifically compiled for the kernel you will use to trace. It can trace the kernel as well as user programs. It may also work by sampling or using tracepoints. Think of it as a massive superset of `strace` with a much lower overhead. We’ll use it only in a very simple way here. If you want to know more about `perf`, I highly encourage you to [visit Brendan Gregg’s blog](http://www.brendangregg.com/perf.html).

`eBPF` is a relatively recent addition to the Linux Kernel. As its name suggests, this is an extended version of the BPF bytecode known as “Berkeley Packet Filter” used to… filter packets on the BSD family. You name it. On Linux, it can also be used to safely run platform independent code in the live kernel, provided that it meets some safety criteria. For instance, memory accesses are validated BEFORE the program can run and it must be possible to prove that the program will end in a restricted amount of time. If the kernel can’t prove it, even if it’s safe and always terminates, it will be rejected.

Such programs can be used as network classifier for QOS, very low level networking and filtering as part of eXpress Data Plane (XDP), as a tracing agent and many other places. Tracing probes can be attached to any function whose symbol is exported in `/proc/kallsyms` or any tracepoints. In this post, I’ll focus on tracing agents attached to tracepoints.

For an example of tracing probe attached to a kernel function or as a gentler introduction, I invite you to [read my previous post on eBPF](https://blog.yadutaf.fr/2016/03/30/turn-any-syscall-into-event-introducing-ebpf-kernel-probes/).

### Lab setup

For this post, we need `perf` and some tools to work with eBPF. As I’m not a great fan of handwritten assembly, I’ll use [`bcc`](https://github.com/iovisor/bcc) here. This is a powerful and flexible tool allowing you to write kernel probes as restricted C and instrument them in userland with Python. Heavyweight for production, but perfect for development!

I’ll reproduce here install instructions for Ubuntu 17.04 (Zesty) which is the OS powering my laptop. Instructions for “perf” should not diverge much from distributions to other and specific [`bcc` install instructions can be found on Github](https://github.com/iovisor/bcc/blob/master/INSTALL.md).

> Note: attaching eBPF to tracepoints requires at least Linux kernel > 4.7.

Install `perf`:

```bash
# Grab 'perf'
sudo apt install linux-tools-generic

# Test it
perf
```

If you see an error message, it probably means that your kernel was updated recently but you did not reboot yet.

Install `bcc`:

```bash
# Install dependencies
sudo apt install bison build-essential cmake flex git libedit-dev python zlib1g-dev libelf-dev libllvm4.0 llvm-dev libclang-dev luajit luajit-5.1-dev

# Grab the sources
git clone https://github.com/iovisor/bcc.git

# Build and install
mkdir bcc/build
cd bcc/build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr
make
sudo make install
```

### Finding good tracepoints aka as “manually tracing a packet’s journey with `perf`“

There are multiple ways to find good tracepoints. In a previous version of this post, I started from the code of the `veth` driver and followed the trail from there to find functions to trace. While it did lead to acceptable results, I could not catch all the packets. Indeed, the common paths crossed by all packets are in un-exported (inline or static) methods. This is also when I realized Linux had tracepoints and decided to rewrite this post and the associated code using tracepoints instead. This was quite frustrating, but also much more interesting (to me).

Enough talks on myself, back to work.

The goal is to trace the path taken by a packet. Depending on the crossed interfaces, the crossed tracepoints may differ (spoiler alert: they do).

To find suitable tracepoints, I used ping with 2 internal and 2 external targets under `perf trace`:

1. localhost with IP *127.0.0.1*
2. An innocent Docker container with IP *172.17.0.2*
3. My phone via USB tethering with IP *192.168.42.129*
4. My phone via WiFi with IP *192.168.43.1*

`perf trace` is a sub command of perf, which produces an output similar to strace (with a MUCH lower overhead) by default. We can easily tweak it to hide the syscalls themselves and instead print events of the ‘net’ category. For instance, tracing a ping to a Docker container with IP 172.17.0.2 would look like:

```
sudo perf trace --no-syscalls --event 'net:*' ping 172.17.0.2 -c1 > /dev/null
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

Keeping only the event names and skbaddr, this looks more readable.

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

There are multiple things to be said here. The most obvious being that the `skbaddr` changes in the middle, but stays the same otherwise. This is when the echo reply packet is generated as a reply to this echo request (ping). The rest of the time, the same network packet is moved between interfaces, with hopefully no copy. Copying is expensive…

The other interesting point is, we clearly see the packet going through the `docker0` bridge, then the host side of the veth, `veth79215ff` in my case, and finally the container side of the veth, pretending to be `eth0`. We don’t see the network namespaces yet, but it already gives a good overview.

Finally, after seeing the packet on `eth0` we hit tracepoints in reverse order. This is not the response, but the finalization of the transmission.

By repeating a similar process on the 4 target scenarios, we can pick the most appropriate tracing points to track our packet’s journey. I picked 4 of them:

- `net_dev_queue`
- `netif_receive_skb_entry`
- `netif_rx`
- `napi_gro_receive_entry`

Taking these 4 tracepoints will give me trace events in order with no duplication, saving some de-duplication work. Still good to take.

We can easily double check this selection like:

```
sudo perf trace --no-syscalls           \
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
     0.045 net:netif_receive_skb_entry:dev=docker0 napi_id=0x1 queue_mapping=0 skbaddr=0xffff8e849cb8cd00 vlan_tagged=0 vlan_proto=0x0000 vlan_tci=0x0000 protocol=0x0800 ip_summed=2 hash=0x00000000 l4_hash=0 len=84 data_len=0 truesize=768 mac_header_valid=1 mac_header=-14 nr_frags=0 gso_size=0 gso_type=0)
```

Mission accomplished!

If you want to go further and explore a list of available network tracepoints, you may user `perf list`:

```bash
sudo perf list 'net:*'
```

This should return a list of tracepoints names like `net:netif_rx`. The part before the colon (’:‘) is the event category (‘net’). The part after is the event name, in this category.

### Writing a custom tracer with `eBPF` / `bcc`

This would be more than enough for most situations. If you were reading this post to learn how to trace a packet’s journey on a Linux box, you already got all you need. But, if you want to dive deeper, run a custom filter, track more data like the network namespaces crossed by the packets or the source and destination IPs, please, bear with me.

Starting with Linux Kernel 4.7, eBPF programs can be attached to kernel tracepoints. Before that, the only alternative to build this tracer would have been to attach the probes to exported kernel symbols. While this could work, it would have a couple of drawbacks:

1. The kernel internal API is not stable. Tracepoints are (although the data structures ae not necessarily…).
2. For performance reasons, most of the networking inner functions are inlined or static. Neither of which can be probed.
3. It is tedious to find all potential call sites for this functions, and sometime not all required data is available at this stage.

An earlier version of this post attempted to use kprobes, which are easier to use, but the results were at best incomplete.

Now, let’s be honest, accessing data via tracepoints is a lot more tedious than with there kprobe counterpart. While I tried to keep this post as gentle as possible, you may want to start with the (slightly older) post [“How to turn any syscall into an event: Introducing eBPF Kernel probes”](https://blog.yadutaf.fr/2016/03/30/turn-any-syscall-into-event-introducing-ebpf-kernel-probes/).

This disclaimer aside, let’s start with a simple hello world and get the low level plumbing into place. In this hello world, we’ll build an event every time 1 of the 4 tracepoints we chose earlier (`net_dev_queue`, `netif_receive_skb_entry`, `netif_rx` and `napi_gro_receive_entry`) is triggered. To keep things simple at this stage, we’ll send the program’s `comm`, that is, a 16 char string that’s basically the program name.

```c
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

This snippet attaches to the 4 tracepoints of the “net” category, loads the `skbaddr` field and passes it to the common section which only loads the program name for now. If you wonder where this `args->skbaddr` come from (and I’d be glad you do), the `args` structure is generated for you by bcc whenever you define a tracepoint with `TRACEPOINT_PROBE`. As it is generated on the fly, there is no easy way to see its definition BUT, there is a better way. We can directly look at the data source, from the kernel. Fortunately there is a `/sys/kernel/debug/tracing/events` entry for each tracepoint. For instance, for the `net:netif_rx`, one could just “cat” `/sys/kernel/debug/tracing/events/net/netif_rx/format` which should output something like this:

```
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

You may notice the `print fmt` line at the end of the record. This is exactly what’s used by `perf trace` to generate its output.

With the low level plumbing in place and well understood, we can wrap it in a Python script to display a line for every event send by the eBPF side of the probe:

```python
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

You may test it now. You will need to be root.

> Note: There is no filtering at this stage. Even a low background network usage may flood your terminal!

```
$> sudo python ./tracepkt.py
...
Just got a packet from ping6
Just got a packet from ping6
Just got a packet from ping
Just got a packet from irq/46-iwlwifi
...
```

In this case, you can see that I was using ping and ping6 and the WiFi driver just received some packets. In that case, that was the echo reply.

Let’s start adding some useful data / filters.

I will not focus on performance in this post. This will better demonstrate the the power and limitations of eBPF. To make it (much) faster, we could use the packet size as a heuristic, assuming there is no strange IP options. Using the example programs as is will slow down your network traffic.

> Note: to limit the length of this post, I’ll focus on the C/eBPF part here. I’ll put a link to the full source code at the end of this post.

### Add in network interface information

First, you can safely remove the “comm” fields, loading and sched.h header. It’s of no real use here, sorry.

Then you can include `net/inet_sock.h` so that we have all necessary declarations and add `char ifname[IFNAMSIZ];` to the event structure.

We’ll now load the device name from the device structure. This is interesting as this is an actually useful piece of information and it demonstrates on a manageable scale the techniques to load any data:

```c
// Get device pointer, we'll need it to get the name and network namespace
struct net_device *dev;
bpf_probe_read(&dev, sizeof(skb->dev), ((char*)skb) + offsetof(typeof(*skb), dev));

// Load interface name
bpf_probe_read(&evt.ifname, IFNAMSIZ, dev->name);
```

You can test it, it works as is. Do not forget to add the related part on the Python side though :)

OK, so how does it work? To load the interface name, we need the interface device structure. I’ll start from the last statement as it’s the easiest to understand and the previous one is actually just or trickier version. It uses `bpf_probe_read` to read data of length `IFNAMSIZ` from `dev->name` and copy it to `evt.ifname`. The fist line follows exactly the same logic. It loads the value of the `skb->dev` pointer into `dev`. Unfortunately, I could not find another way to load the field address without this nice offsetof / typeof tricks.

As a reminder, the goal of eBPF is to allow *safe* scripting of the kernel. This implies that random memory access are forbidden. All memory accesses must be validated. Unless the memory you access in on the stack, you need to use the `bpf_probe_read` read accessor. This makes to code cumbersome to read / write but makes it safe too. `bpf_probe_read` is somehow like a safe version of `memcpy`. It is defined in [bpf_trace.c in the kernel](http://elixir.free-electrons.com/linux/v4.10.17/source/kernel/trace/bpf_trace.c#L64). The interesting parts being:

1. It’s like memcpy. Beware of the cost of copies on performance.
2. In case of error, it will return a buffer initialized to 0 and return an error. It will *not* crash or stop the program.

For the remaining parts of this post, I’ll use the following macro to help keep things readable:

```c
#define member_read(destination, source_struct, source_member)                 \
  do{                                                                          \
    bpf_probe_read(                                                            \
      destination,                                                             \
      sizeof(source_struct->source_member),                                    \
      ((char*)source_struct) + offsetof(typeof(*source_struct), source_member) \
    );                                                                         \
  } while(0)
```

Which allows us to write:

```c
member_read(&dev, skb, dev);
```

That’s better!

### Add in the network namespace ID

That’s probably the most valuable piece of information. In itself, it is a valid reason to all these efforts. Unfortunately, this is also the hardest to load.

The namespace identifier can be loaded from 2 places:

1. the socket ‘sk’ structure
2. the device ‘dev’ structure

I was initially using the socket structure as this is the one I was using when writing [solisten.py](https://github.com/iovisor/bcc/blob/master/tools/solisten.py). Unfortunately, and I’m not sure why, the namespace identifier is no longer readable as soon as the packet crosses a namespace boundary. The field is all 0s, which is a clear indicator of an invalid memory access (remember how bpf_probe_read works in case of errors) and defeats the whole point.

Fortunately, the device approach works. Think of it like asking the packet on which interface it is and asking the interface in which namespace it belongs.

```c
struct net* net;

// Get netns id. Equivalent to: evt.netns = dev->nd_net.net->ns.inum
possible_net_t *skc_net = &dev->nd_net;
member_read(&net, skc_net, net);
struct ns_common* ns = member_address(net, ns);
member_read(&evt.netns, ns, inum);
```

Which uses the following additional macro for improved readability:

```c
#define member_address(source_struct, source_member) \
({                                                   \
  void* __ret;                                       \
  __ret = (void*) (((char*)source_struct) + offsetof(typeof(*source_struct), source_member)); \
  __ret;                                             \
})
```

As a side effect, it allows to simplify the `member_read` macro. I’ll leave it as an exercise for the reader.

Plug this together, and… Tadaa!

```
$> sudo python ./tracepkt.py
[  4026531957]          docker0
[  4026531957]      vetha373ab6
[  4026532258]             eth0
[  4026532258]             eth0
[  4026531957]      vetha373ab6
[  4026531957]          docker0
```

This is what you should see if you send a ping to a Docker container. The packet goes through the local `docker0` bridge and then moves to the the `veth` pair, crossing the network namespace boundary and the reply follows the exact reverse path.

That was a nasty one!

### Going further: trace only requests reply and echo replies packets

As a bonus, we’ll also load the IP from the packets. We have to read the IP header anyway. I’ll stick to IPv4 here, but the same logic applies for IPv6.

Bad news is, nothing is really simple. Remember, we are dealing with the kernel, in the network path. Some packets have not yet been opened. This means that some headers offsets are still uninitialized. We’ll have to compute all of them, going from the MAC header to the IP header and finally to the ICMP header.

Let’s start gently by loading the MAC header address and deducing the IP header address. We won’t load the MAC header itself and instead assume it is 14 bytes long.

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

This basically means that the IP header starts at `skb->head + skb->mac_header + MAC_HEADER_SIZE;`.

We can now decode the IP version in the first 4 bits of the IP header, that is, the first half of the first byte, and make sure it is IPv4:

```c
// Load IP protocol version
u8 ip_version;
bpf_probe_read(&ip_version, sizeof(u8), ip_header_address);
ip_version = ip_version >> 4 & 0xf;

// Filter IPv4 packets
if (ip_version != 4) {
    return 0;
}
```

We now load the full IP header, grab the IPs to make the Python info even more useful, make sure the next header is ICMP and derive the ICMP header offset. Yes all this:

```c
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

Finally, we can load the ICMP header itself, make sure this is an echo request of reply and load the id and seq from it:

```c
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

That’s all folks!

If you want to filter ICMP from a specific ping instance, you may assume `evt.icmpid` [is the PID of the ping](https://github.com/iputils/iputils/blob/master/ping_common.c) at least using Linux’s ping.

### Show time!

With some straightforward Python to handle the event, we can test it in a couple of scenarios. Start the program as root, launch some “ping” in another terminal and observe:

```
# ping -4 localhost
[  4026531957]               lo request #20212.001 127.0.0.1 -> 127.0.0.1
[  4026531957]               lo request #20212.001 127.0.0.1 -> 127.0.0.1
[  4026531957]               lo   reply #20212.001 127.0.0.1 -> 127.0.0.1
[  4026531957]               lo   reply #20212.001 127.0.0.1 -> 127.0.0.1
```

An ICMP echo request is sent by process 20212 (the ICMP id on Linux’s ping) on the loopback interface, delivered to the very same loopback interface where an echo reply is generated and sent back. The loopback interface is both the emitting and receiving interface.

What about my WiFi gateway?

```
# ping -4 192.168.43.1
[  4026531957]           wlp2s0 request #20710.001 192.168.43.191 -> 192.168.43.1
[  4026531957]           wlp2s0   reply #20710.001 192.168.43.1 -> 192.168.43.191
```

In this case, the echo request and echo reply go through the WiFi interface. Easy.

On a slightly unrelated note, remember when we were only printing the “comm” of the process owning the packet? In this case, the echo request would belong to ping process while the reply would belong to the WiFi driver as this is the one generating it as far as Linux is concerned.

And the last one, my personal favorite, ping a Docker container. It’s not my favorite because of Docker. It is my favorite because it best shows the the power of eBPF. It allowed to build an “x-ray” like tool for ping.

```
# ping -4 172.17.0.2
[  4026531957]          docker0 request #17146.001 172.17.0.1 -> 172.17.0.2
[  4026531957]      vetha373ab6 request #17146.001 172.17.0.1 -> 172.17.0.2
[  4026532258]             eth0 request #17146.001 172.17.0.1 -> 172.17.0.2
[  4026532258]             eth0   reply #17146.001 172.17.0.2 -> 172.17.0.1
[  4026531957]      vetha373ab6   reply #17146.001 172.17.0.2 -> 172.17.0.1
[  4026531957]          docker0   reply #17146.001 172.17.0.2 -> 172.17.0.1
```

With some art, it now looks like:

```
       Host netns           | Container netns
+---------------------------+-----------------+
| docker0 ---> veth0e65931 ---> eth0          |
+---------------------------+-----------------+
```

### Final word

eBPF/bcc enables us to write a new range of tools to deeply troubleshoot, trace and track issues in places previously unreachable without patching the kernel. Tracepoints are also quite handy as they give a good hint on interesting places, removing the need to tediously read the kernel code and can be placed in portions of the code that would otherwise be unreachable from kprobes, like inline or static functions.

To go further, we could add IPv6 support. This is quite easy to do and I’ll leave it as an exercise for the reader. Ideally, I’d like to measure the impact on performance as well. But this post is already very, very long. It could be interesting to improve this tool by tracing routing and iptables decisions and tracing ARP packets. All this would turn this tool into a perfect “x-ray” packet tracer for people like me, sometime struggling with non-trivial Linux network setups.

As promised, you can see the full code (with IPv6 support) on Github: https://github.com/yadutaf/tracepkt

Finally, I’d like to acknowledge the help of [@fcabestre](https://twitter.com/fcabestre) who helped me rescue the working draft of this post from a malfunctioning hard disk, [@bluxte](https://twitter.com/bluxte) for his patient proof reading and the people of [bcc](https://github.com/iovisor/bcc) who made this post technically possible.

### Note(s)

------

1. I’ve put “containers” into quotes as, technically speaking, network namespaces are one of the many building blocks of Linux containers. [[return\]](https://blog.yadutaf.fr/2017/07/28/tracing-a-packet-journey-using-linux-tracepoints-perf-ebpf/#fnref:722df47ecbedbece281b05064cb93eb9:containers)

← [Docker for your users - Introducing user namespace](http://blog.yadutaf.fr/2016/04/14/docker-for-your-users-introducing-user-namespace/) [About me](http://blog.yadutaf.fr/about/) →