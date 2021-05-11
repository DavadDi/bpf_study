---
title: "BPF 二进制文件：BTF，CO-RE 和 BPF 性能工具的未来【译】"
date: 2021-03-25T10:32:04+08:00
keywords:
- bpf
- btf
- core
description : "BTF 和 CO-RE 这两项新技术为 BPF 成为价值十亿美元的产业铺平了道路。目前，有许多 BPF（eBPF）初创公司正在构建网络，安全性和性能产品（并且更多未浮出水面的），但是要求客户安装 LLVM，Clang 和内核头文件依赖（可能消耗超过100 MB的存储空间）是一个额外的负担。 BTF 和 CO-RE 在运行时消除了这些依赖关系，不仅使 BPF 在嵌入式 Linux 环境中更加实用，而且在任何地方都可以使用。"
tags: []
categories: ["BPF","foundation"]
---

作者： [Brendan Gregg](http://www.brendangregg.com/blog/index.html)

## 1. 简述

BTF 和 CO-RE 这两项新技术为 BPF 成为价值十亿美元的产业铺平了道路。目前，有许多 BPF（eBPF）初创公司正在构建网络，安全性和性能产品（并且更多未浮出水面的），但是要求客户安装 LLVM，Clang 和内核头文件依赖（可能消耗超过100 MB的存储空间）是一个额外的负担。 BTF 和 CO-RE 在运行时消除了这些依赖关系，不仅使 BPF 在嵌入式 Linux 环境中更加实用，而且在任何地方都可以使用。

这些技术是：

* **BTF**：BPF 类型格式，它提供结构信息以避免 Clang 和内核头文件依赖。
* **CO-RE**：BPF Compile-Once Run-Everywhere，它使已编译的 BPF 字节码可重定位，从而避免了 LLVM 重新编译的需要。
  仍然需要 Clang 和 LLVM 进行编译，但是结果是一个轻量级的 ELF 二进制文件，其中包含预编译的 BPF 字节码，并且可以在任何地方运行。 BCC 项目包含这些工具的集合，称为 libbpf 工具。作为示例，我移植了我开发的opensnoop（8）工具：

```bash
# ./opensnoop
PID    COMM              FD ERR PATH
27974  opensnoop         28   0 /etc/localtime
1482   redis-server       7   0 /proc/1482/stat
1657   atlas-system-ag    3   0 /proc/stat
[…]
```


opensnoop（8）是不使用 libLLVM 或 libclang 的 ELF 二进制文件：

```bash
# file opensnoop
opensnoop: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=b4b5320c39e5ad2313e8a371baf5e8241bb4e4ed, with debug_info, not stripped

# ldd opensnoop
    linux-vdso.so.1 (0x00007ffddf3f1000)
    libelf.so.1 => /usr/lib/x86_64-linux-gnu/libelf.so.1 (0x00007f9fb7836000)
    libz.so.1 => /lib/x86_64-linux-gnu/libz.so.1 (0x00007f9fb7619000)
    libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f9fb7228000)
    /lib64/ld-linux-x86-64.so.2 (0x00007f9fb7c76000)

# ls -lh opensnoop opensnoop.stripped
-rwxr-xr-x 1 root root 645K Feb 28 23:18 opensnoop
-rwxr-xr-x 1 root root 151K Feb 28 23:33 opensnoop.stripped
```

...最后文件大小仅为 151 KB。

现在想象一个 BPF 产品：BPF 代理现在可以是单个微小的二进制文件，它可以在任何具有 BTF 的内核上运行，而不是要求客户安装各种重量级（且脆弱）的依赖项。

## 2. 这是如何工作的？

这不仅仅是将 BPF 字节码保存在 ELF 中，然后将其发送到任何其他内核的问题。许多 BPF 程序会使用可从一种内核版本更改为另一种内核版本的内核结构。BPF 字节码可能仍然可以不同的内核上执行，但是其可能会读取错误的结构偏移量并打印错误输出！ opensnoop（8）不会遍历内核结构，因为它可以检测稳定的跟踪点及其参数，但是许多其他工具都需要遍历内核结构。

这涉及到重定位问题，BTF 和 CO-RE 都针对 BPF 二进制文件解决了此问题。 BTF 提供类型信息，以便可以根据需要查询结构偏移量和其他详细信息，并且 CO-RE 记录需要重写 BPF 程序的哪些部分以及如何重写。 CO-RE 开发人员 Andrii Nakryiko 已撰写了很长的帖子，更深入地解释了这一点：[BPF 可移植性以及 CO-RE](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html) （[本站地址见这里](https://www.ebpf.top/post/bpf_core/)) 和 [BTF 类型信息](https://facebookmicrosites.github.io/bpf/blog/2018/11/14/btf-enhancement.html)。



## 3. CONFIG_DEBUG_INFO_BTF = y
新的 BPF 二进制文件仅在设置了此内核配置选项后才可用。该选项为内核映像增加了约 1.5 MB（这与数百 M的 DWARF debuginfo 相比可能很小）。Ubuntu 20.10 已经将此配置选项设置为默认选项，所有其他发行版都应遵循。发行维护者的注意事项：它需要 pahole >= 1.16。



## 4. BPF 性能工具，BCC Python 和 bpftrace 的未来

对于 BPF 性能工具，你应该从运行 BCC 和 bpftrace 工具开始，然后在 bpftrace 中进行编码。 BCC 工具最终应该在后台实现上从 Python 切换到 libbpf C，但是仍然可以正常使用。现在，随着我们转向带有 BTF 和 CO-RE 的l ibbpf C，**已经不赞成使用 BCC Python 中的性能工具**（尽管我们仍需要继续完善库的功能，例如对 USDT 的支持，因此需要一段时间才能使用 Python 版本）。请注意，还有其他 BCC 用例可能会继续使用 Python 接口。 BPF 的共同维护者 Alexei Starovoitov 和我本人在 [iovisor-dev](https://lists.iovisor.org/g/iovisor-dev/topic/future_of_bcc_python_tools/77827559?p=,,,20,0,0,0::recentpostdate%2Fsticky,,,20,2,0,77827559) 上对此进行了简短的讨论。

我的 《BPF Performance Tools》书籍着重于运行 BCC 工具和在 bpftrace 中进行编码，并且这没有改变。但是，现在认为**附录 C 的 Python 编程示例已被弃用**。造成的不便，深表歉意，幸运的是，这本 880 页的书中只有 15 页相关的附录材料。

bpftrace 呢？它确实支持 BTF，并且将来我们还将考虑减少其安装空间（目前可以达到 29 MB，并且我们认为它可以减小很多）。假设平均 libbpf 程序大小为 229 KB（基于当前的 libbpf 工具，已经经过 strippe），平均bpftrace 程序大小为 1KB（我图书中的工具），则有大量 bpftrace 工具加上与 libbpf 中的等效工具相比，bpftrace 二进制文件可能会占用较小的安装空间。再加上 bpftrace 版本可以随时修改。 libbpf 更适合需要自定义参数和库的更复杂，更成熟的工具。

如屏幕截图所示，BPF性能工具的未来是这样的：

```bash
# ls /usr/share/bcc/tools /usr/sbin/*.bt
argdist       drsnoop         mdflush         pythongc     tclobjnew
bashreadline  execsnoop       memleak         pythonstat   tclstat
[...]
/usr/sbin/bashreadline.bt    /usr/sbin/mdflush.bt    /usr/sbin/tcpaccept.bt
/usr/sbin/biolatency.bt      /usr/sbin/naptime.bt    /usr/sbin/tcpconnect.bt
[...]
```


... 还有这个：

```bash
# bpftrace -e 'BEGIN { printf("Hello, World!\n"); }'
Attaching 1 probe...
Hello, World!
^C
```

...而不是这样：

```python
#!/usr/bin/python

from bcc import BPF
from bcc.utils import printb

prog = """
int hello(void *ctx) {
    bpf_trace_printk("Hello, World!\\n");
    return 0;
}
"""
[...]
```

感谢 Song Yonghong（Facebook）领导 BTF 的开发，Andrii Nakryiko（Facebook）领导 CO-RE 的开发，以及参与实现这一目标的其他所有人。



原文地址： http://www.brendangregg.com/blog/2020-11-04/bpf-co-re-btf-libbpf.html