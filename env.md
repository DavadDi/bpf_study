---
title: 'BPF 环境搭建'
tags: []
categories: ["BPF"]
date: "2020-11-10"
---

## 1. 内核版本选择

* **补丁 Prepatch**： 
  Prepatch 或 "RC" 内核是主线内核的预发布版本，主要针对其他内核开发者和 Linux 爱好者。它们必须从源码中编译，并且通常包含新的功能，这些功能必须在稳定发布之前进行测试。Prepatch 内核由 Linus Torvalds 维护和发布。

* **主线版 Mainline**：
  主线版本由 Linus Torvalds 维护。它是介绍所有新功能的版本，包含了所有令人兴奋的新开发的功能。新的主线内核每 2-3 个月发布一次。

* **稳定版 Stable**：
  每一个主线内核发布后，它都被认为是 "稳定的"。任何稳定内核的错误修复都会从主线版本上回溯，并由指定的稳定内核维护者应用。在下一个主线内核可用之前，通常只有几个错误修复内核的发布 -- 除非它被指定为 "长期维护内核"。稳定的内核更新是根据需要发布的，通常一周一次。

* **长期版 Longterm**：
  通常会有几个 "长期维护 "的内核版本，目的是为旧内核树的错误进行后向（backporting）修正。只有重要的bug 修复才会被应用到这长期内核版本中，而且它们通常不会频繁发布，尤其是对于老的内核版本。

  当前长期版本如下：

  | Version | Maintainer                       | Released   | Projected EOL |
  | ------- | -------------------------------- | ---------- | ------------- |
  | 5.4     | Greg Kroah-Hartman & Sasha Levin | 2019-11-24 | Dec, 2025     |
  | 4.19    | Greg Kroah-Hartman & Sasha Levin | 2018-10-22 | Dec, 2024     |
  | 4.14    | Greg Kroah-Hartman & Sasha Levin | 2017-11-12 | Jan, 2024     |
  | 4.9     | Greg Kroah-Hartman & Sasha Levin | 2016-12-11 | Jan, 2023     |
  | 4.4     | Greg Kroah-Hartman & Sasha Levin | 2016-01-10 | Feb, 2022     |

基于上述内核版本信息，我们选择最新 LTS 版本 5.4，5.4 版本最新版本为 5.4.75。

## 2. Ubuntu 20.04 系统搭建

本文的操作环境基于 VirtualBox + Vagrant 搭建，你需要提前安装好 [VirtualBox](https://www.virtualbox.org/) 和  [Vagrant](https://www.vagrantup.com/)，操作系统采用 Ubuntun 20.04 Focal Fossa，其内核版本为 5.4.0， Ubuntu 的完整发行版本列表参见：[wikipedia](https://zh.wikipedia.org/wiki/Ubuntu%E5%8F%91%E8%A1%8C%E7%89%88%E5%88%97%E8%A1%A8)。



| 版本      | 开发代号    | 发布日期   | 标准支持结束时间 | 延迟支持时间 | 内核版本 |
| --------- | ----------- | ---------- | ---------------- | ------------ | -------- |
| 20.04 LTS | Focal Fossa | 2020-04-23 | **2025-04**      | **2030-04**  | 5.4      |



采用 vagrant 安装命令如下：

```bash
$ vagrant init bento/ubuntu-20.04
$ vagrant up
$ vagrant ssh
$ cat /etc/issue
Ubuntu 20.04.1 LTS \n \l

$ lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 20.04.1 LTS
Release:	20.04
Codename:	focal

$ uname -rs
Linux 5.4.0-52-generic

$ uname -a
Linux vagrant 5.4.0-52-generic #57-Ubuntu SMP Thu Oct 15 10:57:00 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux

$ sudo dpkg --get-selections |grep linux-image
linux-image-5.4.0-52-generic			install
linux-image-generic				install
```



内核升级方式【备选资料】

* 到 Ubuntu 网站 http://kernel.ubuntu.com/~kernel-ppa/mainline/ 

* 选择所需要的 Ubuntu 内核版本目录，比如最新的内核版本 [v5.4.75 目录](https://kernel.ubuntu.com/~kernel-ppa/mainline/v5.4.75/)（发布日期 2020 年 11 月 05 日）

* 在介绍页面中，根据硬件的架构选择内核版本，X86 硬件架构 64 位操作系统应选择 AMD64

* 下载对应的 deb 包

  ```bash
  $ wget https://kernel.ubuntu.com/~kernel-ppa/mainline/v5.4.75/amd64/linux-headers-5.4.75-050475-generic_5.4.75-050475.202011051231_amd64.deb
  $ wget https://kernel.ubuntu.com/~kernel-ppa/mainline/v5.4.75/amd64/linux-image-unsigned-5.4.75-050475-generic_5.4.75-050475.202011051231_amd64.deb
  $ wget https://kernel.ubuntu.com/~kernel-ppa/mainline/v5.4.75/amd64/linux-modules-5.4.75-050475-generic_5.4.75-050475.202011051231_amd64.deb
  
  $ ls -hl
  total 59M
  -rw-r--r-- 1 root root 1.2M Nov  5 12:51 linux-headers-5.4.75-050475-generic_5.4.75-050475.202011051231_amd64.deb
  -rw-r--r-- 1 root root 8.5M Nov  5 12:50 linux-image-unsigned-5.4.75-050475-generic_5.4.75-050475.202011051231_amd64.deb
  -rw-r--r-- 1 root root  50M Nov  5 12:50 linux-modules-5.4.75-050475-generic_5.4.75-050475.202011051231_amd64.deb
  ```
  
* 安装新的内核

  ```bash
  $ sudo dpkg -i *.deb
  ```

  升级完成后，重启系统，再次检查内核版本，发薪已经为最新的 5.4.75 版本。

  ```bash
  # uname -sr
  Linux 5.4.75-050475-generic
  ```

  

在操作系统环境准备好以后，我们需要安装 BPF 技术测试的必要系统组件，安装命令如下:

```bash
$ sudo apt update
$ sudo apt install build-essential git make libelf-dev clang llvm strace tar bpfcc-tools linux-headers-$(uname -r) gcc-multilib  flex  bison libssl-dev -y
```



## 3. 内核源码编译

### 3.1 apt 安装源码 【推荐】

一般情况下推荐采用 apt 方式的安装源码，安装简单而且只安装当前内核的源码，源码的大小在 200M 左右。

```bash
# apt-cache search linux-source
linux-source - Linux kernel source with Ubuntu patches
linux-source-5.4.0 - Linux kernel source for version 5.4.0 with Ubuntu patches
linux-hwe-5.8-source-5.8.0 - Linux kernel source for version 5.8.0 with Ubuntu patches

# apt install linux-source-5.4.0
Reading package lists... Done
Building dependency tree
Reading state information... Done
Suggested packages:
  kernel-package libqt3-dev
The following NEW packages will be installed:
  linux-source-5.4.0
0 upgraded, 1 newly installed, 0 to remove and 38 not upgraded.
Need to get 135 MB of archives.
After this operation, 150 MB of additional disk space will be used.
Get:1 http://archive.ubuntu.com/ubuntu focal-updates/main amd64 linux-source-5.4.0 all 5.4.0-52.57 [135 MB]
Fetched 135 MB in 27s (5,015 kB/s)
Selecting previously unselected package linux-source-5.4.0.
(Reading database ... 81402 files and directories currently installed.)
Preparing to unpack .../linux-source-5.4.0_5.4.0-52.57_all.deb ...
Unpacking linux-source-5.4.0 (5.4.0-52.57) ...
Setting up linux-source-5.4.0 (5.4.0-52.57) ...
```

源码安装至 `/usr/src/` 目录下。

```bash
$ ls -hl
total 4.0K
drwxr-xr-x 4 root root 4.0K Nov  9 13:22 linux-source-5.4.0
lrwxrwxrwx 1 root root   45 Oct 15 10:28 linux-source-5.4.0.tar.bz2 -> linux-source-5.4.0/linux-source-5.4.0.tar.bz2

$ tar -jxvf linux-source-5.4.0.tar.bz2
$ cd linux-source-5.4.0

$ make scripts     # 可选
$ cp -v /boot/config-$(uname -r) .config # make defconfig 或者 make menuconfig
$ make headers_install
$ make M=samples/bpf  # 如果配置出错，可以使用 make oldconfig && make prepare 修复
```



### 3.2 内核代码 Git 下载

如果我们的学习过程中需要持续用到多个版本，那么可以从 Ubuntun 官方维护的 git 仓库下载整个仓库包，下载的源码大小在 3G 左右。

Ubuntun 内核代码安装教程参见：[KernelGitGuide](https://wiki.ubuntu.com/Kernel/Dev/KernelGitGuide)。在线内核版本参见[这里](https://elixir.bootlin.com/linux/v5.4/source/samples/bpf)，编译前可以先阅读 [README.rst](https://elixir.bootlin.com/linux/v5.4/source/samples/bpf/README.rst)。

```bash
$ lsb_release -cs
focal
$ git clone git://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/$(lsb_release -cs)

# 源码下载完成后，通常为 master 分支，我们可以切换到我们系统的本地版本号
$ cat /proc/version_signature
Ubuntu 5.4.0-52.57-generic 5.4.65

$ git checkout -b temp Ubuntu-5.4.0-52.57
# 如果后续不需要可以通过 git branch -d temp 删除
$ git log
commit 3f9bcec55a41c263d2f43a7ebbd8256b85767fe5 (HEAD -> temp, tag: Ubuntu-5.4.0-52.57, origin/master, origin/HEAD, master)
Author: Stefan Bader <stefan.bader@canonical.com>
Date:   Thu Oct 15 12:28:28 2020 +0200

    UBUNTU: Ubuntu-5.4.0-52.57

    Signed-off-by: Stefan Bader <stefan.bader@canonical.com>
```

源码下载以后，编译方式与 apt 按照的方式一致。

### 3.3 编译错误

#### 3.3.1 scripts/mod/modpos 报错

```bash
  WARNING: Symbol version dump ./Module.symvers
           is missing; modules will have no dependencies and modversions.

  Building modules, stage 2.
  MODPOST 0 modules
/bin/sh: 1: scripts/mod/modpost: not found
make[1]: *** [scripts/Makefile.modpost:94: __modpost] Error 127
make: *** [Makefile:1670: modules] Error 2
```



可以通过 `make scripts ` 来补全脚本：

```bash
$ make scripts  
```



#### 3.3.2 ”asm/x.h" 头文件缺少

```bash
./include/linux/spinlock.h:60:10: fatal error: 'asm/mmiowb.h' file not found
#include <asm/mmiowb.h>
         ^~~~~~~~~~~~~~
1 error generated.
  CC      samples/bpf/syscall_nrs.s
In file included from ./include/uapi/linux/unistd.h:8,
                 from samples/bpf/syscall_nrs.c:2:
./arch/x86/include/asm/unistd.h:19:12: fatal error: asm/unistd_64_x32.h: No such file or directory
   19 | #  include <asm/unistd_64_x32.h>
      |            ^~~~~~~~~~~~~~~~~~~~~
compilation terminated.
make[1]: *** [scripts/Makefile.build:99: samples/bpf/syscall_nrs.s] Error 1
make: *** [Makefile:1757: samples/bpf] Error 2
```

通过查找发现系统中的头文件有对应的文件：

```bash
$ sudo find / -name mmiowb.h
/usr/src/linux-headers-5.4.0-52-generic/arch/x86/include/generated/asm/mmiowb.h

$ sudo cat /usr/src/linux-headers-5.4.0-52-generic/arch/x86/include/generated/asm/mmiowb.h
#include <asm-generic/mmiowb.h>
```

在 include 文件中创建 asm 目录，并将该 `/usr/src/linux-headers-5.4.0-52-generic/arch/x86/include/generated`  目下的全部文件复制到 `include/asm` 目录下：

```bash
$ mkdir -p include/asm
$ sudo cp /usr/src/linux-headers-5.4.0-52-generic/arch/x86/include/generated/asm/* include/asm
```

参见： https://www.mail-archive.com/openembedded-core@lists.openembedded.org/msg127370.html

#### 3.3.3 "generated/x.h" 报错

```bash
./include/linux/page-flags-layout.h:6:10: fatal error: 'generated/bounds.h' file not found
#include <generated/bounds.h>
         ^~~~~~~~~~~~~~~~~~~~
^Cmake[1]: *** [samples/bpf/Makefile:286: samples/bpf/xdp_tx_iptunnel_kern.o] Interrupt
make: *** [Makefile:1757: samples/bpf] Interrupt
```

解决方式

```bash
$ cp -r /usr/src/linux-headers-5.4.0-52-generic/include/generated/* ./include/generated
```

关于 headers 与 headers.x.y-z-generic 的区别：

```bash
linux-headers-5.4.0-52 Header files related to Linux kernel version 5.4.0
linux-headers-5.4.0-52-generic Linux kernel headers for version 5.4.0 on x86/x86_64
```



#### 3.3.4 其他报错

可参考 https://lore.kernel.org/lkml/20190518004639.20648-3-mcroce@redhat.com/T/



## 4. 编译 sample/bpf 样例

```bash
$ make M=samples/bpf

# 清理
$ make M=samples/bpf clean
```



## 5. "Hello BPF"

内核中的程序 `hello_kern.c`：

```c
#include <linux/bpf.h>
#include "bpf_helpers.h"

#define SEC(NAME) __attribute__((section(NAME), used))

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog(void *ctx)
{
	char msg[] = "Hello BPF!\n";
	bpf_trace_printk(msg, sizeof(msg));
	return 0;
}

char _license[] SEC("license") = "GPL";
```

用户态的程序 `hello_user.c`:

```c
#include <stdio.h>
#include "bpf_load.h"

int main(int argc, char **argv)
{
	if( load_bpf_file("hello_kern.o") != 0)
	{
		printf("The kernel didn't load BPF program\n");
		return -1;
	}

	read_trace_pipe();
	return 0;
}
```



在对应的位置修改 Makefile 文件，添加以下三行：

```bash
hostprogs-y += hello
hello-objs := bpf_load.o hello_user.o
always += hello_kern.o
```

编译

```bash
# V=1 查看详细编译输出
# make M=samples/bpf V=1
```

编译后的效果

```bash
# ls -hl samples/bpf/hello*
-rwxr-xr-x 1 root root 404K Nov 10 10:01 samples/bpf/hello
-rw-r--r-- 1 root root  296 Nov 10 09:58 samples/bpf/hello_kern.c
-rw-r--r-- 1 root root 3.7K Nov 10 10:02 samples/bpf/hello_kern.o
-rw-r--r-- 1 root root  220 Nov 10 09:57 samples/bpf/hello_user.c
-rw-r--r-- 1 root root 2.2K Nov 10 10:01 samples/bpf/hello_user.o
```

运行 `hello` 程序，在另外一个终端执行 `ls -hl`，则输出结果如下：

```bash
# ./hello
           <...>-113094 [000] ....  8411.799754: 0: Hello BPF!
```





## 6. 参考

* [What Stable Kernel Should I Use?](http://kroah.com/log/blog/2018/08/24/what-stable-kernel-should-i-use/)  作者为 LTS 版本维护者 Greg Kroah-Hartman [中文](https://linux.cn/article-10103-1.html)
* [How to compile and install Linux Kernel 5.6.9 from source code](https://www.cyberciti.biz/tips/compiling-linux-kernel-26.html)
* [Can't find the source of some “asm”, “generated” header files in linux kernel?](https://unix.stackexchange.com/questions/585479/cant-find-the-source-of-some-asm-generated-header-files-in-linux-kernel)
* [编译运行Linux内核源码中的BPF示例代码](https://cloud.tencent.com/developer/article/1644458)
* [Ubuntu下bpf纯c程序的编写与运行](https://blog.csdn.net/qq_34258344/article/details/108932912)
* https://me.csdn.net/qq_34258344
* [站点 Linux 服务器分布趋势](https://w3techs.com/technologies/history_details/os-linux/all/y)

