# 环境搭建

## Centos 8

CentOS 8 主要改动和 [RedHat Enterprise Linux 8](https://www.oschina.net/news/106529/redhat-enterprise-linux-8-final) 是一致的，基于 **Fedora 28** 和内核版本 **4.18**, 为用户提供一个稳定的、安全的、一致的基础，跨越混合云部署，支持传统和新兴的工作负载所需的工具。更加详细的说明参见：https://www.cnbeta.com/articles/soft/892951.htm

> 该版本中 eBPF 相关的特性参见：
>
> - 扩展 Berkeley Packet Filtering (**eBPF)** 特性使得用户空间的各个点上附加自定义程序，包括 (sockets, trace points, packet reception) ，用于接收和处理数据。目前该特性还处于特性预览阶段
> - BPF Compiler Collection (**BCC**), 这是一个用来创建高效内核跟踪和操作的工具，目前处于技术预览阶段
> - 支持 **IPVLAN** 虚拟网络驱动程序，用于连接多个容器
> - eXpress Data Path (**XDP**), XDP for Traffic Control (**tc**), 以及 Address Family eXpress Data Path (**AF_XDP**), 可作为部分 Berkeley Packet Filtering (**eBPF)** 扩展特性，目前还是技术预览阶段，详情请看 [Section 5.3.7, “Networking”](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/8.0_release_notes/RHEL-8_0_0_release#networking_technology_preview).
> - 核心支持 **eBPF** 调试的工具包括`BCC`, `PCP`, 和 `SystemTap`.

内核源码安装参见：[我需要内核的源代码](https://wiki.centos.org/zh/HowTos/I_need_the_Kernel_Source#A.2BYhaLuE9gTg2XAImBZXROKlGFaDh2hG6QTuN4AQ-)

## Vagrant 

[vagrant 文件](https://app.vagrantup.com/centos/boxes/8)

```bash
Vagrant.configure("2") do |config|
  config.vm.box = "centos/8"
  config.vm.box_version = "1905.1"
end
```

命令行方式

```bash
$ vagrant init centos/8 \
  --box-version 1905.1
$ vagrant up

# yum update -y
...
Installed:
  kernel-4.18.0-193.14.2.el8_2.x86_64     kernel-core-4.18.0-193.14.2.el8_2.x86_64       kernel-modules-4.18.0-193.14.2.el8_2.x86_64
  yum-utils-4.0.12-3.el8.noarch           elfutils-debuginfod-client-0.178-7.el8.x86_64  centos-gpg-keys-8.2-2.2004.0.1.el8.noarch
  centos-repos-8.2-2.2004.0.1.el8.x86_64  grub2-tools-efi-1:2.02-87.el8_2.x86_64         libssh-config-0.9.0-4.el8.noarch
  libzstd-1.4.2-2.el8.x86_64              mozjs60-60.9.0-4.el8.x86_64                    python3-nftables-1:0.9.3-12.el8.x86_64
  python3-pip-wheel-9.0.3-16.el8.noarch   python3-setuptools-wheel-39.2.0-5.el8.noarch
```



## 测试 tcptracer-bpf

tcptracer-bpf 主要用于跟踪 TCP 服务的状态跟踪（此外也实现了特定进程打开文件 fd 的事件跟踪 ），该库的亮点在于动态计算字段信息的 offset 偏移量，避免了通过引用 linux 头文件来进行连接状态信息的提取，动态计算的方式是在程序启动阶段建立本地连接获取到的事件信息来推测 sock 中各个字段信息比如源端口、目的端口等信息的 offset ，从而实现了对于内核版本的移植性。主要流程如下：

1. 在启动的时候本地建立侦听端口 127.0.0.2，然后在 127.0.0.1 设备上建立连接；

2. 在内核中使用 tcp_v{4,6}_connect 的 kprobe 探针中进行预期字段进行查找，最终确定出各个字段信息在 sock 结构中的 offset，并将将对应的 offset 保存到结构 tcptracer_status_t 中，并存入名为 tcptracer_status 的 map 结构中，实现了用户空间设置 eBPF 相关偏移量的工作；其中 tcptracer_status_t 结构中的 state 字段用于保存初始化的状态，协调用户空间的 offset 递增与 eBPF 在 kprobe 中的验证工作，在多次尝试和验证后， state 状态会被设置为 TCPTRACER_STATE_READY 状态，标志着 offset 初始化完成后；

3. 在完成 offset 初始化以后，后续的相关事件处理中，就可基于 tcptracer_status_t 中保存的 offset 信息来提取事件中的字段信息，当前的支持的字段信息如下：

   ```c
   struct tcptracer_status_t {
   	__u64 state;
   
   	/* checking */
   	__u64 pid_tgid;
   	__u64 what;
   	__u64 offset_saddr;
   	__u64 offset_daddr;
   	__u64 offset_sport;
   	__u64 offset_dport;
   	__u64 offset_netns;
   	__u64 offset_ino;
   	__u64 offset_family;
   	__u64 offset_daddr_ipv6;
   
   	__u64 err;
   
     // 支持提取的字段信息
   	__u32 daddr_ipv6[4];
   	__u32 netns;
   	__u32 saddr;
   	__u32 daddr;
   	__u16 sport;
   	__u16 dport;
   	__u16 family;
   	__u16 padding;
   };
   ```

eBPF 程序由 [tcptracer-bpf.h](https://github.com/weaveworks/tcptracer-bpf/blob/master/tcptracer-bpf.h) 和 [tcptracer-bpf.c](https://github.com/weaveworks/tcptracer-bpf/blob/master/tcptracer-bpf.c) 两个文件组成，在编译以后生产 `ebpf/tcptracer-ebpf.o` 文件，然后通过 `go-bindata` 将 `tcptracer-ebpf.o` 文件转换成 .go 文件，最后通过 go 语言导出 `pkg tracer` 供应用程序引用和使用，具体的方式可以在 `tests` 目录中的 [tracer.go](https://github.com/weaveworks/tcptracer-bpf/blob/master/tests/tracer.go) 文件中找到参考样例，其中对于 eBPF 程序操作的库为 `github.com/iovisor/gobpf/elf`。Tracer 主要结构和初始化的方式如下：

```go
type Callback interface {
	TCPEventV4(TcpV4)
	TCPEventV6(TcpV6)
	LostV4(uint64)
	LostV6(uint64)
}

func NewTracer(cb Callback) (*Tracer, error) {
    // ...
}

type Tracer struct {
	m           *bpflib.Module
	perfMapIPV4 *bpflib.PerfMap
	perfMapIPV6 *bpflib.PerfMap
	stopChan    chan struct{}
}


// 其中 Tracer 的主要方法如下：
func (t *Tracer) Start() {
	t.perfMapIPV4.PollStart()
	t.perfMapIPV6.PollStart()
}

func (t *Tracer) AddFdInstallWatcher(pid uint32) (err error) {
	var one uint32 = 1
	mapFdInstall := t.m.Map("fdinstall_pids")
	err = t.m.UpdateElement(mapFdInstall, unsafe.Pointer(&pid), unsafe.Pointer(&one), 0)
	return err
}

func (t *Tracer) RemoveFdInstallWatcher(pid uint32) (err error) {
	mapFdInstall := t.m.Map("fdinstall_pids")
	err = t.m.DeleteElement(mapFdInstall, unsafe.Pointer(&pid))
	return err
}

func (t *Tracer) Stop() {
	close(t.stopChan)
	t.perfMapIPV4.PollStop()
	t.perfMapIPV6.PollStop()
	t.m.Close()
}
```





验证 tcptracer-bpf 的详细指令下：

```bash
# yum install go git make -y
# go get github.com/DavadDi/tcptracer-bpf
# cd ~/go/src/github.com/ 
# mv DavadDi weaveworks

# From https://www.cnblogs.com/ding2016/p/11592999.html
# install docker-ce
# curl https://download.docker.com/linux/centos/docker-ce.repo -o /etc/yum.repos.d/docker-ce.repo
# yum install https://download.docker.com/linux/fedora/30/x86_64/stable/Packages/containerd.io-1.2.6-3.3.fc30.x86_64.rpm
# yum install docker-ce -y

# systemctl start docker

# make
docker run --rm -e DEBUG=1 \
	-e CIRCLE_BUILD_URL= \
	-v /root/go/src/github.com/weaveworks/tcptracer-bpf:/src:ro \
	-v /root/go/src/github.com/weaveworks/tcptracer-bpf/ebpf:/dist/ \
	--workdir=/src \
	registry.qtt6.cn/paas-dev/tcptracer-bpf-builder \
	make -f ebpf.mk build
Unable to find image 'tcptracer-bpf-builder:latest' locally
latest: Pulling from dwh0403/tcptracer-bpf-builder
565884f490d9: Pull complete
978975d10f48: Pull complete
20bc768d2ae7: Pull complete
a99182571ab5: Pull complete
4e052b8b7625: Pull complete
Digest: sha256:f030a2c944a679fa5d7fa8da188b23e6ce972f2fa351387a24e25b2023d2e635
Status: Downloaded newer image for dwh0403/tcptracer-bpf-builder:latest
clang -D__KERNEL__ -D__ASM_SYSREG_H -D__BPF_TRACING__\
	-DCIRCLE_BUILD_URL=\"\" \
	-Wno-unused-value \
	-Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-Wunused \
	-Wall \
	-Werror \
	-O2 -emit-llvm -c tcptracer-bpf.c \
	 -I /usr/src/kernels/4.18.16-200.fc28.x86_64/arch/x86/include -I /usr/src/kernels/4.18.16-200.fc28.x86_64/arch/x86/include/generated -I /usr/src/kernels/4.18.16-200.fc28.x86_64/include -I /usr/src/kernels/4.18.16-200.fc28.x86_64/include/generated/uapi -I /usr/src/kernels/4.18.16-200.fc28.x86_64/arch/x86/include/uapi -I /usr/src/kernels/4.18.16-200.fc28.x86_64/include/uapi \
	-o - | llc -march=bpf -filetype=obj -o "/dist/tcptracer-ebpf.o"
go-bindata -pkg tracer -prefix "/dist/" -modtime 1 -o "/dist/tcptracer-ebpf.go" "/dist/tcptracer-ebpf.o"
sudo chown -R 0:0 ebpf
cp ebpf/tcptracer-ebpf.go pkg/tracer/tcptracer-ebpf.go

# cd tests
# make
# ./tracer
# e.Timestamp, e.CPU, e.Type, e.Pid, e.Comm, e.SAddr, e.SPort, e.DAddr, e.DPort, e.NetNS
1886981614864 cpu#0 connect 15877 curl 10.0.2.15:38788 61.135.185.32:80 4026531992
1887014987197 cpu#0 close 15877 curl 10.0.2.15:38788 61.135.185.32:80 4026531992

# 在另外一个窗口测试
$ curl www.baidu.com
```

