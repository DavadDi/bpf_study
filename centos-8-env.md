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

