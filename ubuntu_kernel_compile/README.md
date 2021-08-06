# qemu + gdb 调试 linux 内核

ubuntu 启用 ssh

```bash
$ sudo apt update
$ sudo apt install openssh-server
$ sudo systemctl status ssh
$ sudo ufw allow ssh
```



编译内核 CentOS7

```bash
 $ sudo yum group install "Development Tools"
 $ yum install ncurses-devel bison flex elfutils-libelf-devel openssl-devel
 
 $ wget http://ftp.sjtu.edu.cn/sites/ftp.kernel.org/pub/linux/kernel/v4.x/linux-4.19.172.tar.gz
 $ tar xzvf linux-4.19.172.tar.gz
 $ cd linux-4.19.172/

 $ make menuconfig
 $ nproc
 $ make -j 12  # make bzImage
 
 # 编译完成后内核位于以下目录
./arch/x86_64/boot/bzImage
./arch/x86/boot/bzImage
```



通过 busybox 文件系统定制 Linux

```bash
# 首先安装静态依赖
$ yum install -y glibc-static.x86_64 -y

$ wget https://busybox.net/downloads/busybox-1.32.1.tar.bz2
$ tar -xvf busybox-1.32.1.tar.bz2
$ cd busybox-1.32.1/

$ make menuconfig
$ make && make install

$ cd _install
$ mkdir proc
$ mkdir sys
$ vim init  # 内容如下
$ cat init
$ chmod +x init
$ find . | cpio -o --format=newc > ./rootfs.img
cpio: File ./rootfs.img grew, 2758144 new bytes not copied
10777 blocks
$ ls -hl rootfs.img
-rw-r--r-- 1 root root 5.3M Feb  2 11:23 rootfs.img
```

![WeChatWorkScreenshot_2e98920b-ec52-4736-965d-6024bb483fc1](/Users/dwh0403/Library/Containers/com.tencent.WeWorkMac/Data/Library/Application Support/WXWork/Temp/ScreenCapture/WeChatWorkScreenshot_2e98920b-ec52-4736-965d-6024bb483fc1.png)



init 内容如下

```bash
#!/bin/sh
echo "{==DBG==} INIT SCRIPT"
mkdir /tmp
mount -t proc none /proc
mount -t sysfs none /sys
mount -t debugfs none /sys/kernel/debug
mount -t tmpfs none /tmp

mdev -s 
echo -e "{==DBG==} Boot took $(cut -d' ' -f1 /proc/uptime) seconds"
setsid /bin/cttyhack setuidgid 1000 /bin/sh #normal user
```



> 报错排查
>
> ```bash
> /bin/ld: cannot find -lcrypt
> /bin/ld: cannot find -lm
> /bin/ld: cannot find -lresolv
> /bin/ld: cannot find -lrt
> collect2: error: ld returned 1 exit status
> Note: if build needs additional libraries, put them in CONFIG_EXTRA_LDLIBS.
> Example: CONFIG_EXTRA_LDLIBS="pthread dl tirpc audit pam"
> ```
>
> 由于是静态编译可以使用 `yum provides` 命令查看
>
> ```bash
> $ yum provides */libm.a
> // ...
> glibc-static-2.17-317.el7.x86_64 : C library static libraries for -static linking.
> Repo        : base
> Matched from:
> Filename    : /usr/lib64/libm.a
> ```



## QEMU

CentOS 安装，参见[这里](https://www.qemu.org/download/)。

```bash
$ sudo yum install qemu-kvm -y
$ sudo which qemu-kvm
/bin/qemu-kvm

$ /bin/qemu-kvm --version
QEMU emulator version 1.5.3 (qemu-kvm-1.5.3-175.el7_9.1), Copyright (c) 2003-2008 Fabrice Bellard
```



如果启动报错，多数是因为 BIOS 中未开启 Intel 的虚拟化技术导致，（在云厂商的机器上比如阿里的 ECS 可能禁止了虚拟化）。

```bash
Could not access KVM kernel module: No such file or directory
failed to initialize KVM: No such file or directory
Back to tcg accelerator.
```

如果主机支持虚拟化，则可以使用以下方式解决

```bash
Try with sudo modprobe kvm-intel.

In order to have the module automatically loaded at the startup of the virtual machine, do the following:

Edit the corresponding file from the shell with sudo vim /etc/modules.conf
Possibly enter your username password.
Press the key G to go to the end of the document and then o to begin inserting.
Write kvm-intel and press Enter, producing a new line.
Press Esc to return to the Normal mode of vim. "--INSERT--" will disappear fromthe bottom.
Save the file and exit vim by writing :wq.
You are done. Try to reboot and load the nested virtual machine.
```



```bash
$ cp linux-4.19.172/arch/x86_64/boot/bzImage ./
$ cp busybox-1.32.1/_install/rootfs.img ./
```



Ubuntu  20.04

```bash
$ apt install qemu qemu-utils qemu-kvm virt-manager libvirt-daemon-system libvirt-clients bridge-utils
```



```
qemu-system-x86_64 -kernel ./bzImage -initrd  ./rootfs.img -append "console=ttyS0" -s -S -nographic
```



## 参考

* [How to compile and install Linux Kernel 5.6.9 from source code](https://www.cyberciti.biz/tips/compiling-linux-kernel-26.html)
* [用qemu + gdb调试linux内核](https://www.jianshu.com/p/431d606d322c)
* [QEMU+busybox 搭建Linux内核运行环境](https://www.sunxiaokong.xyz/2020-01-14/lzx-linuxkernel-qemuinit/)
* [QEMU+gdb调试Linux内核全过程](https://blog.csdn.net/jasonLee_lijiaqi/article/details/80967912)
* [How to Build A Custom Linux Kernel For Qemu (2015 Edition)](http://mgalgs.github.io/2015/05/16/how-to-build-a-custom-linux-kernel-for-qemu-2015-edition.html)
* [qemu与qemu-kvm到底什么区别](https://www.cnblogs.com/hugetong/p/8808544.html)
* [在qemu环境中用gdb调试Linux内核](https://www.cnblogs.com/wipan/p/9264979.html)