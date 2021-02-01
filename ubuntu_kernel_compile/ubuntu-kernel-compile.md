# Ubuntu 内核编译

当前版本 18.04 

```bash
$ uname -a
Linux ubuntu-bionic 4.15.0-124-generic #127-Ubuntu SMP Fri Nov 6 10:54:43 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
```



国内内核源码下载：http://ftp.sjtu.edu.cn/sites/ftp.kernel.org/pub/linux/kernel/  

将 ubuntu 源替换成清华源 https://mirror.tuna.tsinghua.edu.cn/help/ubuntu/

```bash
$ sudo cp /etc/apt/sources.list /etc/apt/sources.list.bk
$ sudo  vim /etc/apt/sources.list

# 默认注释了源码镜像以提高 apt update 速度，如有需要可自行取消注释
deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ bionic main restricted universe multiverse
# deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ bionic main restricted universe multiverse
deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ bionic-updates main restricted universe multiverse
# deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ bionic-updates main restricted universe multiverse
deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ bionic-backports main restricted universe multiverse
# deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ bionic-backports main restricted universe multiverse
deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ bionic-security main restricted universe multiverse
# deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ bionic-security main restricted universe multiverse

# 预发布软件源，不建议启用
# deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ bionic-proposed main restricted universe multiverse
# deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ bionic-proposed main restricted universe multiverse

$ sudo  apt-get update
```



安装依赖包

```bash
$ sudo apt-get install build-essential libncurses-dev bison flex libssl-dev libelf-dev

# 使用当前系统运行的配置进行编译，如果需要定制使用 make menuconfig
$ sudo cp -v /boot/config-$(uname -r) .config
$ sudo make -j4

$ sudo make modules_install
$ sudo make install

# 重启电脑，查看新的内核
```

