# 编译和测试

Code From: kernel-src/samples/kprobes/

```bash
$ make
make -C /lib/modules/4.18.0-193.14.2.el8_2.x86_64/build  M=/home/vagrant/kprobes modules
make[1]: Entering directory '/usr/src/kernels/4.18.0-193.14.2.el8_2.x86_64'
  CC [M]  /home/vagrant/kprobes/kprobe_example.o
  Building modules, stage 2.
  MODPOST 1 modules
  CC      /home/vagrant/kprobes/kprobe_example.mod.o
  LD [M]  /home/vagrant/kprobes/kprobe_example.ko
make[1]: Leaving directory '/usr/src/kernels/4.18.0-193.14.2.el8_2.x86_64'

# insmod kprobe_example.ko

# dmesg
[26537.263371] kprobe_example: loading out-of-tree module taints kernel.
[26537.264006] kprobe_example: module verification failed: signature and/or required key missing - tainting kernel
[26537.272969] <_do_fork> pre_handler: p->addr = 0x000000001f2d23bd, ip = ffffffff85eb02c1, flags = 0x246
[26537.273726] Planted kprobe at 000000001f2d23bd
[26537.273969] <_do_fork> pre_handler: p->addr = 0x000000001f2d23bd, ip = ffffffff85eb02c1, flags = 0x246
[26537.274031] <_do_fork> post_handler: p->addr = 0x000000001f2d23bd, flags = 0x246
[26537.274651] <_do_fork> post_handler: p->addr = 0x000000001f2d23bd, flags = 0x246
[26540.939990] <_do_fork> pre_handler: p->addr = 0x000000001f2d23bd, ip = ffffffff85eb02c1, flags = 0x246
[26540.941180] <_do_fork> post_handler: p->addr = 0x000000001f2d23bd, flags = 0x246

# rmmod kprobe_example
```
