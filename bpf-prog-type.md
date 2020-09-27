# BPF 程序类型

BPF 相关的程序，首先需要设置为相对应的的程序类型，截止Linux 内核 5.8 程序类型定义有 29 个，而且还是持续增加中，完整的列表可参见 [bpf.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h)。

> Linux 5.9 版本 30 个。

 BPF 程序类型（prog_type）决定了程序可以调用的内核辅助函数的子集。BPF 程序类型也决定了程序输入上下文 -- bpf_context结构的格式，其作为 BPF 程序中的第一个输入参数（数据blog）。例如，跟踪程序与套接字过滤器程序的辅助函数子集并不完全相同（尽管它们可能具有一些共同的帮助函数）。同样，跟踪程序的输入上下文（context）是一组寄存器值，而套接字过滤器的输入是一个网络数据包。更加详细的描述参见 man 2 bpf。

代码基于[linux v5.8 tag](https://github.com/torvalds/linux/releases/tag/v5.8)

特定类型的eBPF程序可用的功能集将来可能会增加。

include/uapi/linux/bpf.h 

```c
 161 enum bpf_prog_type {
 162         BPF_PROG_TYPE_UNSPEC,
 163         BPF_PROG_TYPE_SOCKET_FILTER,
 164         BPF_PROG_TYPE_KPROBE,
 165         BPF_PROG_TYPE_SCHED_CLS,
 166         BPF_PROG_TYPE_SCHED_ACT,
 167         BPF_PROG_TYPE_TRACEPOINT,
 168         BPF_PROG_TYPE_XDP,
 169         BPF_PROG_TYPE_PERF_EVENT,
 170         BPF_PROG_TYPE_CGROUP_SKB,
 171         BPF_PROG_TYPE_CGROUP_SOCK,
 172         BPF_PROG_TYPE_LWT_IN,
 173         BPF_PROG_TYPE_LWT_OUT,
 174         BPF_PROG_TYPE_LWT_XMIT,
 175         BPF_PROG_TYPE_SOCK_OPS,
 176         BPF_PROG_TYPE_SK_SKB,
 177         BPF_PROG_TYPE_CGROUP_DEVICE,
 178         BPF_PROG_TYPE_SK_MSG,
 179         BPF_PROG_TYPE_RAW_TRACEPOINT,
 180         BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
 181         BPF_PROG_TYPE_LWT_SEG6LOCAL,
 182         BPF_PROG_TYPE_LIRC_MODE2,
 183         BPF_PROG_TYPE_SK_REUSEPORT,
 184         BPF_PROG_TYPE_FLOW_DISSECTOR,
 185         BPF_PROG_TYPE_CGROUP_SYSCTL,
 186         BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
 187         BPF_PROG_TYPE_CGROUP_SOCKOPT,
 188         BPF_PROG_TYPE_TRACING,
 189         BPF_PROG_TYPE_STRUCT_OPS,
 190         BPF_PROG_TYPE_EXT,
 191         BPF_PROG_TYPE_LSM,
 192 };
```



程序在载入的过程中会根据 BPF 进行判断，`load_bpf_file` 用户程序用于加载的入口函数，`loader.c` 文件中加载 BPF 程序的使用样例如下：

```c
#include "bpf_load.h"
#include <stdio.h>

int main(int argc, char **argv) {
  if (load_bpf_file("bpf_program.o") != 0) { // 用于加载 ELF 格式的 BPF 程序
    printf("The kernel didn't load the BPF program\n");
    return -1;
  }

  read_trace_pipe();

  return 0;
}
```
samples/bpf/bpf_load.h 
```c
  7 #define MAX_MAPS 32      // 单个程序中的最大 MAP 数目
  8 #define MAX_PROGS 32     // 单个程序中的允许定义的最大 BPF 程序分区的数目
    
  1 /* SPDX-License-Identifier: GPL-2.0 */
  2 #ifndef __BPF_LOAD_H
  3 #define __BPF_LOAD_H
  4
  5 #include <bpf/bpf.h>
  6
  7 #define MAX_MAPS 32
  8 #define MAX_PROGS 32
  9
 10 struct bpf_load_map_def {
 11         unsigned int type;
 12         unsigned int key_size;
 13         unsigned int value_size;
 14         unsigned int max_entries;
 15         unsigned int map_flags;
 16         unsigned int inner_map_idx;
 17         unsigned int numa_node;
 18 };
 19
 20 struct bpf_map_data {
 21         int fd;
 22         char *name;
 23         size_t elf_offset;
 24         struct bpf_load_map_def def;
 25 };
 26
 27 typedef void (*fixup_map_cb)(struct bpf_map_data *map, int idx);
 28
 29 extern int prog_fd[MAX_PROGS];
 30 extern int event_fd[MAX_PROGS];
 31 extern char bpf_log_buf[BPF_LOG_BUF_SIZE];
 32 extern int prog_cnt;
 33
 34 /* There is a one-to-one mapping between map_fd[] and map_data[].
 35  * The map_data[] just contains more rich info on the given map.
 36  */
 37 extern int map_fd[MAX_MAPS];
 38 extern struct bpf_map_data map_data[MAX_MAPS];
 39 extern int map_data_count;
 40
 41 /* parses elf file compiled by llvm .c->.o
 42  * . parses 'maps' section and creates maps via BPF syscall
 43  * . parses 'license' section and passes it to syscall
 44  * . parses elf relocations for BPF maps and adjusts BPF_LD_IMM64 insns by
 45  *   storing map_fd into insn->imm and marking such insns as BPF_PSEUDO_MAP_FD
 46  * . loads eBPF programs via BPF syscall
 47  *
 48  * One ELF file can contain multiple BPF programs which will be loaded
 49  * and their FDs stored stored in prog_fd array
 50  *
 51  * returns zero on success
 52  */
 53 int load_bpf_file(char *path);
 54 int load_bpf_file_fixup_map(const char *path, fixup_map_cb fixup_map);
 55
 56 int bpf_set_link_xdp_fd(int ifindex, int fd, __u32 flags);
 57 #endif
```



参见文件 samples/bpf/bpf_load.c 中的 `do_load_bpf_file` 函数：

```c
30 #define DEBUGFS "/sys/kernel/debug/tracing/"  
31
32 static char license[128];
33 static int kern_version;
34 static bool processed_sec[128];
35 char bpf_log_buf[BPF_LOG_BUF_SIZE];
36 int map_fd[MAX_MAPS];
37 int prog_fd[MAX_PROGS];
38 int event_fd[MAX_PROGS];
39 int prog_cnt;
40 int prog_array_fd = -1;
41
42 struct bpf_map_data map_data[MAX_MAPS];
43 int map_data_count;

659 int load_bpf_file(char *path)
660 {
661         return do_load_bpf_file(path, NULL);
662 }

508 static int do_load_bpf_file(const char *path, fixup_map_cb fixup_map)
509 {
510         int fd, i, ret, maps_shndx = -1, strtabidx = -1;
511         Elf *elf;
512         GElf_Ehdr ehdr;
513         GElf_Shdr shdr, shdr_prog;
514         Elf_Data *data, *data_prog, *data_maps = NULL, *symbols = NULL;
515         char *shname, *shname_prog;
516         int nr_maps = 0;
517
518         /* reset global variables */
519         kern_version = 0;
520         memset(license, 0, sizeof(license));
521         memset(processed_sec, 0, sizeof(processed_sec));
522
523         if (elf_version(EV_CURRENT) == EV_NONE)
524                 return 1;
525
526         fd = open(path, O_RDONLY, 0);
527         if (fd < 0)
528                 return 1;
529
530         elf = elf_begin(fd, ELF_C_READ, NULL);
531
532         if (!elf)
533                 return 1;
534
535         if (gelf_getehdr(elf, &ehdr) != &ehdr)
536                 return 1;
537
538         /* clear all kprobes */
539         i = write_kprobe_events("");
540
541         /* scan over all elf sections to get license and map info */
542         for (i = 1; i < ehdr.e_shnum; i++) {
543
544                 if (get_sec(elf, i, &ehdr, &shname, &shdr, &data))
545                         continue;
546
547                 if (0) /* helpful for llvm debugging */
548                         printf("section %d:%s data %p size %zd link %d flags %d\n",
549                                i, shname, data->d_buf, data->d_size,
550                                shdr.sh_link, (int) shdr.sh_flags);
551
552                 if (strcmp(shname, "license") == 0) {
553                         processed_sec[i] = true;
554                         memcpy(license, data->d_buf, data->d_size);
555                 } else if (strcmp(shname, "version") == 0) {
556                         processed_sec[i] = true;
557                         if (data->d_size != sizeof(int)) {
558                                 printf("invalid size of version section %zd\n",
559                                        data->d_size);
560                                 return 1;
561                         }
562                         memcpy(&kern_version, data->d_buf, sizeof(int));
563                 } else if (strcmp(shname, "maps") == 0) {
564                         int j;
565
566                         maps_shndx = i;
567                         data_maps = data;
568                         for (j = 0; j < MAX_MAPS; j++)
569                                 map_data[j].fd = -1;
570                 } else if (shdr.sh_type == SHT_SYMTAB) {
571                         strtabidx = shdr.sh_link;
572                         symbols = data;
573                 }
574         }
575
576         ret = 1;
577
578         if (!symbols) {
579                 printf("missing SHT_SYMTAB section\n");
580                 goto done;
581         }
582
583         if (data_maps) {
584                 nr_maps = load_elf_maps_section(map_data, maps_shndx,
585                                                 elf, symbols, strtabidx);
586                 if (nr_maps < 0) {
587                         printf("Error: Failed loading ELF maps (errno:%d):%s\n",
588                                nr_maps, strerror(-nr_maps));
589                         goto done;
590                 }
591                 if (load_maps(map_data, nr_maps, fixup_map))
592                         goto done;
593                 map_data_count = nr_maps;
594
595                 processed_sec[maps_shndx] = true;
596         }
597
598         /* process all relo sections, and rewrite bpf insns for maps */
599         for (i = 1; i < ehdr.e_shnum; i++) {
600                 if (processed_sec[i])
601                         continue;
602
603                 if (get_sec(elf, i, &ehdr, &shname, &shdr, &data))
604                         continue;
605
606                 if (shdr.sh_type == SHT_REL) {
607                         struct bpf_insn *insns;
608
609                         /* locate prog sec that need map fixup (relocations) */
610                         if (get_sec(elf, shdr.sh_info, &ehdr, &shname_prog,
611                                     &shdr_prog, &data_prog))
612                                 continue;
613
614                         if (shdr_prog.sh_type != SHT_PROGBITS ||
615                             !(shdr_prog.sh_flags & SHF_EXECINSTR))
616                                 continue;
617
618                         insns = (struct bpf_insn *) data_prog->d_buf;
619                         processed_sec[i] = true; /* relo section */
620
621                         if (parse_relo_and_apply(data, symbols, &shdr, insns,
622                                                  map_data, nr_maps))
623                                 continue;
624                 }
625         }
626
627         /* load programs */
628         for (i = 1; i < ehdr.e_shnum; i++) {
629
630                 if (processed_sec[i])
631                         continue;
632
633                 if (get_sec(elf, i, &ehdr, &shname, &shdr, &data))
634                         continue;
635
636                 if (memcmp(shname, "kprobe/", 7) == 0 ||
637                     memcmp(shname, "kretprobe/", 10) == 0 ||
638                     memcmp(shname, "tracepoint/", 11) == 0 ||
639                     memcmp(shname, "raw_tracepoint/", 15) == 0 ||
640                     memcmp(shname, "xdp", 3) == 0 ||
641                     memcmp(shname, "perf_event", 10) == 0 ||
642                     memcmp(shname, "socket", 6) == 0 ||
643                     memcmp(shname, "cgroup/", 7) == 0 ||
644                     memcmp(shname, "sockops", 7) == 0 ||
645                     memcmp(shname, "sk_skb", 6) == 0 ||
646                     memcmp(shname, "sk_msg", 6) == 0) {
647                         ret = load_and_attach(shname, data->d_buf,
648                                               data->d_size);
649                         if (ret != 0)
650                                 goto done;
651                 }
652         }
653
654 done:
655         close(fd);
656         return ret;
657 }
```

其中 `get_sec` 函数完整定义如下：

```c
316 static int get_sec(Elf *elf, int i, GElf_Ehdr *ehdr, char **shname,
317                    GElf_Shdr *shdr, Elf_Data **data)
318 {
319         Elf_Scn *scn;
320
321         scn = elf_getscn(elf, i);
322         if (!scn)
323                 return 1;
324
325         if (gelf_getshdr(scn, shdr) != shdr)
326                 return 2;
327
328         *shname = elf_strptr(elf, ehdr->e_shstrndx, shdr->sh_name);
329         if (!*shname || !shdr->sh_size)
330                 return 3;
331
332         *data = elf_getdata(scn, 0);
333         if (!*data || elf_getdata(scn, *data) != NULL)
334                 return 4;
335
336         return 0;
337 }
```

以最简单样例为例，完整代码参见 [ bpf_program.c](https://github.com/DavadDi/linux-observability-with-bpf/tree/master/code/chapter-2/hello_world)

```
# cat bpf_program.c
#include <linux/bpf.h>
#define SEC(NAME) __attribute__((section(NAME), used))

static int (*bpf_trace_printk)(const char *fmt, int fmt_size,
                               ...) = (void *)BPF_FUNC_trace_printk;

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog(void *ctx) {
  char msg[] = "Hello, BPF World!";
  bpf_trace_printk(msg, sizeof(msg));
  return 0;
}

char _license[] SEC("license") = "GPL";
```

编译后，我们使用 `readelf` 进行查看编译后以 ELF 格式保存的 `bpf_program.o` 文件：

```bash
# readelf -h bpf_program.o
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              REL (Relocatable file)
  Machine:                           Linux BPF                  # Linux BPF 程序类型
  Version:                           0x1
  Entry point address:               0x0
  Start of program headers:          0 (bytes into file)
  Start of section headers:          424 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           0 (bytes)
  Number of program headers:         0
  Size of section headers:           64 (bytes)
  Number of section headers:         8
  Section header string table index: 1
  
# readelf -S bpf_program.o
There are 8 section headers, starting at offset 0x1a8:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .strtab           STRTAB           0000000000000000  0000012a
       0000000000000079  0000000000000000           0     0     1
  [ 2] .text             PROGBITS         0000000000000000  00000040
       0000000000000000  0000000000000000  AX       0     0     4
  [ 3] tracepoint/syscal PROGBITS         0000000000000000  00000040  # 此处决定了 BPF 的程序类型
       0000000000000070  0000000000000000  AX       0     0     8
  [ 4] .rodata.str1.1    PROGBITS         0000000000000000  000000b0
       0000000000000012  0000000000000001 AMS       0     0     1
  [ 5] license           PROGBITS         0000000000000000  000000c2
       0000000000000004  0000000000000000  WA       0     0     1
  [ 6] .llvm_addrsig     LOOS+0xfff4c03   0000000000000000  00000128
       0000000000000002  0000000000000000   E       7     0     1
  [ 7] .symtab           SYMTAB           0000000000000000  000000c8
       0000000000000060  0000000000000018           1     2     8
```

samples/bpf/bpf_load.c 中的函数 `load_and_attach` 函数中确定程序类型：

```c
 76 static int load_and_attach(const char *event, struct bpf_insn *prog, int size)
 77 {
 78         bool is_socket = strncmp(event, "socket", 6) == 0;
 79         bool is_kprobe = strncmp(event, "kprobe/", 7) == 0;
 80         bool is_kretprobe = strncmp(event, "kretprobe/", 10) == 0;
 81         bool is_tracepoint = strncmp(event, "tracepoint/", 11) == 0;
 82         bool is_raw_tracepoint = strncmp(event, "raw_tracepoint/", 15) == 0;
 83         bool is_xdp = strncmp(event, "xdp", 3) == 0;
 84         bool is_perf_event = strncmp(event, "perf_event", 10) == 0;
 85         bool is_cgroup_skb = strncmp(event, "cgroup/skb", 10) == 0;
 86         bool is_cgroup_sk = strncmp(event, "cgroup/sock", 11) == 0;
 87         bool is_sockops = strncmp(event, "sockops", 7) == 0;
 88         bool is_sk_skb = strncmp(event, "sk_skb", 6) == 0;
 89         bool is_sk_msg = strncmp(event, "sk_msg", 6) == 0;
 90         size_t insns_cnt = size / sizeof(struct bpf_insn);
 91         enum bpf_prog_type prog_type;
 92         char buf[256];
 93         int fd, efd, err, id;
 94         struct perf_event_attr attr = {};
 95
 96         attr.type = PERF_TYPE_TRACEPOINT;
 97         attr.sample_type = PERF_SAMPLE_RAW;
 98         attr.sample_period = 1;
 99         attr.wakeup_events = 1;
100
101         if (is_socket) {
102                 prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
103         } else if (is_kprobe || is_kretprobe) {
104                 prog_type = BPF_PROG_TYPE_KPROBE;
105         } else if (is_tracepoint) {
106                 prog_type = BPF_PROG_TYPE_TRACEPOINT;
107         } else if (is_raw_tracepoint) {
108                 prog_type = BPF_PROG_TYPE_RAW_TRACEPOINT;
109         } else if (is_xdp) {
110                 prog_type = BPF_PROG_TYPE_XDP;
111         } else if (is_perf_event) {
112                 prog_type = BPF_PROG_TYPE_PERF_EVENT;
113         } else if (is_cgroup_skb) {
114                 prog_type = BPF_PROG_TYPE_CGROUP_SKB;
115         } else if (is_cgroup_sk) {
116                 prog_type = BPF_PROG_TYPE_CGROUP_SOCK;
117         } else if (is_sockops) {
118                 prog_type = BPF_PROG_TYPE_SOCK_OPS;
119         } else if (is_sk_skb) {
120                 prog_type = BPF_PROG_TYPE_SK_SKB;
121         } else if (is_sk_msg) {
122                 prog_type = BPF_PROG_TYPE_SK_MSG;
123         } else {
124                 printf("Unknown event '%s'\n", event);
125                 return -1;
126         }
127
128         if (prog_cnt == MAX_PROGS) /*#define MAX_PROGS 32 samples/bpf/bpf_load.h*/
129                 return -1;
130
131         fd = bpf_load_program(prog_type, prog, insns_cnt, license, kern_version,
132                               bpf_log_buf, BPF_LOG_BUF_SIZE);
133         if (fd < 0) {
134                 printf("bpf_load_program() err=%d\n%s", errno, bpf_log_buf);
135                 return -1;
136         }
137
138         prog_fd[prog_cnt++] = fd;
139
140         if (is_xdp || is_perf_event || is_cgroup_skb || is_cgroup_sk)
141                 return 0;
142
143         if (is_socket || is_sockops || is_sk_skb || is_sk_msg) {
144                 if (is_socket)
145                         event += 6;
146                 else
147                         event += 7;
148                 if (*event != '/')
149                         return 0;
150                 event++;
151                 if (!isdigit(*event)) {
152                         printf("invalid prog number\n");
153                         return -1;
154                 }
155                 return populate_prog_array(event, fd);
156         }
157
158         if (is_raw_tracepoint) {
159                 efd = bpf_raw_tracepoint_open(event + 15, fd);
160                 if (efd < 0) {
161                         printf("tracepoint %s %s\n", event + 15, strerror(errno));
162                         return -1;
163                 }
164                 event_fd[prog_cnt - 1] = efd;
165                 return 0;
166         }
167
168         if (is_kprobe || is_kretprobe) {
169                 bool need_normal_check = true;
170                 const char *event_prefix = "";
171
172                 if (is_kprobe)
173                         event += 7;
174                 else
175                         event += 10;
176
177                 if (*event == 0) {
178                         printf("event name cannot be empty\n");
179                         return -1;
180                 }
181
182                 if (isdigit(*event))
183                         return populate_prog_array(event, fd);
184
185 #ifdef __x86_64__
186                 if (strncmp(event, "sys_", 4) == 0) {
187                         snprintf(buf, sizeof(buf), "%c:__x64_%s __x64_%s",
188                                 is_kprobe ? 'p' : 'r', event, event);
189                         err = write_kprobe_events(buf);
190                         if (err >= 0) {
191                                 need_normal_check = false;
192                                 event_prefix = "__x64_";
193                         }
194                 }
195 #endif
196                 if (need_normal_check) {
197                         snprintf(buf, sizeof(buf), "%c:%s %s",
198                                 is_kprobe ? 'p' : 'r', event, event);
199                         err = write_kprobe_events(buf);
200                         if (err < 0) {
201                                 printf("failed to create kprobe '%s' error '%s'\n",
202                                        event, strerror(errno));
203                                 return -1;
204                         }
205                 }
206
207                 strcpy(buf, DEBUGFS);
208                 strcat(buf, "events/kprobes/");
209                 strcat(buf, event_prefix);
210                 strcat(buf, event);
211                 strcat(buf, "/id");
212         } else if (is_tracepoint) {
213                 event += 11;
214
215                 if (*event == 0) {
216                         printf("event name cannot be empty\n");
217                         return -1;
218                 }
219                 strcpy(buf, DEBUGFS); 
220                 strcat(buf, "events/"); // "/sys/kernel/debug/tracing/"
221                 strcat(buf, event);
222                 strcat(buf, "/id");
223         }
224
225         efd = open(buf, O_RDONLY, 0);
226         if (efd < 0) {
227                 printf("failed to open event %s\n", event);
228                 return -1;
229         }
230
231         err = read(efd, buf, sizeof(buf));
232         if (err < 0 || err >= sizeof(buf)) {
233                 printf("read from '%s' failed '%s'\n", event, strerror(errno));
234                 return -1;
235         }
236
237         close(efd);
238
239         buf[err] = 0;
240         id = atoi(buf);
241         attr.config = id;
242
243         efd = sys_perf_event_open(&attr, -1/*pid*/, 0/*cpu*/, -1/*group_fd*/, 0);
244         if (efd < 0) {
245                 printf("event %d fd %d err %s\n", id, efd, strerror(errno));
246                 return -1;
247         }
248         event_fd[prog_cnt - 1] = efd;
249         err = ioctl(efd, PERF_EVENT_IOC_ENABLE, 0);
250         if (err < 0) {
251                 printf("ioctl PERF_EVENT_IOC_ENABLE failed err %s\n",
252                        strerror(errno));
253                 return -1;
254         }
255         err = ioctl(efd, PERF_EVENT_IOC_SET_BPF, fd);
256         if (err < 0) {
257                 printf("ioctl PERF_EVENT_IOC_SET_BPF failed err %s\n",
258                        strerror(errno));
259                 return -1;
260         }
261
262         return 0;
263 }
```

通过函数  `load_and_attach` 中的 212 行 - 262 行分析我们可以得知

```c
212         } else if (is_tracepoint) {  // 如果为 tracepoint，获取到 tracepoint id 的完整目录
213                 event += 11;
214
215                 if (*event == 0) {
216                         printf("event name cannot be empty\n");
217                         return -1;
218                 }
219                 strcpy(buf, DEBUGFS); 
220                 strcat(buf, "events/"); 
221                 strcat(buf, event);
222                 strcat(buf, "/id"); // "/sys/kernel/debug/tracing/syscalls/sys_enter_execve/id"
223         }
224         // 1. 打开文件 "/sys/kernel/debug/tracing/syscalls/sys_enter_execve/id"，文件内容 “685”
225         efd = open(buf, O_RDONLY, 0);
226         if (efd < 0) {
227                 printf("failed to open event %s\n", event);
228                 return -1;
229         }
230         // 2. 获取到 event id  “685”
231         err = read(efd, buf, sizeof(buf));
232         if (err < 0 || err >= sizeof(buf)) {
233                 printf("read from '%s' failed '%s'\n", event, strerror(errno));
234                 return -1;
235         }
236
237         close(efd);
238
239         buf[err] = 0;
240         id = atoi(buf);
241         attr.config = id;
242         // 3. 使用 sys_perf_event_open 函数开启  
243         efd = sys_perf_event_open(&attr, -1/*pid*/, 0/*cpu*/, -1/*group_fd*/, 0);
244         if (efd < 0) {
245                 printf("event %d fd %d err %s\n", id, efd, strerror(errno));
246                 return -1;
247         }
248         event_fd[prog_cnt - 1] = efd;
            // 4. 开启该 event 的追踪
249         err = ioctl(efd, PERF_EVENT_IOC_ENABLE, 0);
250         if (err < 0) {
251                 printf("ioctl PERF_EVENT_IOC_ENABLE failed err %s\n",
252                        strerror(errno));
253                 return -1;
254         }
            // 5. 设置当前追踪所对应的 BPF 程序，fd 即为我们本次打开的 BPF 程序 fd
            // 相关说明参见 https://lwn.net/Articles/683504/
255         err = ioctl(efd, PERF_EVENT_IOC_SET_BPF, fd);
256         if (err < 0) {
257                 printf("ioctl PERF_EVENT_IOC_SET_BPF failed err %s\n",
258                        strerror(errno));
259                 return -1;
260         }
261
262         return 0;
```

ioctl 函数定义在文件 kernel/events/core.c 文件中

```c
 6199 static const struct file_operations perf_fops = {
 6200         .llseek                 = no_llseek,
 6201         .release                = perf_release,
 6202         .read                   = perf_read,
 6203         .poll                   = perf_poll,
 6204         .unlocked_ioctl         = perf_ioctl,
 6205         .compat_ioctl           = perf_compat_ioctl,
 6206         .mmap                   = perf_mmap,
 6207         .fasync                 = perf_fasync,
 6208 };

 5517 static long perf_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
 5518 {
 5519         struct perf_event *event = file->private_data;
 5520         struct perf_event_context *ctx;
 5521         long ret;
 5522
 5523         /* Treat ioctl like writes as it is likely a mutating operation. */
 5524         ret = security_perf_event_write(event);
 5525         if (ret)
 5526                 return ret;
 5527
 5528         ctx = perf_event_ctx_lock(event);
 5529         ret = _perf_ioctl(event, cmd, arg);
 5530         perf_event_ctx_unlock(event, ctx);
 5531
 5532         return ret;
 5533 }

 5417 static long _perf_ioctl(struct perf_event *event, unsigned int cmd, unsigned long arg)
 5418 {
         // ...
 5475         case PERF_EVENT_IOC_SET_BPF:
 5476                 return perf_event_set_bpf_prog(event, arg);
        // ...
 }
 
 // perf_event_set_bpf_prog 定义如下
 9593 static int perf_event_set_bpf_prog(struct perf_event *event, u32 prog_fd)
 9594 {
 9595         bool is_kprobe, is_tracepoint, is_syscall_tp;
 9596         struct bpf_prog *prog;
 9597         int ret;
 9598
 9599         if (!perf_event_is_tracing(event))
 9600                 return perf_event_set_bpf_handler(event, prog_fd);
 9601
 9602         is_kprobe = event->tp_event->flags & TRACE_EVENT_FL_UKPROBE;
 9603         is_tracepoint = event->tp_event->flags & TRACE_EVENT_FL_TRACEPOINT;
 9604         is_syscall_tp = is_syscall_trace_event(event->tp_event);
 9605         if (!is_kprobe && !is_tracepoint && !is_syscall_tp)
 9606                 /* bpf programs can only be attached to u/kprobe or tracepoint */
 9607                 return -EINVAL;
 9608
 9609         prog = bpf_prog_get(prog_fd);
 9610         if (IS_ERR(prog))
 9611                 return PTR_ERR(prog);
 9612
 9613         if ((is_kprobe && prog->type != BPF_PROG_TYPE_KPROBE) ||
 9614             (is_tracepoint && prog->type != BPF_PROG_TYPE_TRACEPOINT) ||
 9615             (is_syscall_tp && prog->type != BPF_PROG_TYPE_TRACEPOINT)) {
 9616                 /* valid fd, but invalid bpf program type */
 9617                 bpf_prog_put(prog);
 9618                 return -EINVAL;
 9619         }
 9620
 9621         /* Kprobe override only works for kprobes, not uprobes. */
 9622         if (prog->kprobe_override &&
 9623             !(event->tp_event->flags & TRACE_EVENT_FL_KPROBE)) {
 9624                 bpf_prog_put(prog);
 9625                 return -EINVAL;
 9626         }
 9627
 9628         if (is_tracepoint || is_syscall_tp) {
 9629                 int off = trace_event_get_offsets(event->tp_event);
 9630
 9631                 if (prog->aux->max_ctx_offset > off) {
 9632                         bpf_prog_put(prog);
 9633                         return -EACCES;
 9634                 }
 9635         }
 9636
 9637         ret = perf_event_attach_bpf_prog(event, prog);
 9638         if (ret)
 9639                 bpf_prog_put(prog);
 9640         return ret;
 9641 }
  // 函数最终调用 perf_event_attach_bpf_prog
```

该函数 `perf_event_attach_bpf_prog` 定义在 kernel/trace/bpf_trace.c 中

```c
1687 #define BPF_TRACE_MAX_PROGS 64
1688
1689 int perf_event_attach_bpf_prog(struct perf_event *event,
1690                                struct bpf_prog *prog)
1691 {
1692         struct bpf_prog_array *old_array;
1693         struct bpf_prog_array *new_array;
1694         int ret = -EEXIST;
1695
1696         /*
1697          * Kprobe override only works if they are on the function entry,
1698          * and only if they are on the opt-in list.
1699          */
1700         if (prog->kprobe_override &&
1701             (!trace_kprobe_on_func_entry(event->tp_event) ||
1702              !trace_kprobe_error_injectable(event->tp_event)))
1703                 return -EINVAL;
1704
1705         mutex_lock(&bpf_event_mutex);
1706
1707         if (event->prog)
1708                 goto unlock;
1709
1710         old_array = bpf_event_rcu_dereference(event->tp_event->prog_array);
1711         if (old_array &&
1712             bpf_prog_array_length(old_array) >= BPF_TRACE_MAX_PROGS) {
1713                 ret = -E2BIG;
1714                 goto unlock;
1715         }
1716
1717         ret = bpf_prog_array_copy(old_array, NULL, prog, &new_array);
1718         if (ret < 0)
1719                 goto unlock;
1720
1721         /* set the new array to event->tp_event and set event->prog */
1722         event->prog = prog;
1723         rcu_assign_pointer(event->tp_event->prog_array, new_array);
1724         bpf_prog_array_free(old_array);
1725
1726 unlock:
1727         mutex_unlock(&bpf_event_mutex);
1728         return ret;
1729 }
1730
```



最终触发的逻辑：

```
 // perf event 触发的时候调用 bpf
 9240 void perf_trace_run_bpf_submit(void *raw_data, int size, int rctx,
 9241                                struct trace_event_call *call, u64 count,
 9242                                struct pt_regs *regs, struct hlist_head *head,
 9243                                struct task_struct *task)
 9244 {
 9245         if (bpf_prog_array_valid(call)) {
 9246                 *(struct pt_regs **)raw_data = regs;
 9247                 if (!trace_call_bpf(call, raw_data) || hlist_empty(head)) { // 调用 bpf 程序
 9248                         perf_swevent_put_recursion_context(rctx);
 9249                         return;
 9250                 }
 9251         }
 9252         perf_tp_event(call->event.type, count, raw_data, size, regs, head,
 9253                       rctx, task);
 9254 }
 9255 EXPORT_SYMBOL_GPL(perf_trace_run_bpf_submit);
```

函数 `bpf_prog_array_valid` 位于文件 include/linux/trace_events.h

```c
312 #ifdef CONFIG_PERF_EVENTS
313 static inline bool bpf_prog_array_valid(struct trace_event_call *call)
314 {
315         /*
316          * This inline function checks whether call->prog_array
317          * is valid or not. The function is called in various places,
318          * outside rcu_read_lock/unlock, as a heuristic to speed up execution.
319          *
320          * If this function returns true, and later call->prog_array
321          * becomes false inside rcu_read_lock/unlock region,
322          * we bail out then. If this function return false,
323          * there is a risk that we might miss a few events if the checking
324          * were delayed until inside rcu_read_lock/unlock region and
325          * call->prog_array happened to become non-NULL then.
326          *
327          * Here, READ_ONCE() is used instead of rcu_access_pointer().
328          * rcu_access_pointer() requires the actual definition of
329          * "struct bpf_prog_array" while READ_ONCE() only needs
330          * a declaration of the same type.
331          */
332         return !!READ_ONCE(call->prog_array);
333 }
334 #endif
```

结构 `struct trace_event_call` 定义在 include/linux/trace_events.h 中

```c
611 struct perf_event {
    // ...
749 #ifdef CONFIG_EVENT_TRACING
750         struct trace_event_call         *tp_event;   // -> trace_event_call
751         struct event_filter             *filter;
752 #ifdef CONFIG_FUNCTION_TRACER
    // ...
}   

278 struct trace_event_call {
279         struct list_head        list;
280         struct trace_event_class *class;
281         union {
282                 char                    *name;
283                 /* Set TRACE_EVENT_FL_TRACEPOINT flag when using "tp" */
284                 struct tracepoint       *tp;
285         };
286         struct trace_event      event;
287         char                    *print_fmt;
288         struct event_filter     *filter;
289         void                    *mod;
290         void                    *data;
291         /*
292          *   bit 0:             filter_active
293          *   bit 1:             allow trace by non root (cap any)
294          *   bit 2:             failed to apply filter
295          *   bit 3:             trace internal event (do not enable)
296          *   bit 4:             Event was enabled by module
297          *   bit 5:             use call filter rather than file filter
298          *   bit 6:             Event is a tracepoint
299          */
300         int                     flags; /* static flags of different events */
301
302 #ifdef CONFIG_PERF_EVENTS
303         int                             perf_refcount;
304         struct hlist_head __percpu      *perf_events;
305         struct bpf_prog_array __rcu     *prog_array;  // 保存 bpf 程序
306
307         int     (*perf_perm)(struct trace_event_call *,
308                              struct perf_event *);
309 #endif
310 };
```



`bpf_load_program` 函数定义在   tools/lib/bpf/bpf.c 文件中

```c
332 int bpf_load_program(enum bpf_prog_type type, const struct bpf_insn *insns,
333                      size_t insns_cnt, const char *license,
334                      __u32 kern_version, char *log_buf,
335                      size_t log_buf_sz)
336 {
337         struct bpf_load_program_attr load_attr;
338
339         memset(&load_attr, 0, sizeof(struct bpf_load_program_attr));
340         load_attr.prog_type = type;
341         load_attr.expected_attach_type = 0;
342         load_attr.name = NULL;
343         load_attr.insns = insns;
344         load_attr.insns_cnt = insns_cnt;
345         load_attr.license = license;
346         load_attr.kern_version = kern_version;
347
348         return bpf_load_program_xattr(&load_attr, log_buf, log_buf_sz);
349 }

220 int bpf_load_program_xattr(const struct bpf_load_program_attr *load_attr,
221                            char *log_buf, size_t log_buf_sz)
222 {
223         void *finfo = NULL, *linfo = NULL;
224         union bpf_attr attr;
225         __u32 log_level;
226         int fd;
227
228         if (!load_attr || !log_buf != !log_buf_sz)
229                 return -EINVAL;
230
231         log_level = load_attr->log_level;
232         if (log_level > (4 | 2 | 1) || (log_level && !log_buf))
233                 return -EINVAL;
234
235         memset(&attr, 0, sizeof(attr));
236         attr.prog_type = load_attr->prog_type;
237         attr.expected_attach_type = load_attr->expected_attach_type;
238         if (attr.prog_type == BPF_PROG_TYPE_STRUCT_OPS ||
239             attr.prog_type == BPF_PROG_TYPE_LSM) {
240                 attr.attach_btf_id = load_attr->attach_btf_id;
241         } else if (attr.prog_type == BPF_PROG_TYPE_TRACING ||
242                    attr.prog_type == BPF_PROG_TYPE_EXT) {
243                 attr.attach_btf_id = load_attr->attach_btf_id;
244                 attr.attach_prog_fd = load_attr->attach_prog_fd;
245         } else {
246                 attr.prog_ifindex = load_attr->prog_ifindex;
247                 attr.kern_version = load_attr->kern_version;
248         }
247                 attr.kern_version = load_attr->kern_version;
248         }
249         attr.insn_cnt = (__u32)load_attr->insns_cnt;
250         attr.insns = ptr_to_u64(load_attr->insns);
251         attr.license = ptr_to_u64(load_attr->license);
252
253         attr.log_level = log_level;
254         if (log_level) {
255                 attr.log_buf = ptr_to_u64(log_buf);
256                 attr.log_size = log_buf_sz;
257         } else {
258                 attr.log_buf = ptr_to_u64(NULL);
259                 attr.log_size = 0;
260         }
261
262         attr.prog_btf_fd = load_attr->prog_btf_fd;
263         attr.func_info_rec_size = load_attr->func_info_rec_size;
264         attr.func_info_cnt = load_attr->func_info_cnt;
265         attr.func_info = ptr_to_u64(load_attr->func_info);
266         attr.line_info_rec_size = load_attr->line_info_rec_size;
267         attr.line_info_cnt = load_attr->line_info_cnt;
268         attr.line_info = ptr_to_u64(load_attr->line_info);
269         if (load_attr->name)
270                 memcpy(attr.prog_name, load_attr->name,
271                        min(strlen(load_attr->name), BPF_OBJ_NAME_LEN - 1));
272         attr.prog_flags = load_attr->prog_flags;
273
274         fd = sys_bpf_prog_load(&attr, sizeof(attr));
275         if (fd >= 0)
276                 return fd;
277
278         /* After bpf_prog_load, the kernel may modify certain attributes
279          * to give user space a hint how to deal with loading failure.
280          * Check to see whether we can make some changes and load again.
281          */
282         while (errno == E2BIG && (!finfo || !linfo)) {
283                 if (!finfo && attr.func_info_cnt &&
284                     attr.func_info_rec_size < load_attr->func_info_rec_size) {
285                         /* try with corrected func info records */
286                         finfo = alloc_zero_tailing_info(load_attr->func_info,
287                                                         load_attr->func_info_cnt,
288                                                         load_attr->func_info_rec_size,
289                                                         attr.func_info_rec_size);
290                         if (!finfo)
291                                 goto done;
292
293                         attr.func_info = ptr_to_u64(finfo);
294                         attr.func_info_rec_size = load_attr->func_info_rec_size;
295                 } else if (!linfo && attr.line_info_cnt &&
296                            attr.line_info_rec_size <
297                            load_attr->line_info_rec_size) {
298                         linfo = alloc_zero_tailing_info(load_attr->line_info,
299                                                         load_attr->line_info_cnt,
300                                                         load_attr->line_info_rec_size,
301                                                         attr.line_info_rec_size);
302                         if (!linfo)
303                                 goto done;
304
305                         attr.line_info = ptr_to_u64(linfo);
306                         attr.line_info_rec_size = load_attr->line_info_rec_size;
307                 } else {
308                         break;
309                 }
310
311                 fd = sys_bpf_prog_load(&attr, sizeof(attr));
312
313                 if (fd >= 0)
314                         goto done;
315         }
316
317         if (log_level || !log_buf)
318                 goto done;
319
320         /* Try again with log */
321         attr.log_buf = ptr_to_u64(log_buf);
322         attr.log_size = log_buf_sz;
323         attr.log_level = 1;
324         log_buf[0] = 0;
325         fd = sys_bpf_prog_load(&attr, sizeof(attr));
326 done:
327         free(finfo);
328         free(linfo);
329         return fd;
330 }
```



BPF 的程序类型是在程序加载的时候在内核中进行确定的，一旦程序类型确定，也就确定了 BPF 程序能够访问到的 BPF 内核帮助函数。

```bash
# strace -ebpf execsnoop
bpf(BPF_MAP_CREATE, {map_type=BPF_MAP_TYPE_PERF_EVENT_ARRAY, key_size=4,
value_size=4, max_entries=8, map_flags=0, inner_map_fd=0, ...}, 72) = 3
bpf(BPF_PROG_LOAD, {prog_type=BPF_PROG_TYPE_KPROBE, insn_cnt=513,
insns=0x7f31c0a89000, license="GPL", log_level=0, log_size=0, log_buf=0,
kern_version=266002, prog_flags=0, ...}, 72) = 4
bpf(BPF_PROG_LOAD, {prog_type=BPF_PROG_TYPE_KPROBE, insn_cnt=60,
insns=0x7f31c0a8b7d0, license="GPL", log_level=0, log_size=0, log_buf=0,
kern_version=266002, prog_flags=0, ...}, 72) = 6
PCOMM            PID    PPID   RET ARGS
bpf(BPF_MAP_UPDATE_ELEM, {map_fd=3, key=0x7f31ba81e880, value=0x7f31ba81e910,
flags=BPF_ANY}, 72) = 0
bpf(BPF_MAP_UPDATE_ELEM, {map_fd=3, key=0x7f31ba81e910, value=0x7f31ba81e880,
flags=BPF_ANY}, 72) = 0
[...]

```

BPF Verfier 会根据底层的程序类型进行对应的检查：

```go
static bool may_access_skb(enum bpf_prog_type type)
{
        switch (type) {
        case BPF_PROG_TYPE_SOCKET_FILTER:
        case BPF_PROG_TYPE_SCHED_CLS:
        case BPF_PROG_TYPE_SCHED_ACT:
                return true;
        default:
                return false;
        }
}
```

每种 BPF 类型可以使用的函数列表参见：[program-types](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#program-types)。程序类型对应的函数关系可以通过以下命令来进行获取：

    git grep -W 'func_proto(enum bpf_func_id func_id' kernel/ net/ drivers/

完整的程序类型对应的帮助函数表格如下：
|Program Type| Helper Functions|
|------------|-----------------|
|`BPF_PROG_TYPE_SOCKET_FILTER`|`BPF_FUNC_skb_load_bytes()` <br> `BPF_FUNC_skb_load_bytes_relative()` <br> `BPF_FUNC_get_socket_cookie()` <br> `BPF_FUNC_get_socket_uid()` <br> `BPF_FUNC_perf_event_output()` <br> `Base functions`|
|`BPF_PROG_TYPE_KPROBE`|`BPF_FUNC_perf_event_output()` <br> `BPF_FUNC_get_stackid()` <br> `BPF_FUNC_get_stack()` <br> `BPF_FUNC_perf_event_read_value()` <br> `BPF_FUNC_override_return()` <br> `Tracing functions`|
|`BPF_PROG_TYPE_SCHED_CLS` <br> `BPF_PROG_TYPE_SCHED_ACT`|`BPF_FUNC_skb_store_bytes()` <br> `BPF_FUNC_skb_load_bytes()` <br> `BPF_FUNC_skb_load_bytes_relative()` <br> `BPF_FUNC_skb_pull_data()` <br> `BPF_FUNC_csum_diff()` <br> `BPF_FUNC_csum_update()` <br> `BPF_FUNC_l3_csum_replace()` <br> `BPF_FUNC_l4_csum_replace()` <br> `BPF_FUNC_clone_redirect()` <br> `BPF_FUNC_get_cgroup_classid()` <br> `BPF_FUNC_skb_vlan_push()` <br> `BPF_FUNC_skb_vlan_pop()` <br> `BPF_FUNC_skb_change_proto()` <br> `BPF_FUNC_skb_change_type()` <br> `BPF_FUNC_skb_adjust_room()` <br> `BPF_FUNC_skb_change_tail()` <br> `BPF_FUNC_skb_get_tunnel_key()` <br> `BPF_FUNC_skb_set_tunnel_key()` <br> `BPF_FUNC_skb_get_tunnel_opt()` <br> `BPF_FUNC_skb_set_tunnel_opt()` <br> `BPF_FUNC_redirect()` <br> `BPF_FUNC_get_route_realm()` <br> `BPF_FUNC_get_hash_recalc()` <br> `BPF_FUNC_set_hash_invalid()` <br> `BPF_FUNC_set_hash()` <br> `BPF_FUNC_perf_event_output()` <br> `BPF_FUNC_get_smp_processor_id()` <br> `BPF_FUNC_skb_under_cgroup()` <br> `BPF_FUNC_get_socket_cookie()` <br> `BPF_FUNC_get_socket_uid()` <br> `BPF_FUNC_fib_lookup()` <br> `BPF_FUNC_skb_get_xfrm_state()` <br> `BPF_FUNC_skb_cgroup_id()` <br> `Base functions`|
|`BPF_PROG_TYPE_TRACEPOINT`|`BPF_FUNC_perf_event_output()` <br> `BPF_FUNC_get_stackid()` <br> `BPF_FUNC_get_stack()` <br> `Tracing functions`|
|`BPF_PROG_TYPE_XDP`| `BPF_FUNC_perf_event_output()` <br> `BPF_FUNC_get_smp_processor_id()` <br> `BPF_FUNC_csum_diff()` <br> `BPF_FUNC_xdp_adjust_head()` <br> `BPF_FUNC_xdp_adjust_meta()` <br> `BPF_FUNC_redirect()` <br> `BPF_FUNC_redirect_map()` <br> `BPF_FUNC_xdp_adjust_tail()` <br> `BPF_FUNC_fib_lookup()` <br> `Base functions`|
|`BPF_PROG_TYPE_PERF_EVENT`| `BPF_FUNC_perf_event_output()` <br> `BPF_FUNC_get_stackid()` <br> `BPF_FUNC_get_stack()` <br> `BPF_FUNC_perf_prog_read_value()` <br> `Tracing functions`|
|`BPF_PROG_TYPE_CGROUP_SKB`|`BPF_FUNC_skb_load_bytes()` <br> `BPF_FUNC_skb_load_bytes_relative()` <br> `BPF_FUNC_get_socket_cookie()` <br> `BPF_FUNC_get_socket_uid()` <br> `Base functions`|
|`BPF_PROG_TYPE_CGROUP_SOCK`|`BPF_FUNC_get_current_uid_gid()` <br> `Base functions`|
|`BPF_PROG_TYPE_LWT_IN`|`BPF_FUNC_lwt_push_encap()` <br> `LWT functions` <br> `Base functions`|
|`BPF_PROG_TYPE_LWT_OUT`| `LWT functions` <br> `Base functions`|
|`BPF_PROG_TYPE_LWT_XMIT`| `BPF_FUNC_skb_get_tunnel_key()` <br> `BPF_FUNC_skb_set_tunnel_key()` <br> `BPF_FUNC_skb_get_tunnel_opt()` <br> `BPF_FUNC_skb_set_tunnel_opt()` <br> `BPF_FUNC_redirect()` <br> `BPF_FUNC_clone_redirect()` <br> `BPF_FUNC_skb_change_tail()` <br> `BPF_FUNC_skb_change_head()` <br> `BPF_FUNC_skb_store_bytes()` <br> `BPF_FUNC_csum_update()` <br> `BPF_FUNC_l3_csum_replace()` <br> `BPF_FUNC_l4_csum_replace()` <br> `BPF_FUNC_set_hash_invalid()` <br> `LWT functions`|
|`BPF_PROG_TYPE_SOCK_OPS`|`BPF_FUNC_setsockopt()` <br> `BPF_FUNC_getsockopt()` <br> `BPF_FUNC_sock_ops_cb_flags_set()` <br> `BPF_FUNC_sock_map_update()` <br> `BPF_FUNC_sock_hash_update()` <br> `BPF_FUNC_get_socket_cookie()` <br> `Base functions`|
|`BPF_PROG_TYPE_SK_SKB`|`BPF_FUNC_skb_store_bytes()` <br> `BPF_FUNC_skb_load_bytes()` <br> `BPF_FUNC_skb_pull_data()` <br> `BPF_FUNC_skb_change_tail()` <br> `BPF_FUNC_skb_change_head()` <br> `BPF_FUNC_get_socket_cookie()` <br> `BPF_FUNC_get_socket_uid()` <br> `BPF_FUNC_sk_redirect_map()` <br> `BPF_FUNC_sk_redirect_hash()` <br> `BPF_FUNC_sk_lookup_tcp()` <br> `BPF_FUNC_sk_lookup_udp()` <br> `BPF_FUNC_sk_release()` <br> `Base functions`|
|`BPF_PROG_TYPE_CGROUP_DEVICE`|`BPF_FUNC_map_lookup_elem()` <br> `BPF_FUNC_map_update_elem()` <br> `BPF_FUNC_map_delete_elem()` <br> `BPF_FUNC_get_current_uid_gid()` <br> `BPF_FUNC_trace_printk()`|
|`BPF_PROG_TYPE_SK_MSG`|`BPF_FUNC_msg_redirect_map()` <br> `BPF_FUNC_msg_redirect_hash()` <br> `BPF_FUNC_msg_apply_bytes()` <br> `BPF_FUNC_msg_cork_bytes()` <br> `BPF_FUNC_msg_pull_data()` <br> `BPF_FUNC_msg_push_data()` <br> `BPF_FUNC_msg_pop_data()` <br> `Base functions`|
|`BPF_PROG_TYPE_RAW_TRACEPOINT`|`BPF_FUNC_perf_event_output()` <br> `BPF_FUNC_get_stackid()` <br> `BPF_FUNC_get_stack()` <br> `BPF_FUNC_skb_output()` <br> `Tracing functions`|
|`BPF_PROG_TYPE_CGROUP_SOCK_ADDR`|`BPF_FUNC_get_current_uid_gid()` <br> `BPF_FUNC_bind()` <br> `BPF_FUNC_get_socket_cookie()` <br> `Base functions`|
|`BPF_PROG_TYPE_LWT_SEG6LOCAL`|`BPF_FUNC_lwt_seg6_store_bytes()` <br> `BPF_FUNC_lwt_seg6_action()` <br> `BPF_FUNC_lwt_seg6_adjust_srh()` <br> `LWT functions`|
|`BPF_PROG_TYPE_LIRC_MODE2`|`BPF_FUNC_rc_repeat()` <br> `BPF_FUNC_rc_keydown()` <br> `BPF_FUNC_rc_pointer_rel()` <br> `BPF_FUNC_map_lookup_elem()` <br> `BPF_FUNC_map_update_elem()` <br> `BPF_FUNC_map_delete_elem()` <br> `BPF_FUNC_ktime_get_ns()` <br> `BPF_FUNC_tail_call()` <br> `BPF_FUNC_get_prandom_u32()` <br> `BPF_FUNC_trace_printk()`|
|`BPF_PROG_TYPE_SK_REUSEPORT`|`BPF_FUNC_sk_select_reuseport()` <br> `BPF_FUNC_skb_load_bytes()` <br> `BPF_FUNC_load_bytes_relative()` <br> `Base functions`|
|`BPF_PROG_TYPE_FLOW_DISSECTOR`|`BPF_FUNC_skb_load_bytes()` <br> `Base functions`|

|Function Group| Functions|
|------------------|-------|
|`Base functions`| `BPF_FUNC_map_lookup_elem()` <br> `BPF_FUNC_map_update_elem()` <br> `BPF_FUNC_map_delete_elem()` <br> `BPF_FUNC_map_peek_elem()` <br> `BPF_FUNC_map_pop_elem()` <br> `BPF_FUNC_map_push_elem()` <br> `BPF_FUNC_get_prandom_u32()` <br> `BPF_FUNC_get_smp_processor_id()` <br> `BPF_FUNC_get_numa_node_id()` <br> `BPF_FUNC_tail_call()` <br> `BPF_FUNC_ktime_get_boot_ns()` <br> `BPF_FUNC_ktime_get_ns()` <br> `BPF_FUNC_trace_printk()` <br> `BPF_FUNC_spin_lock()` <br> `BPF_FUNC_spin_unlock()` |
|`Tracing functions`|`BPF_FUNC_map_lookup_elem()` <br> `BPF_FUNC_map_update_elem()` <br> `BPF_FUNC_map_delete_elem()` <br> `BPF_FUNC_probe_read()` <br> `BPF_FUNC_ktime_get_boot_ns()` <br> `BPF_FUNC_ktime_get_ns()` <br> `BPF_FUNC_tail_call()` <br> `BPF_FUNC_get_current_pid_tgid()` <br> `BPF_FUNC_get_current_task()` <br> `BPF_FUNC_get_current_uid_gid()` <br> `BPF_FUNC_get_current_comm()` <br> `BPF_FUNC_trace_printk()` <br> `BPF_FUNC_get_smp_processor_id()` <br> `BPF_FUNC_get_numa_node_id()` <br> `BPF_FUNC_perf_event_read()` <br> `BPF_FUNC_probe_write_user()` <br> `BPF_FUNC_current_task_under_cgroup()` <br> `BPF_FUNC_get_prandom_u32()` <br> `BPF_FUNC_probe_read_str()` <br> `BPF_FUNC_get_current_cgroup_id()` <br> `BPF_FUNC_send_signal()` <br> `BPF_FUNC_probe_read_kernel()` <br> `BPF_FUNC_probe_read_kernel_str()` <br> `BPF_FUNC_probe_read_user()` <br> `BPF_FUNC_probe_read_user_str()` <br> `BPF_FUNC_send_signal_thread()` <br> `BPF_FUNC_get_ns_current_pid_tgid()` <br> `BPF_FUNC_xdp_output()` <br> `BPF_FUNC_get_task_stack()`|
|`LWT functions`|  `BPF_FUNC_skb_load_bytes()` <br> `BPF_FUNC_skb_pull_data()` <br> `BPF_FUNC_csum_diff()` <br> `BPF_FUNC_get_cgroup_classid()` <br> `BPF_FUNC_get_route_realm()` <br> `BPF_FUNC_get_hash_recalc()` <br> `BPF_FUNC_perf_event_output()` <br> `BPF_FUNC_get_smp_processor_id()` <br> `BPF_FUNC_skb_under_cgroup()`|



BPF 程序类型可以使用工具 bpftools 进行查看

```bash
# bpftool prog help
Usage: bpftool prog { show | list } [PROG]
       bpftool prog dump xlated PROG [{ file FILE | opcodes | visual | linum }]
       bpftool prog dump jited  PROG [{ file FILE | opcodes | linum }]
       bpftool prog pin   PROG FILE
       bpftool prog { load | loadall } OBJ  PATH \
                         [type TYPE] [dev NAME] \
                         [map { idx IDX | name NAME } MAP]\
                         [pinmaps MAP_DIR]
       bpftool prog attach PROG ATTACH_TYPE [MAP]
       bpftool prog detach PROG ATTACH_TYPE [MAP]
       bpftool prog tracelog
       bpftool prog help
       MAP := { id MAP_ID | pinned FILE }
       PROG := { id PROG_ID | pinned FILE | tag PROG_TAG }
       TYPE := { socket | kprobe | kretprobe | classifier | action |q
[...]

```



```
const char * const prog_type_name[] = {
        [BPF_PROG_TYPE_UNSPEC]                  = "unspec",
        [BPF_PROG_TYPE_SOCKET_FILTER]           = "socket_filter",
        [BPF_PROG_TYPE_KPROBE]                  = "kprobe",
        [BPF_PROG_TYPE_SCHED_CLS]               = "sched_cls",
        [BPF_PROG_TYPE_SCHED_ACT]               = "sched_act",
        [BPF_PROG_TYPE_TRACEPOINT]              = "tracepoint",
        [BPF_PROG_TYPE_XDP]                     = "xdp",
        [BPF_PROG_TYPE_PERF_EVENT]              = "perf_event",
        [BPF_PROG_TYPE_CGROUP_SKB]              = "cgroup_skb",
        [BPF_PROG_TYPE_CGROUP_SOCK]             = "cgroup_sock",
        [BPF_PROG_TYPE_LWT_IN]                  = "lwt_in",
        [BPF_PROG_TYPE_LWT_OUT]                 = "lwt_out",
        [BPF_PROG_TYPE_LWT_XMIT]                = "lwt_xmit",
        [BPF_PROG_TYPE_SOCK_OPS]                = "sock_ops",
        [BPF_PROG_TYPE_SK_SKB]                  = "sk_skb",
        [BPF_PROG_TYPE_CGROUP_DEVICE]           = "cgroup_device",
        [BPF_PROG_TYPE_SK_MSG]                  = "sk_msg",
        [BPF_PROG_TYPE_RAW_TRACEPOINT]          = "raw_tracepoint",
        [BPF_PROG_TYPE_CGROUP_SOCK_ADDR]        = "cgroup_sock_addr",
        [BPF_PROG_TYPE_LWT_SEG6LOCAL]           = "lwt_seg6local",
        [BPF_PROG_TYPE_LIRC_MODE2]              = "lirc_mode2",
        [BPF_PROG_TYPE_SK_REUSEPORT]            = "sk_reuseport",
        [BPF_PROG_TYPE_FLOW_DISSECTOR]          = "flow_dissector",
        [BPF_PROG_TYPE_CGROUP_SYSCTL]           = "cgroup_sysctl",
        [BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE] = "raw_tracepoint_writable",
        [BPF_PROG_TYPE_CGROUP_SOCKOPT]          = "cgroup_sockopt",
        [BPF_PROG_TYPE_TRACING]                 = "tracing",
        [BPF_PROG_TYPE_STRUCT_OPS]              = "struct_ops",
        [BPF_PROG_TYPE_EXT]                     = "ext",
        [BPF_PROG_TYPE_LSM]                     = "lsm",
        [BPF_PROG_TYPE_SK_LOOKUP]               = "sk_lookup",
};
```



## 参考

* [bpf for tracing](http://chrisarges.net/2019/03/21/bpf-for-tracing.html)

* [trace in linux](http://chrisarges.net/2018/10/04/tracing-in-linux.html)

* [allow bpf attach to tracepoints](https://lore.kernel.org/patchwork/cover/664890/)

* [Taming Tracepoints in the Linux Kernel](https://blogs.oracle.com/linux/taming-tracepoints-in-the-linux-kernel)