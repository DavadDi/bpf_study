# Linux Tracing System

![](http://www.slideshare.net/brendangregg/velocity-2015-linux-perf-tools/105)

整体架构图，灰色为动态跟踪

![Alt text](https://g.gravizo.com/svg?
digraph G {
    kprobes[style=filled];
    uprobes[style=filled];
    kprobes -> {ebpf;ftrace;SystemTap;LTTng}
    uprobes ->  {ebpf;ftrace;SystemTap;LTTng};
    usdt -> ebpf;
    "kernel-tracepoint" ->  {ebpf;ftrace;perf_events;SystemTap;LTTng};
    "dtrace-probes" -> {ebpf;SystemTap}   
    "lttng-ust" -> {LTTng} -> {"LTTng-front"}
    ebpf -> {BCC}
    perf_events -> {"perf-trace", "perf-tools"}
    ftrace -> {"perf-trace", "trace-cmd"; kernelshark; catapult}
    SystemTap -> {"SystemTap-front"}
   }
)




## 数据源 DataSource

|          | 内核              | 用户空间                                             |
| -------- | ----------------- | ---------------------------------------------------- |
| **动态** | kprobe            | uprobe                                               |
| **静态** | kernel tracepoint | usdt<br />dtrace probes<br />LTTng userspace Tracing |



## 提取数据的方式 Ways to extrace data

* perf
* ftrace
* LTTng
* ebpf
* SystemTap
* Sysdig



## 前端界面 Frontends

* perf
* ftrace
* trace-cmd
* catapult
* kernelshark
* trace compass
* bcc
* sysdig
* LTTng
* SystemTap



* [Linux Tracing Technologies](https://www.kernel.org/doc/html/latest/trace/index.html)

* https://support.typora.io/Draw-Diagrams-With-Markdown/

