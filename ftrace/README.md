# 客户端网络调用堆栈获取

## ftrace 跟踪 connect 内核细节

脚本 `sys_connnet.sh` 用于跟踪我们执行命令中的 connect 客户端连接的调用整个堆栈。

比如

```bash
./sys_connect.sh  curl www.baidu.com
```

然后使用脚本 `col_and_reset.sh` 可以获取到 connect 在内核中的完整调用堆栈，并关闭 ftrace 的跟踪，最终文件保存到 `/tmp/trace.log` 文件中。



在获取到 connect 的完整调用逻辑后，我们可以使用 kprobe + bpf 技术获取到函数中的更多细节。



##  扩展

[perf-tools](https://github.com/brendangregg/perf-tools)中的 [funcgraph](https://github.com/brendangregg/perf-tools/blob/master/bin/funcgraph) 对于 ftrace 的使用做了更加易用的封装，我们可以直接使用。



BCC 的 [trace](https://github.com/iovisor/bcc/blob/master/tools/trace.py) 工具与  [funcgraph](https://github.com/brendangregg/perf-tools/blob/master/bin/funcgraph) 的配合对于内核函数的调用跟踪起到绝妙的配合。

* [trace](https://github.com/iovisor/bcc/blob/master/tools/trace.py)  用于跟踪这个函数被谁调用的，就是函数调用的上半部分，用于确定函数被那些堆栈的调用。
*  [funcgraph](https://github.com/brendangregg/perf-tools/blob/master/bin/funcgraph)  则是这个函数调用了那些函数，实现调用方的完整堆栈。