# 客户端网络调用堆栈获取

脚本 `sys_connnet.sh` 用于跟踪我们执行命令中的 connect 客户端连接的调用整个堆栈。

比如

```bash
./sys_connect.sh  curl www.baidu.com
```

然后使用脚本 `col_and_reset.sh` 可以获取到 connect 在内核中的完整调用堆栈，并关闭 ftrace 的跟踪，最终文件保存到 `/tmp/trace.log` 文件中。



在获取到 connect 的完整调用逻辑后，我们可以使用 kprobe + bpf 技术获取到函数中的更多细节。