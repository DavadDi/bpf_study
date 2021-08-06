使用 kprobe 的事件 Trace 

int tcp_conn_request(struct request_sock_ops *rsk_ops,
		     const struct tcp_request_sock_ops *af_ops,
		     struct sock *sk, struct sk_buff *skb);

/* x86
		offsetof(struct pt_regs, di),
		offsetof(struct pt_regs, si),
		offsetof(struct pt_regs, dx),
		offsetof(struct pt_regs, cx),
		offsetof(struct pt_regs, r8),
		offsetof(struct pt_regs, r9),
*/

see: https://www.kernel.org/doc/html/latest/trace/kprobetrace.html

```bash
$ sudo echo 'p:myprobe tcp_conn_request rsk_ops=%di af_ops=%si sk=%dx skb=%cx' > /sys/kernel/debug/tracing/kprobe_events

$ sudo  cat /sys/kernel/debug/tracing/events/kprobes/myprobe/format
$ sudo  echo 1 > /sys/kernel/debug/tracing/events/kprobes/myprobe/enable
$ sudo  echo 1 > tracing_on

$ sudo cat /sys/kernel/debug/tracing/trace
# tracer: nop
#
# entries-in-buffer/entries-written: 1/1   #P:16
#
#                              _-----=> irqs-off
#                             / _----=> need-resched
#                            | / _---=> hardirq/softirq
#                            || / _--=> preempt-depth
#                            ||| /     delay
#           TASK-PID   CPU#  ||||    TIMESTAMP  FUNCTION
#              | |       |   ||||       |         |
            curl-23427 [011] d.s1 5017168.745924: myprobe: (tcp_conn_request+0x0/0x760) rsk_ops=0xffffffff8b969940 af_ops=0xffffffff8b4a2b60 sk=0xffff9581df11a6c0 skb=0xffff957324b948f8

$ echo 0 > tracing_o // 关闭
```

