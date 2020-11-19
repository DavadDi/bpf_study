---
title: "如何在 BPF 程序中正确地按照 PID 过滤？"
date: 2020-11-17T21:20:06+08:00
tags: []
categories: ["BPF", "foundation"]
---



## 1. 前言

在 bpf 的实现中我们经常在内核 helper 函数 `bpf_get_current_pid_tgid()` 来进行用户空间进程 `pid` 进行过滤，那么到底如何写呢？ 在 [`BCC`](https://github.com/iovisor/bcc) 项目中有不少程序直接使用 `bpf_get_current_pid_tgid()` 直接与用户空间传入的 pid 对比，也有使用 `bpf_get_current_pid_tgid() >> 32` 进行过滤的，那么使用者或者开发者到底应该使用哪种方式，这篇文章可以帮你彻底解决这类的疑惑。



## 2. Linux 进程与线程

在 Linux 系统中进程在内核空间一般用任务/Task来表示，内核中对应的结构为 `task_struct`，每个进程之间通过该结构进行资源隔离，内核中的调度器基于 `task_struct ` 结构进行调度。

Linux 线程是基于进程的基础进行演进的，用户创建的线程在 Linux 内核中也会对等创建一个 `task_struct` 结构，属于同一个进程的多个线程对应的 `task_struct` 结构在底层实现了进程级别资源的共享，比如内存、信号量、文件等。

从上述实现上看 Linux 系统中的进程和线程在内核级别的实现并无不同，结构都是 `task_struct` ，调度器也一视同仁。

在创建方式上 Linux 线程通过 `clone` 函数实现，进程与线程的最底层都是通过 `do_fork` 函数实现，只是传入的参数不同。

>  内核线程是另外依赖的特殊的实现，有 Linux 内核负责创建，只运行在内核态，所有内核线程共享整个内核空间地址，通过 ps 命令查看的时候以 "[]" 进行区别。



## 2.1 Linux 线程

### 线程库

POSIX Thread 是以一个定义 Thread 相关函数的 API 集。Redhat 公司的 **Native POSIX Thread Library**（**NPTL**）是 [Linux内核](https://zh.wikipedia.org/wiki/Linux内核) 中实践 [POSIX Threads](https://zh.wikipedia.org/wiki/POSIX_Threads) 标准的库，参见 [wiki](https://zh.wikipedia.org/wiki/Native_POSIX_Thread_Library)。

```bash
# lsb_release -a
LSB Version:	:core-4.1-amd64:core-4.1-noarch
Distributor ID:	CentOS
Description:	CentOS Linux release 7.6.1810 (Core)
Release:	7.6.1810
Codename:	Core

# getconf GNU_LIBPTHREAD_VERSION
NPTL 2.17
```

NPTL 是一个所谓的 1:1 线程函数库，用户产生的线程与内核能够分配的对象之间的联系是一对一的，这种实现也是效率和简单的折中。

当使用 `pthread_create()` 调用创建一个线程后，在内核里就相应创建了一个调度实体 `task_struct`。

* 用户空间的线程 - - 负责执行线程的创建、销毁等操作；

* 内核空间的线程 - - 作为调度单元；



### 2.2 Linux 线程的 PID 与 TGID

进程中第一个创建的线程称作主线程，作为线程组的 Leader，线程组的 id 使用 tgid 标识，主线程的 pid 与 tgid 相同。

![linux-threads](https://www.do1618.com:8080/images/2020/11/18/1a9ad9eda46b5addbf1b9f0128932861.png)

下图也通过进程创建进程和线程的异同，给了比较直观的展示：

```bash
                      USER VIEW
 <-- PID 43 --> <----------------- PID 42 ----------------->
                     +---------+
                     | process |
                    _| pid=42  |_
                  _/ | tgid=42 | \_ (new thread) _
       _ (fork) _/   +---------+                  \
      /                                        +---------+
+---------+                                    | process |
| process |                                    | pid=44  |
| pid=43  |                                    | tgid=42 |
| tgid=43 |                                    +---------+
+---------+
 <-- PID 43 --> <--------- PID 42 --------> <--- PID 44 --->
                     KERNEL VIEW
```

`getpid` 与 `gettid` 的内核实现在文件 [kernel/sys.c](https://elixir.bootlin.com/linux/v5.8/source/kernel/sys.c#L896)：

```c
/**
 * sys_getpid - return the thread group id of the current process
 *
 * Note, despite the name, this returns the tgid not the pid.  The tgid and
 * the pid are identical unless CLONE_THREAD was specified on clone() in
 * which case the tgid is the same in all threads of the same group.
 *
 * This is SMP safe as current->tgid does not change.
 */
SYSCALL_DEFINE0(getpid)
{
	return task_tgid_vnr(current);
}

/* Thread ID - the internal kernel "pid" */
SYSCALL_DEFINE0(gettid)
{
	return task_pid_vnr(current);
}
```

`task_tgid_vnr` 的实现参见 [linux/sched.h](https://elixir.bootlin.com/linux/v5.8/source/include/linux/sched.h#L1409)， `gettid` 的情况类似：

```c
static inline pid_t task_tgid_vnr(struct task_struct *tsk)
{
	return __task_pid_nr_ns(tsk, PIDTYPE_TGID, NULL); // PIDTYPE_TGID 获取当前 task 的 tgid
}
```

函数 `__task_pid_nr_ns` 参见 [kernel/pid.c](https://elixir.bootlin.com/linux/v5.8/source/kernel/pid.c#L490)：

```c
pid_t __task_pid_nr_ns(struct task_struct *task, enum pid_type type,
			struct pid_namespace *ns)
{
	pid_t nr = 0;

	rcu_read_lock();
	if (!ns)
		ns = task_active_pid_ns(current);
	nr = pid_nr_ns(rcu_dereference(*task_pid_ptr(task, type)), ns);
	rcu_read_unlock();

	return nr;
}
```



## 3. BPF 中的 PID 过滤功能

在 BPF 中内核中的函数 [`bpf_get_current_pid_tgid()`](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#toc20):

```bash
Syntax: u64 bpf_get_current_pid_tgid(void)

Return: current->tgid << 32 | current->pid

Returns the process ID in the lower 32 bits (kernel's view of the PID, which in user space is usually presented as the thread ID), and the thread group ID in the upper 32 bits (what user space often thinks of as the PID). By directly setting this to a u32, we discard the upper 32 bits.
```

`bpf_get_current_pid_tgid` 的返回值为： `current->tgid << 32 | current->pid`，高 32 位置为 tgid ，低 32 位为 pid(tid)，如果我们计划采用进程空间传统的 pid 过滤那么则可以这样写 [`tcptop.py`](https://github.com/iovisor/bcc/blob/master/tools/tcptop.py)：

```c
int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk,
    struct msghdr *msg, size_t size)
{
    if (container_should_be_filtered()) {
        return 0;
    }
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER_PID  // if (pid != %s) { return 0; }  有 python 进行替换
      
    // ...
      
}
```

如果通过 `tid` 进行过滤那么写法这样写：

```c
int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk,
    struct msghdr *msg, size_t size)
{
    if (container_should_be_filtered()) {
        return 0;
    }
    u32 tid = bpf_get_current_pid_tgid(); // 只是取低 11 位
    FILTER_PID  // if (tid != %s) { return 0; }  有 python 进行替换
      
    // ...
      
}
```



## 4. 参考

* [linux线程与进程的理解](https://blog.csdn.net/u012218309/article/details/81912074)

* [深入 Linux 多线程编程](http://senlinzhan.github.io/2017/06/10/pthread-inside/)

* [If threads share the same PID, how can they be identified?](https://stackoverflow.com/questions/9305992/if-threads-share-the-same-pid-how-can-they-be-identified)

* [POSIX Threads Programming](https://computing.llnl.gov/tutorials/pthreads/)

* [Linux threading models compared: LinuxThreads and NPTL ](http://cs.uns.edu.ar/~jechaiz/sosd/clases/extras/03-LinuxThreads%20and%20NPTL.pdf) pdf

* [The Native POSIX Thread Library for Linux](https://compas.cs.stonybrook.edu/~nhonarmand/courses/fa14/cse506.2/papers/nptl-design.pdf) pdf