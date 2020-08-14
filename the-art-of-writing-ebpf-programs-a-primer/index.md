# The art of writing eBPF programs: a primer

>  By Gianluca Borello
> on February 27, 2019
> 原文地址： https://sysdig.com/blog/the-art-of-writing-ebpf-programs-a-primer/

Interested in writing eBPF programs? In this blog, this will be our focus — the process of writing eBPF programs. For reference, in the [first part](https://sysdig.com/blog/sysdig-and-falco-now-powered-by-ebpf) of this series, we took a high level look at the generic architecture of eBPF and its support in sysdig. Our goal was to provide you with an understanding how the different parts work together. Now, we’ll dig into the verification process and the eBPF virtual machine — both key enablers of the runtime safety features eBPF provides.

Our eBPF exercises below are entirely driven by examples. We’ll try to incrementally build some code to intercept system call data. As we run into unexpected errors, we’ll stop and analyze what’s going on under the hood.

There is a lot to know about eBPF. We will barely scratch the surface. Writing complex eBPF programs requires much more context than what we’ll shared in this blog. But, you can certainly consider this a “primer.” Also, keep in mind that writing eBPF programs in the Python/Lua interface offered by [bcc](https://github.com/iovisor/bcc/blob/master/docs/tutorial_bcc_python_developer.md), or by using higher level languages such as the one offered by [bpftrace](https://github.com/iovisor/bpftrace), will definitely make the process more user friendly. The goal of this post is to go at the core of the problem without abstracting away too many steps.

## System call decoding with eBPF

### First experiment

In this example, we’ll decode a very simple and widely used system call: [openat](http://man7.org/linux/man-pages/man2/open.2.html). This system call is used to open a file in Linux by passing its path name. The system call either returns a proper file descriptor or a negative number in case of error. This is its prototype:

```
int openat(int dirfd, const char *pathname, int flags, mode_t mode);
```

Our exercise consists of decoding the arguments in input to the system call, the most interesting one being the path name itself. While this seems a pretty easy task, we will see how writing the code to do the job thoroughly in eBPF hides a few intricacies.

The code we will write can be fundamentally used in any eBPF project with minor adaptations. Feel free to do your experiments with either bcc, a custom eBPF loader (the kernel ships a few example ones, such as [bpf_load.c](https://github.com/torvalds/linux/blob/v4.18/samples/bpf/bpf_load.c), or [sysdig](https://github.com/draios/sysdig) itself. If you use sysdig, all the code we’re going to write next can be simply put inside the [probe.c file](https://github.com/draios/sysdig/blob/0.23.1/driver/bpf/probe.c) while commenting out the current content so it won’t interfere with the typical sysdig eBPF programs. The compilation can be done by following the [instructions on our GitHub page](https://github.com/draios/sysdig/wiki/eBPF).

Let’s start with the most simple example:

```
__attribute__((section("raw_tracepoint/sys_enter"), used))
void bpf_openat_parser()
{
}
```

Here, the empty function bpf_openat_parser is what we want to be executed whenever we enter the openat system call. What about the attribute above it? That one is a compiler attribute we use to tell LLVM to put the object code for the bpf_openat_parser function into a separate [Executable and Linkable Format](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format) (ELF) section, named *raw_tracepoint/sys_enter* in the final object file. As we will see shortly, this is part of an implicit protocol between the developer who wrote the bpf_openat_parser function (us), and the eBPF loader inside the sysdig process that needs to know to the system event to which it should attach such eBPF program.

After we compile the program (in this case I’m using sysdig so a standard “make” will do), Clang and LLVM will process the source code and emit a single object file containing the eBPF program. In the sysdig case, this will be in the driver/bpf/probe.o location. We know it’s an ELF file, so we can inspect its sections:

```
$ llvm-readelf -sections driver/bpf/probe.o
There are 203 section headers, starting at offset 0x2d8890:

Section Headers:
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
...
  [179] raw_tracepoint/sys_enter_openat PROGBITS 0000000000000000 1074b8 000008 00  AX  0   0  8
...
```

As expected, we can find an ELF section named after the string we put in the source code. We can inspect its content as well:

```
$ llvm-objdump -no-show-raw-insn -section=raw_tracepoint/sys_enter -S driver/bpf/probe.o
Disassembly of section raw_tracepoint/sys_enter:
bpf_openat_parser:
       0:       exit
```

Here we have our very first encounter with eBPF bytecode. The ELF section contains the eBPF bytecode for the bpf_openat_parser function. Since the function is empty, the program consists of one single instruction — *exit*.This terminates the program and instructs the eBPF virtual machine to return the control to the normal kernel execution flow.

[The art of writing #eBPF programs: a primer by @sysdig.**Click to tweet**](https://sysdig.com/blog/the-art-of-writing-ebpf-programs-a-primer/#)



### The eBPF loader

How do we run this program? This is the responsibility of the eBPF loader, a user space component, which in sysdig is embedded inside the [scap library](https://github.com/draios/sysdig/blob/0.23.1/userspace/libscap/scap_bpf.c#L1195). The ELF file containing the eBPF program is passed as input to the eBPF loader, which performs the following operations:

1. Parse the ELF sections, and pick the ones that start with a given keyword. For example, a keyword used in sysdig is *raw_tracepoint*. This indicates to the loader that the ELF section contains an eBPF program that will need to be attached to a raw tracepoint kernel event. Raw tracepoints, when available, allow by far the best performance, at the cost of flexibility, as opposed to other kernel event types an eBPF program can attach to (kprobes, uprobes, tracepoints, …).
2. The other part of the ELF section name will get interpreted as the event name. In our case, the event name is *sys_enter*. This identifies a [raw tracepoint ](https://github.com/torvalds/linux/blob/v4.18/arch/x86/entry/common.c#L127)that gets called every time a new system call invocation is done. This is essentially a string that the kernel directly recognizes as a system event, and can be used to uniquely identify it. The full list of supported tracepoints can be easily explored by running *perf list* on the host.
3. Once the kernel event has been validated, the eBPF program is loaded into the kernel. This is done via the [bpf system call](http://man7.org/linux/man-pages/man2/bpf.2.html). During this step the kernel verifies that the program is safe to run, and will optionally translate it into machine code via the JIT process. The bpf system call will either return a file descriptor identifying the loaded eBPF program, or an error.
4. Finally, using the bpf system call, or the perf_event_open system call depending on [the kernel event type](http://man7.org/linux/man-pages/man2/perf_event_open.2.html), the eBPF loader will instruct the kernel to attach the eBPF program just loaded to the event identified at the previous step.

The whole thing is a bit tricky, but it’s mostly just boilerplate. After this, our program will be called every single time the event triggers in the kernel.

### The eBPF verifier

Now that we know what happens, we can proceed to run sysdig and see if our eBPF program gets correctly loaded and attached:

```bash
$ sudo sysdig
0: (95) exit
R0 !read_ok
bpf_load_program() err=13 event=sys_enter
```

*That didn’t work*. This is our first encounter with the eBPF verifier. The verifier tells us that the program couldn’t be loaded (step 3 above), and the reason is *R0 !read_ok*. What does that mean? R0 is one of the eleven eBPF virtual machine registers (R0-R10). The verifier is telling us that it cannot read its value. What happens here is that we violated a requirement of an eBPF program. Each eBPF program must always return an integer value at the end of its execution, and this return value must be stored in R0. The return value is needed because most of the time the kernel will actually use the return value of the program and act upon its value. For example, if an eBPF program is used to filter network packets, the return value will be interpreted as a boolean to drop/accept the packet.

The verifier here complains because it detected that R0 was never written during the execution of the program. It contains “garbage.” It detects this by effectively simulating every single execution branch that the eBPF program could possibly take at runtime. It keeps track of the value and type of the registers for each branch, making sure they are properly initialized if they are ever read.

We can simply fix this first mistake by changing the prototype of our function and returning an integer:

```c
__attribute__((section("raw_tracepoint/sys_enter"), used))
int bpf_openat_parser()
{
    return 0;
}

$ llvm-objdump -no-show-raw-insn -section=raw_tracepoint/sys_enter -S driver/bpf/probe.o 
Disassembly of section raw_tracepoint/sys_enter:
bpf_openat_parser:
       0:       r0 = 0
       1:       exit
```

We can see how this time the eBPF program becomes two instructions long. The first one indeed initializes the return value register to 0 before exiting. If we run sysdig this time, it won’t fail.

### Memory accesses in eBPF

Since the eBPF program is completely empty, this is not particularly useful. We need to actually access the arguments passed to the system call. In order to do this, we have to introduce the concept of “context.” Each eBPF program, upon start, gets passed a pointer to a *context* in the R1 register. The context is basically a structure that assumes a different meaning depending on the specific event type to which we attach the eBPF program — and is directly handled by the eBPF virtual machine. For raw tracepoints, the kind we are using in this example, the context is a pointer to a struct of this type:

```c
struct bpf_raw_tracepoint_args {
    __u64 args[0];
};
```

This structure has a single member, *args*, which is an array of undeclared size that contains all the arguments passed to the tracepoint when it’s statically invoked in the kernel, casted to 8 bytes unsigned integers. So what’s the value of args for our system call tracepoint? We can go in the kernel tree, and grep for the definition of the sys_enter tracepoint, and we’ll find [this](https://github.com/torvalds/linux/blob/v4.18/include/trace/events/syscalls.h#L20):

```c
TRACE_EVENT_FN(sys_enter,
    TP_PROTO(struct pt_regs *regs, long id),
…
```

This tells us that every time our eBPF program is invoked via the sys_enter tracepoint, the first two arguments of the context will contain a pointer to a saved copy of the CPU registers at the time of the invocation (pt_regs) as well as the id of the system call that is being invoked.

How do we get the system call arguments — in particular the path name — from these two tracepoint arguments? Luckily, the System V ABI mandates the protocol for exchanging arguments during a system call invocation between user and kernel, and the exchange happens via CPU registers. In particular, the convention is:

- User-level applications use as integer registers for passing the sequence %rdi, %rsi, %rdx, %rcx, %r8 and %r9.
- The kernel interface uses %rdi, %rsi, %rdx, %r10, %r8 and %r9.

This means that for our *openat* system call we will find the path name argument in the rsi register (since it’s the second argument of the system call) under the form of pointer to string. rsi is naturally one of the values that is present in the pt_regs structure passed to our BPF program, as we can see from the [kernel sources](https://github.com/torvalds/linux/blob/v4.18/arch/x86/include/asm/ptrace.h#L73)):

```c
struct pt_regs {
...
    unsigned long si;
...
```

Now we have all the material to write a more substantial BPF program, such as this:

```c
__attribute__((section("raw_tracepoint/sys_enter"), used))
int bpf_openat_parser(struct bpf_raw_tracepoint_args *ctx)
{
    unsigned long syscall_id = ctx->args[1];
    volatile struct pt_regs *regs;
    volatile const char *pathname;

    if (syscall_id != __NR_openat)
        return 0;

    regs = (struct pt_regs *)ctx->args[0];
    pathname = (const char *)regs->si;

    return 0;
}
```

Notice how we get the invoked system call id from the tracepoint argument, and we compare it against the openat system call id, which is fixed and part of the kernel ABI. Then, we access the register structure from the first tracepoint argument, and we use its value to dereference the value of the path name argument held in the si register, which we cast to a proper pointer to string. The volatile keyword is just there to make sure the compiler doesn’t remove those assignments during the generation of optimized code.

Let’s see how this looks from an eBPF bytecode point of view:

```bash
$ llvm-objdump-7 -no-show-raw-insn -section=raw_tracepoint/sys_enter -S driver/bpf/probe.o 
Disassembly of section raw_tracepoint/sys_enter:
bpf_openat_parser:
       0:       r2 = *(u64 *)(r1 + 8)
       1:       if r2 != 257 goto +2 <lbb81_2>
       2:       r1 = *(u64 *)(r1 + 0)
       3:       r1 = *(u64 *)(r1 + 104)

LBB81_2:
       4:       r0 = 0
       5:       exit
</lbb81_2>
```

Lots of new stuff here to analyze. In particular:

- **Instruction 0:** We are dereferencing the system call id, which again is the second member of the tracepoint argument structure. Since the arguments array address is stored in R1 (the context), the second member is obtained by accessing offset 8 from the context.
- **Instruction 1:** We compare the system call id to the openat id (257), and if they don’t match we jump forward and exit the program.
- **Instruction 2:** This is the same as instruction 0, except that here we deference the first member of the array at offset 0 from the context, which contains the pt_regs structure pointer.
- **Instruction 3:** We dereference the si register value from the pt_regs structure we obtained at the previous instruction, which happens to be at offset 104. So, R1 now finally contains the pointer to the path name string.

What happens if we try to run this program? This is what we get:

```bash
$ sudo sysdig
3: (79) r1 = *(u64 *)(r1 +104)
R1 invalid mem access 'inv'
bpf_load_program() err=13 event=sys_enter
```

That didn’t work. The verifier didn’t seem to like instruction 3.

Let’s reflect for a second on what we were trying to do. In instruction 3, we were accessing the pt_regs structure, by dereferencing its pointer. However, is that really safe to do? What would happen if pt_regs was NULL or pointing to a bogus area (e.g. 0x42424242)? If that was the case, when the eBPF virtual machine runs such code, or worse when the translated JIT code tries to do the memory access using native machine instructions, we would essentially get an invalid memory access while in kernel space, which could very likely lead to a kernel crash. So, the eBPF verifier is stopping us from executing this potentially unsafe action. The solution here will be to properly dereference potentially unsafe memory using a checked access, as we’ll see shortly.

*As a trivia question*, why didn’t the verifier complain about instruction 0 or instruction 2? Those were also dereferencing memory, just like instruction 3. The difference is that those instructions were dereferencing members of the context structure, which the eBPF verifier knows to always be set to a proper bpf_raw_tracepoint structure. That could never generate a crash unless the offset used in the access runs past the size of the structure itself, which the verifier checks as well. In other words, the eBPF verifier keeps track of what memory each register points at for each branch that could possibly be executed, and it denies accesses that could potentially be unsafe. Understanding this is the key to writing eBPF programs without headaches.

### eBPF helpers

The solution to the previous problem is to do a checked memory access via an eBPF helper. On top of the standard virtual execution environment, eBPF also offers the possibility to call a fixed set of kernel functions, called eBPF helpers. eBPF helpers execute some operation on behalf of the eBPF program, natively. These functions are implemented inside the kernel in C, and are thus hardcoded and part of the kernel ABI. One of these helpers is [bpf_probe_read](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#1-bpf_probe_read). It can be thought of as a safe version of a *memcpy*. You can pass to it an arbitrary memory pointer and it will try to read such memory without ever crashing. If the memory is unsafe to read, it will simply and safely return an error. The details of its implementation are pretty interesting and related to how the page fault handler works in Linux.

This means that we can change our BPF program to something like this:

```c
__attribute__((section("raw_tracepoint/sys_enter"), used))
int bpf_openat_parser(struct bpf_raw_tracepoint_args *ctx)
{
    unsigned long syscall_id = ctx->args[1];
    struct pt_regs *regs;
    const char *pathname;

    if (syscall_id != __NR_openat)
        return 0;

    regs = (struct pt_regs *)ctx->args[0];
    bpf_probe_read(&pathname, sizeof(pathname), &regs->si);

    return 0;
}
```

As you can see, the syntax of bpf_probe_read is very similar to a traditional memcpy. This time the memory access works since we are dereferencing the unsafe memory using the helper.

Let’s take a look at the bytecode:

```bash
$ llvm-objdump-7 -no-show-raw-insn -section=raw_tracepoint/sys_enter -S driver/bpf/probe.o 
Disassembly of section raw_tracepoint/sys_enter:
bpf_openat_parser:
       0:       r2 = *(u64 *)(r1 + 8)
       1:       if r2 != 257 goto +6 <lbb81_2>
       2:       r3 = *(u64 *)(r1 + 0)
       3:       r3 += 104
       4:       r1 = r10
       5:       r1 += -8
       6:       r2 = 8
       7:       call 4

LBB81_2:
       8:       r0 = 0
       9:       exit
</lbb81_2>
```

This one is similar to the previous one except for instructions in the 2-7 range. These instructions are involved with calling the helper, which we didn’t have before. The eBPF calling convention mandates that arguments to a helper function must be passed using the registers R1-R5, sequentially. We can analyze the instructions as follows:

- **Instructions 2-3:** R3 is populated with the address of regs->si, and it indicates the address from where data will be copied, just like a memcpy (third parameter in the source code).
- **Instructions 4-5:** here we are setting R1, which is set to the address of the local variable “pathname,” where the data will be copied to — again just like a memcpy (first parameter in the source code). Here the compiler is using R10 for the first time. R10 is a special register and it’s initialized by the virtual machine automatically to the “frame pointer” of the eBPF program. It points to the top of the stack that the eBPF program can use to store local variables. The stack is limited to 512 bytes in size. Here we are setting R1 to R10 – 8, meaning that we are reserving space for an 8 bytes local stack variable that will hold the content of regs->si.
- **Instruction 6:** R2 is simply set to 8, which corresponds to the size of the data we will copy (second parameter in the source code).
- **Instruction 7:** The helper is called. Each eBPF helper is identified by a unique integer that is set in stone in the kernel ABI via [enum](https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h#L2081)). We can see that the bpf_probe_read helper has an id of 4.

### Strings and eBPF

Now that we have the pathname string pointer, let’s do something with it. Usually this involves sending its value to userspace. In order to do that, the first thing to do is to copy the string somewhere so we can save it in a temporary buffer. The eBPF program stack seems a perfect place to host this buffer. Since reading the string means essentially dereferencing memory that could be unsafe, just like before, we need to use another helper.

In this case, we can use [bpf_probe_read_str](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#2-bpf_probe_read_str), which is similar to bpf_probe_read, except that it’s string aware. This means it will stop at the end of the string, which is more efficient (and it will also return the length of the copied string). This is an eBPF helper that was introduced in the kernel by Sysdig as part of [our porting work](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=a5e8c07059d0f0b31737408711d44794928ac218):

```c
__attribute__((section("raw_tracepoint/sys_enter"), used))
int bpf_openat_parser(struct bpf_raw_tracepoint_args *ctx)
{
    unsigned long syscall_id = ctx->args[1];
    struct pt_regs *regs;
    const char *pathname;
    char buf[64];
    int res;

    if (syscall_id != __NR_openat)
        return 0;

    regs = (struct pt_regs *)ctx->args[0];
    bpf_probe_read(&pathname, sizeof(pathname), &regs->si);
    res = bpf_probe_read_str(buf, sizeof(buf), pathname);

    return 0;
}
```

The usage of bpf_probe_>read_str is pretty straightforward. We reserve a local variable of 64 bytes, and we copy the path name into it. Let’s take a look at the bytecode:

```bash
$ llvm-objdump-7 -no-show-raw-insn -section=raw_tracepoint/sys_enter -S driver/bpf/probe.o 
Disassembly of section raw_tracepoint/sys_enter:
bpf_openat_parser:
       0:       r2 = *(u64 *)(r1 + 8)
       1:       if r2 != 257 goto +11 <lbb81_2>
       2:       r3 = *(u64 *)(r1 + 0)
       3:       r3 += 104
       4:       r1 = r10
       5:       r1 += -8
       6:       r2 = 8
       7:       call 4
       8:       r3 = *(u64 *)(r10 - 8)
       9:       r1 = r10
      10:       r1 += -80
      11:       r2 = 64
      12:       call 45

LBB81_2:
      13:       r0 = 0
      14:       exit
</lbb81_2>
```

This also looks pretty straightforward. The additional eBPF instructions are in the range 9-12, and they simply set the proper arguments to the bpf_probe_read_str helper. In this case, the compiler decides to put the *buf* variable on the stack starting at the address R10 – 80, so the next 64 bytes are going to be filled with the string content.

If we try to run this example, it works. By using other helpers, such as [bpf_trace_printk](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#1-bpf_trace_printk) or [bpf_perf_event_output](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#3-perf_submit), we could either print the path name we just copied to the kernel log, or push it to a high performance ring buffer shared with user space, respectively (what sysdig does).

However, there is a significant flaw in this program. 64 bytes might not be enough to properly hold the full path name. Dealing with truncated data is something not ideal when doing system call instrumentation for system call auditing purposes (like Falco does). It would be much better to properly size the temporary buffer to make sure it can hold a longer path. We can use the constant *PATH_MAX*, which is expanded to 4096 and should hold the maximum supported path length in Linux. If we try to change the size of *buf* to *PATH_MAX* however, we get this error at compile time:

```bash
error: <unknown>:0:0: in function bpf_openat_parser i32 (%struct.bpf_raw_tracepoint_args*): Looks like the BPF stack limit of 512 bytes is exceeded. Please move large on stack variables into BPF per-cpu array map.
</unknown>
```

Remember that the stack the eBPF virtual environment gives us is just 512 bytes. Reserving a 4096 bytes variable on it would certainly cause a stack violation. And, we would most definitely overwrite other kernel memory if the program were to run — so it’s an unsafe operation. We are lucky that the compiler caught that so early. Even if the compiler didn’t catch it, the eBPF verifier would have detected such condition and would have prevented the loading of the program.

### eBPF maps

How do we solve this? We need to store the temporary buffer into a different location, off the stack. The eBPF virtual environment doesn’t provide us the ability to allocate external memory or use global variables like we would do in a normal C user/kernel program. We do however have the possibility to use eBPF maps. eBPF maps are key/value data structures that are accessible from the eBPF program via an additional set of helpers, and are persistent across invocations. The kernel offers different types of maps (hash tables, arrays, and more, [described here](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#maps)). What we can use here is a per-cpu array map. This way, every invocation of the eBPF program will get its own slot of the map that can be used for the entire duration of the program. Since eBPF programs are never preempted during their execution, storing those in a per-cpu map is safe and can never lead to race conditions or corrupted data. The adjusted program looks like this:

```c
__attribute__((section("maps"), used))
struct bpf_map_def tmp_storage_map = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = PATH_MAX,
    .max_entries = 1,
};

__attribute__((section("raw_tracepoint/sys_enter"), used))
int bpf_openat_parser(struct bpf_raw_tracepoint_args *ctx)
{
    unsigned long syscall_id = ctx->args[1];
    struct pt_regs *regs;
    const char *pathname;
    char *map_value;
    u32 map_id;
    int res;

    if (syscall_id != __NR_openat)
        return 0;

    regs = (struct pt_regs *)ctx->args[0];

    res = bpf_probe_read(&pathname, sizeof(pathname), &regs->si);

    map_id = 0;
    map_value = bpf_map_lookup_elem(&tmp_storage_map, &map_id);
    if (!map_value)
        return 0;

    res = bpf_probe_read_str(map_value, PATH_MAX, pathname);

    return 0;
}
```

This looks a bit more complicated, so let’s analyze it. The first section is the map definition that goes in a separate ELF section so that the eBPF loader can properly detect it and set it up (this also happens with the bpf system call). We can see the map is declared of type per-cpu array with one single entry (so that each cpu will get its own single slot), and the size of the map is PATH_MAX, enough to hopefully hold the full path name coming from the system call. We could complicate this by adding other fields, for example, space for other system call arguments or the pid of the process (this is what sysdig does).

In the bpf_openat_parser function, we can use the [bpf_map_lookup_elem](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#12-maplookup) helper to get at runtime the map slot allocated for the specific cpu where the eBPF program is running at that time. We also return in case it’s NULL, so the eBPF verifier won’t complain.

Finally, we can simply call *bpf_probe_read_str*. But instead of passing as destination pointer the stack buffer like before, we pass it the pointer to the map storage area. We can directly point a BPF helper argument to a map area. This functionality was [another improvement](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=5722569bb9c3bd922c4f10b5b2912fe88c255312) added by Sysdig to the kernel.

### Variable memory accesses in eBPF

This program works fine and gets accepted by the verifier. We are just missing a tricky bit that’s good to know when working with eBPF. The documentation states that bpf_probe_read_str correctly NULL-terminates the copied string even if the destination buffer is smaller than the original string itself, and that it will return the final length of the string copied, including the NULL.

For the sake of this example, let’s forget for one second about the automatic NULL termination, and let’s manually terminate the string, to be extra safe. We could do this by changing the bpf_probe_read_str invocation as follows:

```bash
    res = bpf_probe_read_str(map_value, PATH_MAX, pathname);
    if (res > 0)
        map_value[res - 1] = 0;
```

Pretty reasonable C code. We know for sure that the return value of the helper, when positive, will be less than or equal to PATH_MAX, so the above code should be safe.

However, the verifier doesn’t like it:

```bash
$ sudo sysdig
...
20: (85) call bpf_probe_read_str#45
 R1_w=map_value(id=0,off=0,ks=4,vs=4096,imm=0) R2_w=inv4096 R3_w=inv(id=0) R6=map_value(id=0,off=0,ks=4,vs=4096,imm=0) R10=fp0,call_-1
21: (67) r0 <<= 32
22: (c7) r0 s>>= 32
23: (b7) r1 = 1
24: (6d) if r1 s> r0 goto pc+3
 R0=inv(id=0,umin_value=1,umax_value=9223372036854775807,var_off=(0x0; 0x7fffffffffffffff)) R1=inv1 R6=map_value(id=0,off=0,ks=4,vs=4096,imm=0) R10=fp0,call_-1
25: (0f) r6 += r0
26: (b7) r1 = 0
27: (73) *(u8 *)(r6 -1) = r1
 R0=inv(id=0,umin_value=1,umax_value=9223372036854775807,var_off=(0x0; 0x7fffffffffffffff)) R1_w=inv0 R6_w=map_value(id=0,off=0,ks=4,vs=4096,umin_value=1,umax_value=9223372036854775807,var_off=(0x0; 0x7fffffffffffffff)) R10=fp0,call_-1
R6 unbounded memory access, make sure to bounds check any array access into a map
bpf_load_program() err=13 event=sys_enter
```

This looks like a lot of output to digest. It’s actually pretty easy to go through it, especially as the verifier prints a summary of the content of the registers after each instruction is simulated during the verification process:

- **Instruction 20:** the bpf*probe*read*str is invoked. After the call, in R0 we have the “res” variable. The verifier is also telling us that the map value containing the string is stored in R1 and R6 (look for the keywords “R6=map*value” and “vs=4096”, indicating that the slot is PATH_MAX in size).
- **Instruction 24: **if “res” is zero or less, we jump past the string termination code, since it wouldn’t make sense otherwise. Notice that R0, which contains the “res” variable, is identified by the verifier of type scalar value (“inv”), with a proper lower bound of 1 since we passed the branch check (“umin*value=1”), but without a known upper bound (“umax*value=9223372036854775807”). In other words, the verifier doesn’t assume anything about the return value of the bpf*probe*read_str helper, unless we do explicit checks.
- **Instruction 25:** R0, containing the “res” variable, is used as an offset into R6, which contains the “map*value” variable. This instruction sets R6 to the C equivalent &map*value[res].
- **Instruction 27:** We now take the value we computed at instruction 25, add an offset of -1, and write 0 to the memory pointed by that address. This is the explicit NULL termination we wrote in the code at position &map_value[res-1].

As it’s now hopefully more clear, instruction 27 fails because the verifier doesn’t know the upper bound of the “res” variable, because it was only checked against the lower bound of 1 in the if condition. By doing the NULL termination using “res” as an offset we are potentially doing an unsafe memory access. Except this time we know for a fact we aren’t because “res” is never larger than PATH_MAX. The verifier unfortunately doesn’t know this.

The solution? Help the verifier understand that the full possible range of the variable is within PATH_MAX. We do this by adding gratuitous checks that in traditional C code wouldn’t be needed, such as:

```c
    res = bpf_probe_read_str(map_value, PATH_MAX, pathname);
    if (res > 0 && res <= PATH_MAX) 
        map_value[res - 1] = 0;
```

If you try this code though, you’ll see that it doesn’t work and gets refused once again by the verifier with a similar error. This is due to the way the compiler likes to rearrange that branch in a way that the verifier doesn’t understand yet. *Try it at home to verify this behavior, that’s why we call it “the art of writing eBPF programs” as opposed to “the science” :-)*. A solution that works better is to leverage the fact that PATH_MAX is a power of 2 (4096) and move the upper bound check as close as possible to the point where the variable is used as offset:

```c
    res = bpf_probe_read_str(map_value, PATH_MAX, pathname);
    if (res > 0)
        map_value[(res - 1) & (PATH_MAX - 1)] = 0;
```

This will work, and is semantically the same as the former more explicit check, considering that we know the “res” value to be positive and not bigger than PATH_MAX (guaranteed by the helper). In other words, we’re just helping the verifier verify the code. The bytecode looks like this:

```c
25: (07) r0 += 4095
26: (57) r0 &= 4095
27: (bf) r1 = r6
28: (0f) r1 += r0
29: (b7) r2 = 0
30: (73) *(u8 *)(r1 +0) = r2
 R0_w=inv(id=0,umax_value=4095,var_off=(0x0; 0xfff))
 R1_w=map_value(id=0,off=0,ks=4,vs=4096,umax_value=4095,var_off=(0x0; 0xfff)) R2_w=inv0 
 R6=map_value(id=0,off=0,ks=4,vs=4096,imm=0) R10=fp0,call_-1
```

We can see how the R0 register, after the subtraction by 1 and the bitwise AND with 4095, has now a correctly tracked upper bound of 4095 (“umax_value=4095), so it can be used as an offset to the map value pointer, safely.

This is [another improvement](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=06c1c049721a995dee2829ad13b24aaf5d7c5cce) to the kernel that was contributed by Sysdig, making the process of dealing with data whose size is not strictly known at verification time much easier, which is essential for system call instrumentation.

At this point, let’s end this journey by printing into the kernel trace log the full path name that we extracted:

```c
    char fmt[] = "path_name:%sn";
    bpf_trace_printk(fmt, sizeof(fmt), map_value);
```

If we run the code and then observe the kernel trace log (/sys/kernel/debug/tracing/trace_pipe), we’ll see:

```bash
htop-1960  [001] .... 20839.191270: 0: path_name:/proc/124286/task
htop-1960  [001] .... 20839.191283: 0: path_name:/proc/124286/statm
htop-1960  [001] .... 20839.191292: 0: path_name:/proc/124286/stat
htop-1960  [001] .... 20839.191308: 0: path_name:/proc/124290/task
htop-1960  [001] .... 20839.191321: 0: path_name:/proc/124290/statm
htop-1960  [001] .... 20839.191331: 0: path_name:/proc/124290/stat
htop-1960  [001] .... 20839.191443: 0: path_name:/proc/loadavg
htop-1960  [001] .... 20839.191472: 0: path_name:/proc/uptime
tmux: server-936   [003] .... 20839.964390: 0: path_name:/proc/124286/cmdline
```

Mission accomplished!

## Conclusions

This concludes the second part of this eBPF series. We’ve taken a direct look at how the core technology works under the hood, and how it can be programmed.

As said earlier, keep in mind that we haven’t covered several other key aspects of writing eBPF programs, such as the inability to do loops and all the other program types that one can write in eBPF besides the tracing use case. Also, while this content is static, eBPF is certainly not. The verifier keeps getting smarter and smarter with [every new kernel release](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#main-features), making the life of eBPF program developers easier. So, this content might certainly become obsolete at some point in the future. If you want to write eBPF programs supporting a wide variety of kernel versions that a third party user might run, you’ll still have to deal with these quirks in order to be as backwards-compatible as possible.

If you want to see a vast amount of eBPF code in action, feel free to take a look at our [sysdig repository](https://github.com/draios/sysdig/tree/0.23.1/driver/bpf) and stay tuned for the additional eBPF content from us in the future.

