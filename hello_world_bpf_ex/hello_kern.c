#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_hello(struct pt_regs *ctx)
{
    char fmt[] = "Hello %s !";
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_trace_printk(fmt, sizeof(fmt), comm);

    return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
