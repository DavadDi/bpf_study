#include <linux/init.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

static int __init hello_init(void)
{
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    int i = 0;
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);

    char *func_addr = (char *)kallsyms_lookup_name("__do_sys_fork");

    for (i = 0; i < 5; i++)
    {
	pr_info("0x%02x ", (u8)func_addr[i]);
    }

    pr_info("fun addr 0x%lx\n", func_addr);
    return 0;
}
module_init(hello_init);


static void __exit hello_exit(void)
{
    printk("Hello World Module Exit\n");
}
module_exit(hello_exit);


MODULE_LICENSE("GPL");
MODULE_AUTHOR("dwh0403");
MODULE_DESCRIPTION("hello world module");
MODULE_ALIAS("hello_module");

