#include <linux/init.h>
#include <linux/module.h>

bool debug_on = 0;
module_param(debug_on, bool, S_IRUSR);

static int __init hello_init(void)
{
    if (debug_on)
        printk("[ DEBUG ] debug info output\n");
    printk("Hello World Module Init\n");
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

