#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/pid.h>
#include <linux/sched.h>

pid_t  pid = 0;
module_param(pid, int, S_IRUSR);

static int __init pid_init(void)
{
    struct pid *spid;
    struct task_struct *task;

    if (pid < 0 )
    {
        printk("[ DEBUG ] pid < 0, %d\n", pid);
        return 0;
    }


    spid = find_get_pid(pid);
    if (!spid)
    {
        printk("[ DEBUG ] find struct pid for pid %d failed\n", pid);
        return 0;
    }

    task = get_pid_task(spid, PIDTYPE_PID);
    if (!task)
    {
	 printk("[ DEBUG ] find task_struct  for pid %d failed\n", pid);
         return 0;
    }
    
    printk("[ DEBUG ] %s %d\n", task->comm, task->pid);

    return 0;
}

module_init(pid_init);


static void __exit pid_exit(void)
{
    printk("PID Module Exit\n");
}

module_exit(pid_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("dwh0403");
MODULE_DESCRIPTION("print task_struct for pid");
MODULE_ALIAS("pid_module");
