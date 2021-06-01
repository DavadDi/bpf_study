#include <linux/module.h>         // Needed by all modules
#include <linux/kernel.h>         // KERN_INFO
#include <linux/sched/signal.h>   // for_each_process, pr_info  old in: #include <linux/sched.h> 

#include <linux/fdtable.h>
#include <linux/fs_struct.h>

void procs_info_print(void)
{
        struct task_struct* task_list;
        size_t process_counter = 0;
        for_each_process(task_list) {
                pr_info("== %s [%d] state:%lx prio: %d static_prio %d file_count: %d \n", 
			task_list->comm, task_list->pid, 
			task_list->state, task_list->prio,task_list->static_prio,
			atomic_read((&(task_list->files)->count)));
                
		++process_counter;
        }
        printk(KERN_INFO "== Number of process: %zu\n", process_counter);
}

int init_module(void)
{
        printk(KERN_INFO "[ INIT ==\n");
        procs_info_print();
        return 0;
}

void cleanup_module(void)
{
        printk(KERN_INFO "== CLEANUP ]\n");
}

MODULE_LICENSE("GPL");
