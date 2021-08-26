#include<linux/module.h>
#include<linux/init.h>
#include<linux/proc_fs.h>
#include<linux/sched.h>
#include<linux/uaccess.h>
#include<linux/fs.h>
#include<linux/seq_file.h>
#include<linux/slab.h>

// from https://gist.githubusercontent.com/BrotherJing/c9c5ffdc9954d998d1336711fa3a6480/raw/52c549beca2631b857580c2860f488b26344373a/helloproc.c

static char *str = NULL;

static int my_proc_show(struct seq_file *m,void *v){
    seq_printf(m,"%s\n",str);
    return 0;
}

static ssize_t my_proc_write(struct file* file,const char __user *buffer,size_t count,loff_t *f_pos){
    char *tmp = kzalloc((count+1),GFP_KERNEL);
    if(!tmp)return -ENOMEM;
    if(copy_from_user(tmp,buffer,count)){
        kfree(tmp);
        return EFAULT;
    }
    kfree(str);
    str=tmp;
    return count;
}

static int my_proc_open(struct inode *inode,struct file *file){
    return single_open(file,my_proc_show,NULL);
}

static struct file_operations my_fops={
    .owner = THIS_MODULE,
    .open = my_proc_open,
    .release = single_release,
    .read = seq_read,
    .llseek = seq_lseek,
    .write = my_proc_write
};

static int __init hello_init(void){
    struct proc_dir_entry *entry;
    entry = proc_create("helloproc",0777,NULL,&my_fops);
    if(!entry){
        return -1;
    }else{
        printk(KERN_INFO "create proc file successfully\n");
    }
    return 0;
}

static void __exit hello_exit(void){
    remove_proc_entry("helloproc",NULL);
    printk(KERN_INFO "Goodbye world!\n");
}

module_init(hello_init);
module_exit(hello_exit);
MODULE_LICENSE("GPL");
