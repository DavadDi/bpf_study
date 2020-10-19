# KProbe 源码实现分析

[TOC]

本文源码分析基于 Linux v5.8。

## KProbes 结构

include/linux/kprobes.h

```c
 60 struct kprobe {
 61         struct hlist_node hlist;
 62
 63         /* list of kprobes for multi-handler support */
 64         struct list_head list;
 65
 66         /*count the number of times this probe was temporarily disarmed */
 67         unsigned long nmissed;
 68
 69         /* location of the probe point */
 70         kprobe_opcode_t *addr;  // 探测点的地址
 71
 72         /* Allow user to indicate symbol name of the probe point */
 73         const char *symbol_name;  // 探测点的名字
 74
 75         /* Offset into the symbol */
 76         unsigned int offset;     // 探测点的偏移量，一般都为 0，可以设置成不同的值，理论上可以到函数中任何指令地址
 77
 78         /* Called before addr is executed. */
 79         kprobe_pre_handler_t pre_handler;  // pre_handler 函数指针
 80
 81         /* Called after addr is executed, unless... */
 82         kprobe_post_handler_t post_handler; // post_handler 函数指针
 83
 84         /*
 85          * ... called if executing addr causes a fault (eg. page fault).
 86          * Return 1 if it handled fault, otherwise kernel will see it.
 87          */
 88         kprobe_fault_handler_t fault_handler; // // fault_handler 函数指针
 89
 90         /* Saved opcode (which has been replaced with breakpoint) */
 91         kprobe_opcode_t opcode; // 被 breakpoint 替换后的指令地址
 92
 93         /* copy of the original instruction */
 94         struct arch_specific_insn ainsn; // 原始指令集的副本
 95
 96         /*
 97          * Indicates various status flags.
 98          * Protected by kprobe_mutex after this kprobe is registered.
 99          */
100         u32 flags;
101 };
```

## 函数原型和接口

### 函数原型

include/linux/kprobes.h

```c
 52 typedef int (*kprobe_pre_handler_t) (struct kprobe *, struct pt_regs *);
 53 typedef void (*kprobe_post_handler_t) (struct kprobe *, struct pt_regs *,
 54                                        unsigned long flags);
 55 typedef int (*kprobe_fault_handler_t) (struct kprobe *, struct pt_regs *,
 56                                        int trapnr);

 57 typedef int (*kretprobe_handler_t) (struct kretprobe_instance *,
 58                                     struct pt_regs *);
```

### 主要函数

kernel/kprobes.c

```c
// 获取探测地址对应的 kprobe 对象
struct kprobe *get_kprobe(void *addr)
  
// kprobe 初始化
static int __init init_kprobes(void)
  
// 注册和反注册 kprobe
int register_kprobe(struct kprobe *p)
void unregister_kprobe(struct kprobe *p)

// 启用和停用
int disable_kprobe(struct kprobe *kp)
int enable_kprobe(struct kprobe *kp)
```



### 初始化函数 init_kprobes

kernel/kprobes.c

```c
2383 static int __init init_kprobes(void)
2384 {
  					 // 初始化所有相关的列表头部

2395         err = populate_kprobe_blacklist(__start_kprobe_blacklist,
2396                                         __stop_kprobe_blacklist);

  					 // 初始化相关黑名单
2402         if (kretprobe_blacklist_size) {
2403                 /* lookup the function address from its name */
2404                 for (i = 0; kretprobe_blacklist[i].name != NULL; i++) {
2405                         kretprobe_blacklist[i].addr =
2406                                 kprobe_lookup_name(kretprobe_blacklist[i].name, 0);
2407                         if (!kretprobe_blacklist[i].addr)
2408                                 printk("kretprobe: lookup failed: %s\n",
2409                                        kretprobe_blacklist[i].name);
2410                 }
2411         }

						 // 在 x86 架构下 arch_init_kprobes 为空函数
2425         err = arch_init_kprobes();
2426         if (!err) // register_die_notifier 注册 kprobe 异常函数，在 int3/int1 异常情况下调用
2427                 err = register_die_notifier(&kprobe_exceptions_nb);
2428         if (!err)
2429                 err = register_module_notifier(&kprobe_module_nb);
2430
2431         kprobes_initialized = (err == 0);
2432
2433         if (!err)
2434                 init_test_probes();
2435         return err;
2436 }
2437 subsys_initcall(init_kprobes);
```

kprobe_exceptions_nb 结构和对应函数定义如下：

kernel/kprobes.c

```c
1876 static struct notifier_block kprobe_exceptions_nb = {
1877         .notifier_call = kprobe_exceptions_notify,
1878         .priority = 0x7fffffff /* we need to be notified first */
1879 };

1869 int __weak kprobe_exceptions_notify(struct notifier_block *self,
1870                                         unsigned long val, void *data)
1871 {
1872         return NOTIFY_DONE;
1873 }
1874 NOKPROBE_SYMBOL(kprobe_exceptions_notify);
```

### 注册函数 register_kprobe

kernel/kprobes.c

```c
1629 int register_kprobe(struct kprobe *p)
1630 {
1631         int ret;
1632         struct kprobe *old_p;
1633         struct module *probed_mod;
1634         kprobe_opcode_t *addr;
1635
1636         /* Adjust probe address from symbol */
  					 // 从 kprobe 参数中获取到探测点地址，并进行合规性检查
  					 // 底层调用 _kprobe_addr(p->addr, p->symbol_name, p->offset);
1637         addr = kprobe_addr(p); 
1638         if (IS_ERR(addr))
1639                 return PTR_ERR(addr);
  
1640         p->addr = addr; // p->addr 探测点的地址
1641				 /* Check passed kprobe is valid and return kprobe in kprobe_table. */
1642         ret = check_kprobe_rereg(p); // 

1649         INIT_LIST_HEAD(&p->list);
1650
  					 // 地址检查
1651         ret = check_kprobe_address_safe(p, &probed_mod);
1652         if (ret)
1653                 return ret;
1654
1655         mutex_lock(&kprobe_mutex);
1656				 
  					 // 如果当前探测点已经存在 kprobe，则调用 register_aggr_kprobe 进行注册
1657         old_p = get_kprobe(p->addr);
1658         if (old_p) {
1659                 /* Since this may unoptimize old_p, locking text_mutex. */
1660                 ret = register_aggr_kprobe(old_p, p);
1661                 goto out;
1662         }
1663
1664         cpus_read_lock();
1665         /* Prevent text modification */
1666         mutex_lock(&text_mutex);
1667         ret = prepare_kprobe(p);  // 初始化 kprobe 结构
1668         mutex_unlock(&text_mutex);
1669         cpus_read_unlock();

1673         INIT_HLIST_NODE(&p->hlist);   // 初始化 hash list
1674         hlist_add_head_rcu(&p->hlist, // 加入头部
1675                        &kprobe_table[hash_ptr(p->addr, KPROBE_HASH_BITS)]);
1676

1685
1686         /* Try to optimize kprobe */
1687         try_to_optimize_kprobe(p);
1688 out:
1689         mutex_unlock(&kprobe_mutex);
						 
  					 // ...
  
1694         return ret;
1695 }
1696 EXPORT_SYMBOL_GPL(register_kprobe);
```

`register_kprobe` 默认注册后 kprobe 是禁用状态，需要在 enable 以后才会启动替换指令地址。

### 激活探测点 enable_kprobe

kernel/kprobes.c

```c
2136 /* Enable one kprobe */
2137 int enable_kprobe(struct kprobe *kp)
2138 {
2139         int ret = 0;
2140         struct kprobe *p;
2141
2142         mutex_lock(&kprobe_mutex);

						 // 合法性和正确性检查
  
2160         if (!kprobes_all_disarmed && kprobe_disabled(p)) {
2161                 p->flags &= ~KPROBE_FLAG_DISABLED;
2162                 ret = arm_kprobe(p); // 激活探测点，并启动指令替换操作
  									 // ...
2165         }
2166 out:
2167         mutex_unlock(&kprobe_mutex);
2168         return ret;
2169 }
2170 EXPORT_SYMBOL_GPL(enable_kprobe);
```

arm_kprobe 函数定义如下：

```c
1087 /* Arm a kprobe with text_mutex */
1088 static int arm_kprobe(struct kprobe *kp)
1089 {
						 // ...
1093         cpus_read_lock();
1094         mutex_lock(&text_mutex);
1095         __arm_kprobe(kp); // 安装探测点的核心函数
1096         mutex_unlock(&text_mutex);
1097         cpus_read_unlock();
1098
1099         return 0;
1100 }
```

__arm_kprobe 函数定义如下：

```c
 919 /* Put a breakpoint for a probe. Must be called with text_mutex locked */
 920 static void __arm_kprobe(struct kprobe *p)
 921 {
 922         struct kprobe *_p;
 923
 924         /* Check collision with other optimized kprobes */
 925         _p = get_optimized_kprobe((unsigned long)p->addr);
 926         if (unlikely(_p))
 927                 /* Fallback to unoptimized kprobe */
 928                 unoptimize_kprobe(_p, true);
 929
 930         arch_arm_kprobe(p);
 931         optimize_kprobe(p);     /* Try to optimize (add kprobe to a list) */
 932 }
```

函数 `arch_arm_kprobe` 的底层定义与 CPU 架构有关，在 x86 架构下，定义在 arch/x86/kernel/kprobes/core.c 文件中

```c
 504 void arch_arm_kprobe(struct kprobe *p)
 505 {
 506         text_poke(p->addr, ((unsigned char []){INT3_INSN_OPCODE}), 1); // 替换成 0xCC，到此注册和启用工作完成
 507         text_poke_sync();
 508 }
```

INT3_INSN_OPCODE 定如下：

```c
arch/x86/include/asm/text-patching.h
54:#define INT3_INSN_OPCODE	0xCC
```



## KProbes 函数触发

通过上篇 KProbes 原理分析和第一部分注册、启用的函数调用分析，我们得知探测点的地址已经被替换成了 0xCC，当代码执行到此处后会触发中断指令 X86_TRAP_BP（3）。

上篇中的原理部门我们可以看到，X86_TRAP_BP（3） 会触发执行 do_int3， 而 X86_TRAP_DB（1）会触发  handle_debug 函数。

> KProbe 把探测点的指令替换成断点指令 BREAKPOINT，执行到探测点以后，系统会陷入断点异常指令（x86 上的 int3），将程序控制转移至断点处理程序 do_int3()（ arch/x86/kernel/traps.c ）。do_int3() 是通过中断门（ interrupt gate）调用的，因此当控制到达那里时，中断是被禁止的。do_int3() 处理程序通知 KProbes 发生了断点，KProbes检查断点是否由 KProbes 的注册函数设置。如果在探针被击中的地址上没有探针存在，它就简单地返回 0。否则将继续调用注册的 pre_handler 函数，然后把 CPU 设置为单步模式继续执行探测点原有的指令，原有指令执行完成以后又会陷入单步异常 int1，在 int1 中调用 post_handler，并恢复单步模式到正常模式，然后返回继续执行探测点后续的指令。

在 x86 系统的头文件 rch/x86/include/asm/trapnr.h 中定义 X86_TRAP_DB 定义为 1，即 int1；X86_TRAP_BP 被定义为 3， 即 int3。

而在 arch/x86/include/asm/idtentry.h 中则定义了两个中断对应的中断函数，分别为 exc_int3 和 exc_debug。

```c
arch/x86/include/asm/trapnr.h
 8 #define X86_TRAP_DB              1      /* Debug */
10:#define X86_TRAP_BP		 3	/* Breakpoint */

arch/x86/include/asm/idtentry.h
541:DECLARE_IDTENTRY_RAW(X86_TRAP_BP,		exc_int3); // 中断对应的函数
560 DECLARE_IDTENTRY_DEBUG(X86_TRAP_DB,  exc_debug);

arch/x86/include/asm/idtentry.h
126 /**
127  * DEFINE_IDTENTRY_RAW - Emit code for raw IDT entry points
128  * @func:       Function name of the entry point
129  *
130  * @func is called from ASM entry code with interrupts disabled.
131  *
132  * The macro is written so it acts as function definition. Append the
133  * body with a pair of curly brackets.
134  *
135  * Contrary to DEFINE_IDTENTRY() this does not invoke the
136  * idtentry_enter/exit() helpers before and after the body invocation. This
137  * needs to be done in the body itself if applicable. Use if extra work
138  * is required before the enter/exit() helpers are invoked.
139  */
140 #define DEFINE_IDTENTRY_RAW(func)                                       \
141 __visible noinstr void func(struct pt_regs *regs)
```

在文件 idt.c 文件中定义的了两个中断的对应处理函数，int1 和 int3 被定义在 early_idts 结构体中，该结构体在函数 `idt_setup_early_traps` 中进行初始化，此函数 `setup_arch` 调用，最终的函数总调用入口在 `init/main.c` 文件中的  `start_kernel` 函数。

总的调用流程如下： `start_kernel` -> `setup_arch` -> `idt_setup_early_traps` -> `early_idts`。

arch/x86/kernel/idt.c

```c
 60 /*
 61  * Early traps running on the DEFAULT_STACK because the other interrupt
 62  * stacks work only after cpu_init().
 63  */
 64 static const __initconst struct idt_data early_idts[] = {
 65         INTG(X86_TRAP_DB,               asm_exc_debug),
 66         SYSG(X86_TRAP_BP,               asm_exc_int3),
   
224 /**
225  * idt_setup_early_traps - Initialize the idt table with early traps
226  *
227  * On X8664 these traps do not use interrupt stacks as they can't work
228  * before cpu_init() is invoked and sets up TSS. The IST variants are
229  * installed after that.
230  */
231 void __init idt_setup_early_traps(void)
232 {
233         idt_setup_from_table(idt_table, early_idts, ARRAY_SIZE(early_idts),
234                              true);
235         load_idt(&idt_descr);
236 }
```

`setup_arch` 中完成 ``early_idts` 结构的初始化。

```c
 789 void __init setup_arch(char **cmdline_p)
 790 {
 				// ...
 847         idt_setup_early_traps();
 				// ...
 }
```

init/main.c

```c
 830 asmlinkage __visible void __init start_kernel(void)
 831 {
 				// ...
 852         setup_arch(&command_line);
 				// ...
 }
```

### int3 中断函数 do_int3

arch/x86/kernel/traps.c

```c
 630 DEFINE_IDTENTRY_RAW(exc_int3)
 631 {
 632         /*
 633          * poke_int3_handler() is completely self contained code; it does (and
 634          * must) *NOT* call out to anything, lest it hits upon yet another
 635          * INT3.
 636          */
 637         if (poke_int3_handler(regs))
 638                 return;
 639
 640         /*
 641          * idtentry_enter_user() uses static_branch_{,un}likely() and therefore
 642          * can trigger INT3, hence poke_int3_handler() must be done
 643          * before. If the entry came from kernel mode, then use nmi_enter()
 644          * because the INT3 could have been hit in any context including
 645          * NMI.
 646          */
 647         if (user_mode(regs)) {
 648                 idtentry_enter_user(regs);
 649                 instrumentation_begin();
 650                 do_int3_user(regs);
 651                 instrumentation_end();
 652                 idtentry_exit_user(regs);
 653         } else { // 内核模式下的中断调用
 654                 nmi_enter();
 655                 instrumentation_begin();
 656                 trace_hardirqs_off_finish();
 657                 if (!do_int3(regs))    // ------> 最终调用  do_int3
 658                         die("int3", regs, 0);
 659                 if (regs->flags & X86_EFLAGS_IF)
 660                         trace_hardirqs_on_prepare();
 661                 instrumentation_end();
 662                 nmi_exit();
 663         }
 664 }
```

`do_int3` 函数定义如下：

```c
 601 static bool do_int3(struct pt_regs *regs)
 602 {
				// ...
 610
 611 #ifdef CONFIG_KPROBES
 612         if (kprobe_int3_handler(regs)) // --> 在启用 kprobes 情况下调用 kprobe_int3_handler 函数
 613                 return true;
 614 #endif
 615         res = notify_die(DIE_INT3, "int3", regs, 0, X86_TRAP_BP, SIGTRAP);
 616
 617         return res == NOTIFY_STOP;
 618 }
```

kernel/notifier.c

```
503 int notrace notify_die(enum die_val val, const char *str,
504                struct pt_regs *regs, long err, int trap, int sig)
505 {
506         struct die_args args = {
507                 .regs   = regs,
508                 .str    = str,
509                 .err    = err,
510                 .trapnr = trap,
511                 .signr  = sig,
512
513         };
514         RCU_LOCKDEP_WARN(!rcu_is_watching(),
515                            "notify_die called but RCU thinks we're quiescent");
516         return atomic_notifier_call_chain(&die_chain, val, &args);
517 }
518 NOKPROBE_SYMBOL(notify_die);
519
```



arch/x86/kernel/kprobes/core.c

```c
 658 /*
 659  * Interrupts are disabled on entry as trap3 is an interrupt gate and they
 660  * remain disabled throughout this function.
 661  */
 662 int kprobe_int3_handler(struct pt_regs *regs)
 663 {
 664         kprobe_opcode_t *addr;
 665         struct kprobe *p;
 666         struct kprobe_ctlblk *kcb;
						
						 // ...
 
 671         addr = (kprobe_opcode_t *)(regs->ip - sizeof(kprobe_opcode_t));
 672         /*
 673          * We don't want to be preempted for the entire duration of kprobe
 674          * processing. Since int3 and debug trap disables irqs and we clear
 675          * IF while singlestepping, it must be no preemptible.
 676          */
 677
 678         kcb = get_kprobe_ctlblk();
 679         p = get_kprobe(addr);
 680         // 如果该地址上设置了 kprobe 函数，在条件具备的情况下调用 pre_handler
 681         if (p) {
 682                 if (kprobe_running()) {
 683                         if (reenter_kprobe(p, regs, kcb))
 684                                 return 1;
 685                 } else {
 686                         set_current_kprobe(p, regs, kcb);
 687                         kcb->kprobe_status = KPROBE_HIT_ACTIVE;
 688
 689                         /*
 690                          * If we have no pre-handler or it returned 0, we
 691                          * continue with normal processing.  If we have a
 692                          * pre-handler and it returned non-zero, that means
 693                          * user handler setup registers to exit to another
 694                          * instruction, we must skip the single stepping.
 695                          */  
   													 // 如果设置了 pre_handler 并调用 pre_handler 成功，则进入单步模式
 696                         if (!p->pre_handler || !p->pre_handler(p, regs))
 697                                 setup_singlestep(p, regs, kcb, 0); // 调用成功后进入单步执行模式
 698                         else
 699                                 reset_current_kprobe();
 700                         return 1;
 701                 }
 702         } else if (*addr != INT3_INSN_OPCODE) {
 703                 /*
 704                  * The breakpoint instruction was removed right
 705                  * after we hit it.  Another cpu has removed
 706                  * either a probepoint or a debugger breakpoint
 707                  * at this address.  In either case, no further
 708                  * handling of this interrupt is appropriate.
 709                  * Back up over the (now missing) int3 and run
 710                  * the original instruction.
 711                  */
 712                 regs->ip = (unsigned long)addr;
 713                 return 1;
 714         } /* else: not a kprobe fault; let the kernel handle it */
 715
 716         return 0;
 717 }
 718 NOKPROBE_SYMBOL(kprobe_int3_handler);
```

setup_singlestep 函数将指令执行设置为单步模式。

```c
 /* CPU 设置为单步模式继续执行探测点原有的指令，原有指令执行完成以后又会陷入单步异常 int1，在 int1 中调用 post_handler，并恢复单步模式到正常模式，然后返回继续执行探测点后续的指令 */
 585 static void setup_singlestep(struct kprobe *p, struct pt_regs *regs,
 586                              struct kprobe_ctlblk *kcb, int reenter)
 587 {
 588         if (setup_detour_execution(p, regs, reenter))
 589                 return;
						 // ...
 611         /* Prepare real single stepping */
 612         clear_btf();
 613         regs->flags |= X86_EFLAGS_TF;  // If TF is set, we will single-step all the way to do_debug
 614         regs->flags &= ~X86_EFLAGS_IF;
 615         /* single step inline if the instruction is an int3 */
 616         if (p->opcode == INT3_INSN_OPCODE)
 617                 regs->ip = (unsigned long)p->addr;   
 618         else
 619                 regs->ip = (unsigned long)p->ainsn.insn; // 执行保存的探测点的指令，执行完成后会陷入 int1 中断
 620 }
 621 NOKPROBE_SYMBOL(setup_singlestep);
```

设置的 X86_EFLAGS_TF 为 CPU 中执行的单步执行模式，定义如下：

```c
arch/x86/include/uapi/asm/processor-flags.h
23:#define X86_EFLAGS_TF_BIT	8 /* Trap Flag */
24:#define X86_EFLAGS_TF		_BITUL(X86_EFLAGS_TF_BIT)
```



### int1 中断函数 handle_debug

在上述设置单步模式 `setup_singlestep` 后，运行探测点原来备份的指令，在指令完成后会触发 int1 中断，最终调用到 `exc_debug` 函数。

arch/x86/kernel/traps.c

```c
 912 #ifdef CONFIG_X86_64
 913 /* IST stack entry */
 914 DEFINE_IDTENTRY_DEBUG(exc_debug)
 915 {
 916         unsigned long dr6, dr7;
 917
 918         debug_enter(&dr6, &dr7);
 919         exc_debug_kernel(regs, dr6);
 920         debug_exit(dr7);
 921 }
 922
 923 /* User entry, runs on regular task stack */
 924 DEFINE_IDTENTRY_DEBUG_USER(exc_debug)
 925 {
 926         unsigned long dr6, dr7;
 927
 928         debug_enter(&dr6, &dr7);
 929         exc_debug_user(regs, dr6);
 930         debug_exit(dr7);
 931 }
```

在内核模式下调用 `exc_debug_kernel`。

```c
 867 static __always_inline void exc_debug_kernel(struct pt_regs *regs,
 868                                              unsigned long dr6)
 869 {
						 // ...
 887         handle_debug(regs, dr6, false);
						 // ...
 893 }
```

`handle_debug` 函数为 int1 在内核中最终调用的处理函数。

arch/x86/kernel/traps.c

```c
 773 /*
 774  * Our handling of the processor debug registers is non-trivial.
 775  * We do not clear them on entry and exit from the kernel. Therefore
 776  * it is possible to get a watchpoint trap here from inside the kernel.
 777  * However, the code in ./ptrace.c has ensured that the user can
 778  * only set watchpoints on userspace addresses. Therefore the in-kernel
 779  * watchpoint trap can only occur in code which is reading/writing
 780  * from user space. Such code must not hold kernel locks (since it
 781  * can equally take a page fault), therefore it is safe to call
 782  * force_sig_info even though that claims and releases locks.
 783  *
 784  * Code in ./signal.c ensures that the debug control register
 785  * is restored before we deliver any signal, and therefore that
 786  * user code runs with the correct debug control register even though
 787  * we clear it here.
 788  *
 789  * Being careful here means that we don't have to be as careful in a
 790  * lot of more complicated places (task switching can be a bit lazy
 791  * about restoring all the debug state, and ptrace doesn't have to
 792  * find every occurrence of the TF bit that could be saved away even
 793  * by user code)
 794  *
 795  * May run on IST stack.
 796  */
 797 static void handle_debug(struct pt_regs *regs, unsigned long dr6, bool user)
 798 {
			 	 // ...
 827 #ifdef CONFIG_KPROBES
 828         if (kprobe_debug_handler(regs)) {
 829                 return;
 830         }
 831 #endif
 832
				// ...
 865 }
```

调用 `kprobe_debug_handler` 完成 kprobe 的处理。

arch/x86/kernel/kprobes/core.c

```c
 968 /*
 969  * Interrupts are disabled on entry as trap1 is an interrupt gate and they
 970  * remain disabled throughout this function.
 971  */
 972 int kprobe_debug_handler(struct pt_regs *regs)
 973 {
   
 980         resume_execution(cur, regs, kcb);  // 恢复单步模式为正常模式 arch/x86/kernel/kprobes/core.c
 981         regs->flags |= kcb->kprobe_saved_flags;

   					 // 调用 post_handler 函数处理
 983         if ((kcb->kprobe_status != KPROBE_REENTER) && cur->post_handler) {
 984                 kcb->kprobe_status = KPROBE_HIT_SSDONE;
 985                 cur->post_handler(cur, regs, 0);
 986         }

						 // ...
1004 }
1005 NOKPROBE_SYMBOL(kprobe_debug_handler);
```

## kretprobe

```
 720 /*
 721  * When a retprobed function returns, this code saves registers and
 722  * calls trampoline_handler() runs, which calls the kretprobe's handler.
 723  */
 724 asm(
 725         ".text\n"
 726         ".global kretprobe_trampoline\n"
 727         ".type kretprobe_trampoline, @function\n"
 728         "kretprobe_trampoline:\n"
 729         /* We don't bother saving the ss register */
 730 #ifdef CONFIG_X86_64
 731         "       pushq %rsp\n"
 732         "       pushfq\n"
 733         SAVE_REGS_STRING
 734         "       movq %rsp, %rdi\n"
 735         "       call trampoline_handler\n"
 736         /* Replace saved sp with true return address. */
 737         "       movq %rax, 19*8(%rsp)\n"
 738         RESTORE_REGS_STRING
 739         "       popfq\n"
 740 #else
 741         "       pushl %esp\n"
 742         "       pushfl\n"
 743         SAVE_REGS_STRING
 744         "       movl %esp, %eax\n"
 745         "       call trampoline_handler\n"
 746         /* Replace saved sp with true return address. */
  747         "       movl %eax, 15*4(%esp)\n"
 748         RESTORE_REGS_STRING
 749         "       popfl\n"
 750 #endif
 751         "       ret\n"
 752         ".size kretprobe_trampoline, .-kretprobe_trampoline\n"
 753 );
 754 NOKPROBE_SYMBOL(kretprobe_trampoline);
 755 STACK_FRAME_NON_STANDARD(kretprobe_trampoline);
 
 757 /*
 758  * Called from kretprobe_trampoline
 759  */
 760 __used __visible void *trampoline_handler(struct pt_regs *regs)
 761 {
 762         struct kretprobe_instance *ri = NULL;
 763         struct hlist_head *head, empty_rp;
 764         struct hlist_node *tmp;
 765         unsigned long flags, orig_ret_address = 0;
 766         unsigned long trampoline_address = (unsigned long)&kretprobe_trampoline;
 767         kprobe_opcode_t *correct_ret_addr = NULL;
 768         void *frame_pointer;
 769         bool skipped = false;
 770
 771         /*
 772          * Set a dummy kprobe for avoiding kretprobe recursion.
 773          * Since kretprobe never run in kprobe handler, kprobe must not
 774          * be running at this point.
 775          */
 776         kprobe_busy_begin();
 777
 778         INIT_HLIST_HEAD(&empty_rp);
 779         kretprobe_hash_lock(current, &head, &flags);
 780         /* fixup registers */
 781         regs->cs = __KERNEL_CS;
 782 #ifdef CONFIG_X86_32
 783         regs->cs |= get_kernel_rpl();
 784         regs->gs = 0;
 785 #endif
  786         /* We use pt_regs->sp for return address holder. */
 787         frame_pointer = &regs->sp;
 788         regs->ip = trampoline_address;
 789         regs->orig_ax = ~0UL;
 790
 791         /*
 792          * It is possible to have multiple instances associated with a given
 793          * task either because multiple functions in the call path have
 794          * return probes installed on them, and/or more than one
 795          * return probe was registered for a target function.
 796          *
 797          * We can handle this because:
 798          *     - instances are always pushed into the head of the list
 799          *     - when multiple return probes are registered for the same
 800          *       function, the (chronologically) first instance's ret_addr
 801          *       will be the real return address, and all the rest will
 802          *       point to kretprobe_trampoline.
 803          */
 804         hlist_for_each_entry(ri, head, hlist) {
 805                 if (ri->task != current)
 806                         /* another task is sharing our hash bucket */
 807                         continue;
 808                 /*
 809                  * Return probes must be pushed on this hash list correct
 810                  * order (same as return order) so that it can be popped
 811                  * correctly. However, if we find it is pushed it incorrect
 812                  * order, this means we find a function which should not be
 813                  * probed, because the wrong order entry is pushed on the
 814                  * path of processing other kretprobe itself.
 815                  */
 816                 if (ri->fp != frame_pointer) {
 817                         if (!skipped)
 817                         if (!skipped)
 818                                 pr_warn("kretprobe is stacked incorrectly. Trying to fixup.\n");
 819                         skipped = true;
 820                         continue;
 821                 }
 822
 823                 orig_ret_address = (unsigned long)ri->ret_addr;
 824                 if (skipped)
 825                         pr_warn("%ps must be blacklisted because of incorrect kretprobe order\n",
 826                                 ri->rp->kp.addr);
 827
 828                 if (orig_ret_address != trampoline_address)
 829                         /*
 830                          * This is the real return address. Any other
 831                          * instances associated with this task are for
 832                          * other calls deeper on the call stack
 833                          */
 834                         break;
 835         }
 836
 837         kretprobe_assert(ri, orig_ret_address, trampoline_address);
 838
 839         correct_ret_addr = ri->ret_addr;
 840         hlist_for_each_entry_safe(ri, tmp, head, hlist) {
 841                 if (ri->task != current)
 842                         /* another task is sharing our hash bucket */
 843                         continue;
 844                 if (ri->fp != frame_pointer)
 845                         continue;
 846
 847                 orig_ret_address = (unsigned long)ri->ret_addr;
 848                 if (ri->rp && ri->rp->handler) {
 849                         __this_cpu_write(current_kprobe, &ri->rp->kp);
 850                         ri->ret_addr = correct_ret_addr;
 851                         ri->rp->handler(ri, regs);
 852                         __this_cpu_write(current_kprobe, &kprobe_busy);
 853                 }
 854
 855                 recycle_rp_inst(ri, &empty_rp);
 856
 857                 if (orig_ret_address != trampoline_address)
 858                         /*
 859                          * This is the real return address. Any other
 860                          * instances associated with this task are for
 861                          * other calls deeper on the call stack
 862                          */
 863                         break;
 864         }
 865
 866         kretprobe_hash_unlock(current, &flags);
 867
 868         kprobe_busy_end();
 869
 870         hlist_for_each_entry_safe(ri, tmp, &empty_rp, hlist) {
 871                 hlist_del(&ri->hlist);
 872                 kfree(ri);
 873         }
 874         return (void *)orig_ret_address;
 875 }
 876 NOKPROBE_SYMBOL(trampoline_handler);
```

## KProbes Event

基于 KProbes 技术的基础，使用的前端有两种接口 ftrace 和 perf，通过 ftrace 设置启用 KProbes 以后，在底层实现上是注册了函数 `kprobe_dispatcher` 和 `kretprobe_dispatcher` ，也就是说为了搜集 KProbes 的触发的 Event，都会统一在 `kprobe_dispatcher`  函数中进行处理：

相关结构定义

```c
/*
 * Kprobe event core functions
 */
struct trace_kprobe {
  struct dyn_event  devent;
  struct kretprobe  rp; /* Use rp.kp for kprobe use */  // 内部嵌入了  kprobe
  unsigned long __percpu *nhit;
  const char    *symbol;  /* symbol name */  // 跟踪的函数名称
  struct trace_probe  tp;
};


struct trace_probe {
  struct list_head    list;
  struct trace_probe_event  *event;
  ssize_t       size; /* trace entry size */
  unsigned int      nr_args;
  struct probe_arg    args[];
};

struct kretprobe {
  struct kprobe kp;
  kretprobe_handler_t handler;
  kretprobe_handler_t entry_handler;
  int maxactive;
  int nmissed;
  size_t data_size;
  struct hlist_head free_instances;
  raw_spinlock_t lock;
};
```

`kprobe_dispatcher` 函数定义：

```c
static int kprobe_dispatcher(struct kprobe *kp, struct pt_regs *regs)
{
  // 通过 kprobe 结构反推到 trace_kprobe 结构
	struct trace_kprobe *tk = container_of(kp, struct trace_kprobe, rp.kp);
	int ret = 0;

	raw_cpu_inc(*tk->nhit);

	if (trace_probe_test_flag(&tk->tp, TP_FLAG_TRACE)) // 基于 ftrace 的方式
		kprobe_trace_func(tk, regs);
#ifdef CONFIG_PERF_EVENTS
	if (trace_probe_test_flag(&tk->tp, TP_FLAG_PROFILE)) // 基于 PROFILE 的方式 Perf 
		ret = kprobe_perf_func(tk, regs);
#endif
	return ret;
}
NOKPROBE_SYMBOL(kprobe_dispatcher);
```



在 Perf 的方式下，可以挂载 BPF 相关程序，在  `kprobe_perf_func` 函数中通过 `bpf_prog_array_valid`函数进行 BPF 程序判断。

```c
/* Kprobe profile handler */
static int
kprobe_perf_func(struct trace_kprobe *tk, struct pt_regs *regs)
{
	struct trace_event_call *call = trace_probe_event_call(&tk->tp);
	struct kprobe_trace_entry_head *entry;
	struct hlist_head *head;
	int size, __size, dsize;
	int rctx;

	if (bpf_prog_array_valid(call)) { // 判断是否注入了 BPF 程序
		unsigned long orig_ip = instruction_pointer(regs);
		int ret;

		ret = trace_call_bpf(call, regs); // 调用 BPF 程序

		/*
		 * We need to check and see if we modified the pc of the
		 * pt_regs, and if so return 1 so that we don't do the
		 * single stepping.
		 */
		if (orig_ip != instruction_pointer(regs))
			return 1;
		if (!ret)
			return 0;
	}

	head = this_cpu_ptr(call->perf_events);
	if (hlist_empty(head))
		return 0;

	dsize = __get_data_size(&tk->tp, regs);
	__size = sizeof(*entry) + tk->tp.size + dsize;
	size = ALIGN(__size + sizeof(u32), sizeof(u64));
	size -= sizeof(u32);

	entry = perf_trace_buf_alloc(size, NULL, &rctx); // 创建 perf event
	if (!entry)
		return 0;

	entry->ip = (unsigned long)tk->rp.kp.addr;
	memset(&entry[1], 0, dsize);
	store_trace_args(&entry[1], &tk->tp, regs, sizeof(*entry), dsize);
	perf_trace_buf_submit(entry, size, rctx, call->event.type, 1, regs,
			      head, NULL);
	return 0;
}
NOKPROBE_SYMBOL(kprobe_perf_func);
```





## 参考

* https://blog.csdn.net/pwl999/article/details/80689127

* https://blog.csdn.net/pwl999/article/details/78225858