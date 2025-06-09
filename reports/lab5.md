# 操作系统lab5

# 原先代码改进

我们首先需要改进do_fork函数：

```c
//LAB5 YOUR CODE : (更新LAB4步骤)
/* 一些函数
*    set_links:  设置进程的关系链接。另见：remove_links: 清理进程的关系链接
*    -------------------
*    更新步骤1: 设置子进程的父进程为当前进程，确保当前进程的wait_state为0
*    更新步骤5: 将proc_struct插入hash_list和proc_list，设置进程的关系链接
*/
```

步骤1增加代码：`assert(current->wait_state == 0);` 

步骤5改为`set_links(proc);`

将原来简单的计数改成来执行set_links函数，从而实现设置进程的相关链接

do_fork整体代码变为：

```c
/* do_fork -     parent process for a new child process
 * @clone_flags: used to guide how to clone the child process
 * @stack:       the parent's user stack pointer. if stack==0, It means to fork a kernel thread.
 * @tf:          the trapframe info, which will be copied to child process's proc->tf
 */
int
do_fork(uint32_t clone_flags, uintptr_t stack, struct trapframe *tf) {
    int ret = -E_NO_FREE_PROC;
    struct proc_struct *proc;
    if (nr_process >= MAX_PROCESS) {
        goto fork_out;
    }
    ret = -E_NO_MEM;
    if ((proc = alloc_proc()) == NULL) {
        goto fork_out;
    }
    
    proc->parent = current;
    assert(current->wait_state == 0);

    if (setup_kstack(proc) != 0) {
        goto bad_fork_cleanup_proc;
    }
    if (copy_mm(clone_flags, proc) != 0) {
        goto bad_fork_cleanup_kstack;
    }
    copy_thread(proc, stack, tf);

    bool intr_flag;
    local_intr_save(intr_flag);
    {
        proc->pid = get_pid();
        hash_proc(proc);
        set_links(proc);
    }
    local_intr_restore(intr_flag);

    wakeup_proc(proc);

    ret = proc->pid;
fork_out:
    return ret;

bad_fork_cleanup_kstack:
    put_kstack(proc);
bad_fork_cleanup_proc:
    kfree(proc);
    goto fork_out;
}
```

同时我们需要改进`alloc_proc`函数

```c
// LAB5 你的代码：在 LAB4 的基础上进行更新
/*
 * 以下是在 LAB5 中新增的 proc_struct 结构体字段，需要进行初始化：
 *       uint32_t wait_state;                        // 等待状态
 *       struct proc_struct *cptr, *yptr, *optr;     // 进程之间的关系指针
 */
```

我们初始化对应字段如下：

```c
static struct proc_struct *alloc_proc(void) {
    struct proc_struct *proc = kmalloc(sizeof(struct proc_struct));
    if (proc != NULL) {
        proc->state=PROC_UNINIT;   //未初始化状态
        proc->pid=-1;
        proc->runs=0;
        proc->kstack=0;
        proc->need_resched=0;
        proc->parent=NULL;
        proc->mm=NULL;
        memset(&(proc->context),0,sizeof(struct context));
        proc->tf=NULL;
        proc->cr3=boot_cr3;        //页目录设置为内核页目录表的基址
        proc->flags=0;
        memset(proc->name,0,PROC_NAME_LEN);
        proc->wait_state = 0;
        proc->cptr = proc->optr = proc->yptr = NULL;
    }
    return proc;
}
```

改进idt_init函数

```c
/* LAB5 你的代码 */
// 你需要在这里对你在 LAB1 中的代码进行更新（只需添加一到两行代码），
// 目的是让用户态的应用程序可以通过系统调用（syscall）来获得 uCore 内核提供的服务。
// 因此你需要在这里设置系统调用的中断门（syscall interrupt gate）。
```

这是调用宏 SETGATE(...) 往中断描述符表（IDT）中设置第 T_SYSCALL 项，也就是系统调用中断。设置 IDT 的系统调用中断入口，使得用户程序可以用 int T_SYSCALL 执行系统调用，进入内核提供的服务。

```c
void idt_init(void) {
    extern uintptr_t __vectors[];
    int i;
    for (i = 0; i < sizeof(idt) / sizeof(struct gatedesc); i ++) {
        SETGATE(idt[i], 0, GD_KTEXT, __vectors[i], DPL_KERNEL);
    }
    SETGATE(idt[T_SYSCALL], 1, GD_KTEXT, __vectors[T_SYSCALL], DPL_USER); //设置相应的中断门
    lidt(&idt_pd);
}
```

改进trap_dispatch函数

```c
/* LAB5 你的代码 */
/* 你应该在 LAB1 的基础上更新你的代码（只需要添加一两行）：
 *    每隔 TICK_NUM 个时钟周期，你就应该设置当前进程的 current->need_resched = 1
 */
```

改进后的代码，增加了一行`current->need_resched = 1`

```c
ticks ++;
if (ticks % TICK_NUM == 0) {
    assert(current != NULL);
    current->need_resched = 1;
}
```

# 练习1: 加载应用程序并执行

查看`do_execve`函数，发现`do_execv`函数调用load_icode（位于kern/process/proc.c中）来加载并解析一个处于内存中的ELF执行文件格式的应用程序，建立相应的用户内存空间来放置应用程序的代码段、数据段等。

```c
// do_execve - call exit_mmap(mm)&put_pgdir(mm) to reclaim memory space of current process
//           - call load_icode to setup new memory space accroding binary prog.
int 
do_execve(const char *name, size_t len, unsigned char *binary, size_t size) {
    struct mm_struct *mm = current->mm; // 获取当前进程的内存空间描述符

    // 检查用户传入的 name 字符串是否在用户空间合法（防止越界或访问非法内存）
    if (!user_mem_check(mm, (uintptr_t)name, len, 0)) {
        return -E_INVAL; // 非法地址，返回错误
    }

    // 限制程序名长度不能超过最大限制
    if (len > PROC_NAME_LEN) {
        len = PROC_NAME_LEN;
    }

    // 将程序名拷贝到内核局部变量中，保证安全性
    char local_name[PROC_NAME_LEN + 1];
    memset(local_name, 0, sizeof(local_name)); // 清零（末尾留 \0）
    memcpy(local_name, name, len);             // 拷贝实际名字

    // 如果当前进程已有内存空间（mm）则要释放它
    if (mm != NULL) {
        lcr3(boot_cr3);  // 切换页目录到内核（boot_cr3），防止后续释放自己用的页表时崩溃

        // 如果 mm 引用计数减为 0，说明没有其他线程共享此 mm，可以释放
        if (mm_count_dec(mm) == 0) {
            exit_mmap(mm);      // 回收用户内存空间
            put_pgdir(mm);      // 回收页目录相关资源
            mm_destroy(mm);     // 销毁 mm 结构本身
        }
        current->mm = NULL;     // 当前进程不再拥有内存空间（将重新分配）
    }

    int ret;
    // 尝试加载新的用户程序（binary 是 ELF 格式可执行文件）
    if ((ret = load_icode(binary, size)) != 0) {
        goto execve_exit;  // 加载失败，退出
    }

    // 设置当前进程的名字为新程序名（用于 ps/top 等工具显示）
    set_proc_name(current, local_name);
    return 0;  // 成功

execve_exit:
    // 加载失败，直接终结当前进程
    do_exit(ret);
    panic("already exit: %e.\n", ret); // 实际上不会执行到这里（do_exit 不会返回）
}

```

查看load_icode函数，发现其主要完成了以下功能：

1. 为当前进程创建一个新的内存管理结构
2. 创建新的页目录表，并将mm->pgdir设置为页目录表的内核虚拟地址
3. 将二进制程序中的TEXT/DATA段复制到进程的内存空间，并构建BSS段
4. 建立用户栈内存
5. 设置当前进程的mm、sr3，并将CR3寄存器设置为页目录表的物理地址
6. 为用户环境设置陷阱帧

```c
static int
load_icode(unsigned char *binary, size_t size) {
    if (current->mm != NULL) {
        panic("load_icode: current->mm must be empty.\n");
    }

    int ret = -E_NO_MEM;
    struct mm_struct *mm;
    //(1) 为当前进程创建一个新的内存管理结构
    if ((mm = mm_create()) == NULL) {
        goto bad_mm;
    }
    //(2) 创建新的页目录表，并将mm->pgdir设置为页目录表的内核虚拟地址
    if (setup_pgdir(mm) != 0) {
        goto bad_pgdir_cleanup_mm;
    }
    //(3) 将二进制程序中的TEXT/DATA段复制到进程的内存空间，并构建BSS段
    struct Page *page;
    //(3.1) 获取二进制程序的ELF文件头
    struct elfhdr *elf = (struct elfhdr *)binary;
    //(3.2) 获取二进制程序的程序段头表入口
    struct proghdr *ph = (struct proghdr *)(binary + elf->e_phoff);
    //(3.3) 验证程序是否合法
    if (elf->e_magic != ELF_MAGIC) {
        ret = -E_INVAL_ELF;
        goto bad_elf_cleanup_pgdir;
    }

    uint32_t vm_flags, perm;
    struct proghdr *ph_end = ph + elf->e_phnum;
    for (; ph < ph_end; ph ++) {
    //(3.4) 遍历每个程序段头
        if (ph->p_type != ELF_PT_LOAD) {
            continue ;
        }
        if (ph->p_filesz > ph->p_memsz) {
            ret = -E_INVAL_ELF;
            goto bad_cleanup_mmap;
        }
        if (ph->p_filesz == 0) {
            continue ;
        }
    //(3.5) 调用mm_map函数建立新的虚拟内存区域(ph->p_va, ph->p_memsz)
        vm_flags = 0, perm = PTE_U;
        if (ph->p_flags & ELF_PF_X) vm_flags |= VM_EXEC;
        if (ph->p_flags & ELF_PF_W) vm_flags |= VM_WRITE;
        if (ph->p_flags & ELF_PF_R) vm_flags |= VM_READ;
        if (vm_flags & VM_WRITE) perm |= PTE_W;
        if ((ret = mm_map(mm, ph->p_va, ph->p_memsz, vm_flags, NULL)) != 0) {
            goto bad_cleanup_mmap;
        }
        unsigned char *from = binary + ph->p_offset;
        size_t off, size;
        uintptr_t start = ph->p_va, end, la = ROUNDDOWN(start, PGSIZE);

        ret = -E_NO_MEM;

     //(3.6) 分配内存，并将每个程序段的内容(from, from+end)复制到进程内存(la, la+end)
        end = ph->p_va + ph->p_filesz;
     //(3.6.1) 复制二进制程序的TEXT/DATA段
        while (start < end) {
            if ((page = pgdir_alloc_page(mm->pgdir, la, perm)) == NULL) {
                goto bad_cleanup_mmap;
            }
            off = start - la, size = PGSIZE - off, la += PGSIZE;
            if (end < la) {
                size -= la - end;
            }
            memcpy(page2kva(page) + off, from, size);
            start += size, from += size;
        }

      //(3.6.2) 构建二进制程序的BSS段
        end = ph->p_va + ph->p_memsz;
        if (start < la) {
            /* ph->p_memsz == ph->p_filesz */
            if (start == end) {
                continue ;
            }
            off = start + PGSIZE - la, size = PGSIZE - off;
            if (end < la) {
                size -= la - end;
            }
            memset(page2kva(page) + off, 0, size);
            start += size;
            assert((end < la && start == end) || (end >= la && start == la));
        }
        while (start < end) {
            if ((page = pgdir_alloc_page(mm->pgdir, la, perm)) == NULL) {
                goto bad_cleanup_mmap;
            }
            off = start - la, size = PGSIZE - off, la += PGSIZE;
            if (end < la) {
                size -= la - end;
            }
            memset(page2kva(page) + off, 0, size);
            start += size;
        }
    }
    //(4) 建立用户栈内存
    vm_flags = VM_READ | VM_WRITE | VM_STACK;
    if ((ret = mm_map(mm, USTACKTOP - USTACKSIZE, USTACKSIZE, vm_flags, NULL)) != 0) {
        goto bad_cleanup_mmap;
    }
    assert(pgdir_alloc_page(mm->pgdir, USTACKTOP-PGSIZE , PTE_USER) != NULL);
    assert(pgdir_alloc_page(mm->pgdir, USTACKTOP-2*PGSIZE , PTE_USER) != NULL);
    assert(pgdir_alloc_page(mm->pgdir, USTACKTOP-3*PGSIZE , PTE_USER) != NULL);
    assert(pgdir_alloc_page(mm->pgdir, USTACKTOP-4*PGSIZE , PTE_USER) != NULL);
    
    //(5) 设置当前进程的mm、sr3，并将CR3寄存器设置为页目录表的物理地址
    mm_count_inc(mm);
    current->mm = mm;
    current->cr3 = PADDR(mm->pgdir);
    lcr3(PADDR(mm->pgdir));

    //(6) 为用户环境设置陷阱帧
    struct trapframe *tf = current->tf;
    memset(tf, 0, sizeof(struct trapframe));
    /* LAB5:EXERCISE1 你的代码
     * 应该设置tf_cs,tf_ds,tf_es,tf_ss,tf_esp,tf_eip,tf_eflags
     * 注意：如果我们正确设置了陷阱帧，用户级进程就能从内核态返回到用户态。
     *       因此：
     *       tf_cs应该是USER_CS段(参见memlayout.h)
     *       tf_ds=tf_es=tf_ss应该是USER_DS段
     *       tf_esp应该是用户栈的顶部地址(USTACKTOP)
     *       tf_eip应该是该二进制程序的入口点(elf->e_entry)
     *       tf_eflags应该设置为允许计算机产生中断
     */
    ret = 0;
out:
    return ret;
bad_cleanup_mmap:
    exit_mmap(mm);
bad_elf_cleanup_pgdir:
    put_pgdir(mm);
bad_pgdir_cleanup_mm:
    mm_destroy(mm);
bad_mm:
    goto out;
}
```

## 设计实现过程

本实验需要我们设置好proc_struct结构中的成员变量trapframe中的内容，确保在执行此进程后，能够从应用程序设定的起始执行地址开始执行。

查看trapframe结构体

```c
// 代表中断/异常发生时保存的一组寄存器和状态信息
struct trapframe {
    struct pushregs tf_regs;      // 通用寄存器 (eax, ebx, ecx, edx, esi, edi, ebp) 等，由汇编代码手动保存

    // 段寄存器，由中断进入时自动压栈（部分手动压栈），用于段寄存器的恢复
    uint16_t tf_gs;               // GS 段寄存器
    uint16_t tf_padding0;         // 对齐填充
    uint16_t tf_fs;               // FS 段寄存器
    uint16_t tf_padding1;         // 对齐填充
    uint16_t tf_es;               // ES 段寄存器
    uint16_t tf_padding2;         // 对齐填充
    uint16_t tf_ds;               // DS 段寄存器
    uint16_t tf_padding3;         // 对齐填充

    uint32_t tf_trapno;           // 中断号或异常号（由中断处理例程填入）

    /* 以下部分由 x86 硬件在中断/异常时自动压栈 */

    uint32_t tf_err;              // 错误码（某些异常如页错误、段异常等会压栈）

    uintptr_t tf_eip;             // 中断/异常发生时的 EIP（指令指针）
    uint16_t tf_cs;               // 段选择子（代码段）
    uint16_t tf_padding4;         // 对齐填充
    uint32_t tf_eflags;           // EFLAGS 标志寄存器（保存标志位）

    /* 只有在特权级改变（如从用户态切换到内核态）时才会自动压栈以下内容 */

    uintptr_t tf_esp;             // 被中断代码的用户态 ESP（栈顶指针）
    uint16_t tf_ss;               // 被中断代码的用户态 SS（栈段选择子）
    uint16_t tf_padding5;         // 对齐填充
} __attribute__((packed));        // 不允许编译器自动填充结构体对齐空间

```

依照实验提示，我们需要按照如下方式填充：

```c
/* LAB5:EXERCISE1 你的代码
 * 应该设置tf_cs,tf_ds,tf_es,tf_ss,tf_esp,tf_eip,tf_eflags
 * 注意：如果我们正确设置了陷阱帧，用户级进程就能从内核态返回到用户态。
 *       因此：
 *       tf_cs应该是USER_CS段(参见memlayout.h)
 *       tf_ds=tf_es=tf_ss应该是USER_DS段
 *       tf_esp应该是用户栈的顶部地址(USTACKTOP)
 *       tf_eip应该是该二进制程序的入口点(elf->e_entry)
 *       tf_eflags应该设置为允许计算机产生中断
 */
```

在 x86 架构中，访问内存必须通过段选择子和页表配合完成，而段寄存器（ds, ss, es）决定了当前运行代码的权限和访问范围。在内核态运行时，使用的是 KERNEL_CS, KERNEL_DS 等内核段,在用户态运行时，必须切换到 USER_CS, USER_SS 等用户段。由于最终是在用户态下运行的，所以需要将段寄存器初始化为用户态的代码段、数据段、堆栈段。

esp 应当指向先前的步骤中创建的用户栈的栈顶，每个用户进程必须拥有自己的栈空间。栈是向下增长的，因此设置 ESP 指向栈顶。

eip指向下一条要执行的指令，故eip 应当指向 ELF 可执行文件加载到内存之后的入口处。

eflags 中应当初始化为中断使能。

故需要填充的代码如下：

```c
tf->tf_cs = USER_CS;
tf->tf_ds = tf->tf_es = tf->tf_ss = USER_DS;
tf->tf_esp = USTACKTOP; 
tf->tf_eip = elf->e_entry;
tf->tf_eflags = FL_IF;
```

## 用户态进程被ucore选择占用CPU执行到具体执行应用程序第一条指令的整个经过

在fork/exec后，用户态进程调用了 exec 系统调用，从而转入到了系统调用的处理例程，在经过了中断处理例程之后，执行SYS_exec，并执行调用do_execve函数，然后通过load_icode函数对整个用户线程内存空间的初始化，包括设置用户页表、加载 ELF、构造 trapframe等，在完成了 do_exec 函数之后，进行正常的中断返回的流程，由于中断处理例程的栈上面的 eip 已经被修改成了应用程序的入口处，而 CS 上的 CPL 是用户态，因此 iret（恢复一系列寄存器） 进行中断返回的时候会将堆栈切换到用户的栈，并且完成特权级的切换，并且跳转到要求的应用程序的入口处，接下来开始具体执行应用程序的第一条指令。

图解如下：

```c
fork/exec → do_execve → load_icode
         ↓
设置用户页表、加载 ELF、构造 trapframe
         ↓
trapframe 设置 eip/esp/cs/ds/ss/eflags 等
         ↓
  [iret 指令]
         ↓
CPU 切换为用户态 → 执行 eip 第一条指令
```

# 练习2: 父进程复制自己的内存空间给子进程

## 设计实现过程

创建子进程的函数do_fork在执行中将拷贝当前进程（即父进程）的用户内存地址空间中的合法内容到新进程中（子进程），完成内存资源的复制。具体是通过copy_range函数（位于kern/mm/pmm.c中）实现的。

依照copy_mm的注释，调用路径为 do_fork --> copy_mm --> dup_mmap --> copy_range

do_fork函数通过调用copy_mm根据clone_flag复制或共享父进程内存信息，在copy_mm中打开互斥锁,避免多个进程同时访问内存，在dup_mmap中调用copy_range逐页复制父进程的物理内存到子进程。

查看copy_range函数如下，我们要做的工作便是补充copy_range的实现，确保能够正确执行。

```c
/* copy_range - 将一个进程 A 的指定内存范围 (start, end) 内容复制到另一个进程 B 中
 * @to:    目标进程 B 的页目录地址
 * @from:  源进程 A 的页目录地址
 * @share: 指示是共享还是复制的标志，本实现中仅使用复制方式，因此未使用该参数
 *
 * 调用路径：copy_mm --> dup_mmap --> copy_range
 */
int
copy_range(pde_t *to, pde_t *from, uintptr_t start, uintptr_t end, bool share) {
    assert(start % PGSIZE == 0 && end % PGSIZE == 0);
    assert(USER_ACCESS(start, end));
    // 以页为单位复制内容
    do {
        // 调用 get_pte 查找源进程 A 中地址 start 对应的页表项
        pte_t *ptep = get_pte(from, start, 0), *nptep;
        if (ptep == NULL) {
            start = ROUNDDOWN(start + PTSIZE, PTSIZE);
            continue ;
        }
        // 调用 get_pte 查找目标进程 B 中地址 start 对应的页表项，如果页表项不存在则分配一个页表
        if (*ptep & PTE_P) {
            if ((nptep = get_pte(to, start, 1)) == NULL) {
                return -E_NO_MEM;
            }
            uint32_t perm = (*ptep & PTE_USER);
            // 从页表项中获取对应的物理页
            struct Page *page = pte2page(*ptep);
            // 为进程 B 分配一个新的物理页
            struct Page *npage = alloc_page();
            assert(page != NULL);
            assert(npage != NULL);
            int ret = 0;
            /* LAB5:EXERCISE2 你的实现
             * 复制 page 中的内容到 npage，并建立从线性地址 start 到新物理页的映射
             *
             * 可使用的宏和函数：
             *    page2kva(struct Page *page): 获取页面对应的内核虚拟地址（定义于 pmm.h）
             *    page_insert: 建立一个从线性地址 la 到物理页的映射关系
             *    memcpy: 标准内存拷贝函数
             *
             * 实现步骤：
             * (1) 获取源页面的内核虚拟地址 src_kvaddr
             * (2) 获取目标页面的内核虚拟地址 dst_kvaddr
             * (3) 将 src_kvaddr 内容复制到 dst_kvaddr，复制大小为 PGSIZE
             * (4) 调用 page_insert 建立目标页表项
             */
            assert(ret == 0);
        }
        start += PGSIZE;
    } while (start != 0 && start < end);
    return 0;
}

```

查看copy_range其余部分的代码，源进程 A 中地址 start 对应的页表项对应的物理页是page，目标页面是npage，调用page2kva函数分别获得其对应的在内核地址空间中的虚拟地址，因为mymcpy这个函数执行的时候使用的时内核的地址空间，利用该函数复制PGSIZE大小，查看page_insert函数定义，依照定义建立页表映射，将物理页（npage）映射到目标进程（to）的虚拟地址 start 处，并设置页表项的权限标志 perm。依照实验给出的注释填写代码即可。

```c
void * src_kvaddr = page2kva(page); 
void * dst_kvaddr = page2kva(npage); 
memcpy(dst_kvaddr, src_kvaddr, PGSIZE);
ret = page_insert(to, npage, start, perm);
```

创建后，效果如下

| 类型 | 地址空间 | 虚拟地址（start） | 物理页 | 权限 |
| --- | --- | --- | --- | --- |
| 源进程 A | `from` | `start` | `page` | perm |
| 目标进程 B | `to` | `start` | `npage`（新分配） | 相同权限 |

## 简要说明如何设计实现”Copy on Write 机制“

Copy-on-write（简称COW）的基本概念是指如果有多个使用者对一个资源A（比如内存块）进行读操作，则每个使用者只需获得一个指向同一个资源A的指针，就可以该资源了。若某使用者需要对这个资源A进行写操作，系统会对该资源进行拷贝操作，从而使得该“写操作”使用者获得一个该资源A的“私有”拷贝—资源B，可对资源B进行写操作。该“写操作”使用者对资源B的改变对于其他的使用者而言是不可见的，因为其他使用者看到的还是资源A。

在进程执行 fork 系统调用进行复制的时候，父进程不会简单地将整个内存中的内容复制给子进程，而是暂时共享相同的物理内存页；而当其中一个进程需要对内存进行修改的时候，再额外创建一个自己私有的物理内存页，将共享的内容复制过去，然后在自己的内存页中进行修改；

do_fork 时：

- 共享父进程的物理页。
- 将父进程和子进程的页表项都设置为只读，并标记 COW。
- 如果应用程序试图写某一个共享页就会产生页访问异常，从而可以将控制权交给操作系统进行处理。
- 对每个共享的物理页，增加其引用计数。

写操作时（page fault）：

1. 检查引发缺页的地址是否在用户空间，并且错误原因是写操作。
2. 检查该地址对应的页表项是否存在，并且标记为COW。
3. 如果满足条件，则分配新物理页，复制内容。
4. 修改当前进程的页表项，指向新物理页，并设置权限（可写，清除COW标记）。
5. 减少原始物理页的引用计数，如果引用计数变为0，则释放该物理页。

# 练习3: 阅读分析源代码，理解进程执行 fork/exec/wait/exit 的实现，以及系统调用的实现

在proc.c文件中，介绍了有关 fork/exec/wait/exit 的系统调用及其作用：

```c
SYS_exit        : process exit,                           -->do_exit
SYS_fork        : create child process, dup mm            -->do_fork-->wakeup_proc
SYS_wait        : wait process                            -->do_wait
SYS_exec        : after fork, process execute a program   -->load a program and refresh the mm
```

其右侧给出了调用链。

## fork

在syscall.c中找到了其系统调用的实现：

```c
static int
sys_fork(uint32_t arg[]) {
    struct trapframe *tf = current->tf;
    uintptr_t stack = tf->tf_esp;
    return do_fork(0, stack, tf);
}
```

`sys_fork` 是内核中处理 `fork()` 系统调用的函数，它从当前进程的 trapframe 中提取必要上下文信息，并调用 `do_fork` 来创建一个子进程，使其从同样的位置继续运行。

其中do_fork函数已在lab4已经lab5的练习二中实现，代码也在相应练习中给出，大致完成的工作如下

- 1、分配并初始化进程控制块（ alloc_proc 函数）;
- 2、分配并初始化内核栈，为内核进程（线程）建立栈空间（ setup_stack 函数）;
- 3、根据 clone_flag 标志复制或共享进程内存管理结构（ copy_mm 函数）;
- 4、设置进程在内核（将来也包括用户态）正常运行和调度所需的中断帧和执行上下文 （ copy_thread 函数）;
- 5、为进程分配一个 PID（ get_pid() 函数）;
- 6、把设置好的进程控制块放入 hash_list 和 proc_list 两个全局进程链表中;
- 7、自此，进程已经准备好执行了，把进程状态设置为“就绪”态;
- 8、设置返回码为子进程的 PID 号。

而 wakeup_proc 函数主要是将进程的状态设置为等待，即 proc->wait_state = 0。

## exec

在syscall.c中找到了其系统调用的实现：

```c
static int
sys_exec(uint32_t arg[]) {
    const char *name = (const char *)arg[0];
    size_t len = (size_t)arg[1];
    unsigned char *binary = (unsigned char *)arg[2];
    size_t size = (size_t)arg[3];
    return do_execve(name, len, binary, size);
}
```

`sys_exec` 是内核中处理 `exec` 系统调用的接口函数，它接收用户传入的新程序名称和二进制内容，并调用 `do_execve` 来加载并执行新程序，替换当前进程的执行映像。
`do_execve()`具体实现如下：

```c
int
do_execve(const char *name, size_t len, unsigned char *binary, size_t size) {
    struct mm_struct *mm = current->mm;

    // 1. 检查用户提供的程序名地址是否合法
    if (!user_mem_check(mm, (uintptr_t)name, len, 0)) {
        return -E_INVAL;  // 地址不合法，返回错误
    }

    // 2. 限制程序名称长度，防止溢出
    if (len > PROC_NAME_LEN) {
        len = PROC_NAME_LEN;
    }

    // 3. 拷贝程序名称到内核空间的局部变量
    char local_name[PROC_NAME_LEN + 1];
    memset(local_name, 0, sizeof(local_name)); // 清空缓冲区
    memcpy(local_name, name, len);             // 拷贝用户态程序名到本地字符串

    // 4. 如果当前进程拥有地址空间（mm），则先清理旧的地址空间
    if (mm != NULL) {
        lcr3(boot_cr3);  // 切换到内核页表，暂时脱离当前用户态地址空间
        if (mm_count_dec(mm) == 0) { // 如果该地址空间引用计数为 0
            exit_mmap(mm);           // 释放用户态映射的内存页
            put_pgdir(mm);           // 释放页目录
            mm_destroy(mm);          // 销毁地址空间结构体
        }
        current->mm = NULL;          // 当前进程脱离原地址空间
    }

    int ret;
    // 5. 加载新的程序映像（可执行文件二进制）
    if ((ret = load_icode(binary, size)) != 0) {
        goto execve_exit; // 加载失败，跳转清理退出
    }

    // 6. 设置新进程名
    set_proc_name(current, local_name);

    return 0; // 成功返回

execve_exit:
    // 如果加载失败，直接退出当前进程（do_exit 不返回）
    do_exit(ret);
    // 正常不会执行到这里，加个 panic 保险
    panic("already exit: %e.\n", ret);
}
```

该函数用于执行 `execve` 系统调用的核心逻辑，主要过程如下：

1. 检查用户传入的程序名是否合法；
2. 清理当前进程旧的地址空间；
3. 加载新的可执行程序映像（通过 `load_icode`）；
4. 设置新进程名；
5. 如果加载失败则终止当前进程。

## wait

在syscall.c中找到了其系统调用的实现：

```c
static int
sys_wait(uint32_t arg[]) {
    int pid = (int)arg[0];
    int *store = (int *)arg[1];
    return do_wait(pid, store);
}
```

`sys_wait` 是用户态进程调用 `wait()` 或 `waitpid()` 时进入内核的接口，它接收子进程 pid 和退出码存储位置，并调用 `do_wait` 实现等待子进程退出、回收资源并返回退出信息的功能。
`do_wait()`具体实现如下：

```c
int
do_wait(int pid, int *code_store) {
    struct mm_struct *mm = current->mm;

    // 如果提供了用于保存退出码的地址，则进行合法性检查
    if (code_store != NULL) {
        // 检查该地址是否为当前进程的合法用户内存地址，且具有写权限
        if (!user_mem_check(mm, (uintptr_t)code_store, sizeof(int), 1)) {
            return -E_INVAL; // 非法地址，返回错误
        }
    }

    struct proc_struct *proc;
    bool intr_flag, haskid;

repeat:
    haskid = 0;

    if (pid != 0) {
        // 如果指定了 pid，查找该进程
        proc = find_proc(pid);
        // 如果该进程存在且是当前进程的子进程
        if (proc != NULL && proc->parent == current) {
            haskid = 1;
            // 如果子进程已经是僵尸态，可以回收它
            if (proc->state == PROC_ZOMBIE) {
                goto found;
            }
        }
    }
    else {
        // pid 为 0，表示等待任意一个子进程
        proc = current->cptr;  // 从第一个子进程开始遍历
        for (; proc != NULL; proc = proc->optr) {
            haskid = 1;
            // 找到一个僵尸态子进程，准备回收
            if (proc->state == PROC_ZOMBIE) {
                goto found;
            }
        }
    }

    if (haskid) {
        // 有子进程，但没有僵尸进程，进入等待状态
        current->state = PROC_SLEEPING;
        current->wait_state = WT_CHILD;
        schedule(); // 交出 CPU，等待被唤醒

        // 如果当前进程在等待期间被标记为需要退出
        if (current->flags & PF_EXITING) {
            do_exit(-E_KILLED); // 主动终止
        }
        goto repeat; // 被唤醒后重新检查子进程状态
    }

    // 没有子进程，返回错误
    return -E_BAD_PROC;

found:
    // 安全检查：不允许等待 idleproc 或 initproc
    if (proc == idleproc || proc == initproc) {
        panic("wait idleproc or initproc.\n");
    }

    // 将子进程的退出码写入到用户提供的地址
    if (code_store != NULL) {
        *code_store = proc->exit_code;
    }

    // 进入临界区，处理进程资源的清理
    local_intr_save(intr_flag);
    {
        unhash_proc(proc);     // 从全局进程哈希表中移除
        remove_links(proc);    // 解除与父子链表的链接关系
    }
    local_intr_restore(intr_flag);

    put_kstack(proc);  // 释放内核栈
    kfree(proc);       // 释放进程控制块（PCB）

    return 0;          // 成功等待并回收子进程
}

```

`do_wait` 是内核实现的等待子进程退出的函数，它支持等待指定或任意子进程，并在找到已退出的子进程后回收其资源并返回退出码；如果没有找到，就让当前进程进入休眠，直到子进程退出或进程被杀死。

## exit

在syscall.c中找到了其系统调用的实现：

```c
static int
sys_exit(uint32_t arg[]) {
    int error_code = (int)arg[0];
    return do_exit(error_code);
}
```

`sys_exit` 是用户态进程调用 `exit()` 时进入内核的系统调用接口，它接收退出码并调用 `do_exit` 来终止进程并进行资源清理。

接下来我们来看看`do_exit()` 的具体实现：

```c
int
do_exit(int error_code) {
    // 如果当前进程是 idleproc（空闲进程），直接 panic。
    if (current == idleproc) {
        panic("idleproc exit.\n");
    }
    // 如果当前进程是 initproc（第一个用户进程），panic。
    if (current == initproc) {
        panic("initproc exit.\n");
    }
    
    // 获取当前进程的内存管理结构指针。
    struct mm_struct *mm = current->mm;
    if (mm != NULL) {
        // 切换到内核页表（boot_cr3），以便可以安全地销毁用户空间的页表。
        lcr3(boot_cr3);

        // 减少该内存管理结构的引用计数，如果为 0，说明可以释放。
        if (mm_count_dec(mm) == 0) {
            exit_mmap(mm);      // 释放所有内存映射（如代码段、堆、栈等）。
            put_pgdir(mm);      // 释放页目录。
            mm_destroy(mm);     // 销毁 mm_struct 本身。
        }

        // 将当前进程的 mm 清空，表示它不再拥有用户内存空间。
        current->mm = NULL;
    }

    // 将当前进程的状态设置为 ZOMBIE（僵尸），等待父进程回收资源。
    current->state = PROC_ZOMBIE;

    // 设置进程退出码。
    current->exit_code = error_code;
    
    bool intr_flag;
    struct proc_struct *proc;

    // 关闭中断，进入临界区，保护进程控制结构不被打断。
    local_intr_save(intr_flag);
    {
        // 获取父进程
        proc = current->parent;

        // 如果父进程正在等待子进程结束，唤醒它。
        if (proc->wait_state == WT_CHILD) {
            wakeup_proc(proc);
        }

        // 处理当前进程的子进程：将它们的父进程重新指向 initproc
        while (current->cptr != NULL) {
            proc = current->cptr;       // 获取当前的一个子进程
            current->cptr = proc->optr; // 从链表中移除该子进程

            proc->yptr = NULL; // 清除该子进程在兄弟链表中的后向指针

            // 将该子进程插入到 initproc 的子进程链表前端
            if ((proc->optr = initproc->cptr) != NULL) {
                initproc->cptr->yptr = proc;
            }
            proc->parent = initproc;
            initproc->cptr = proc;

            // 如果这个子进程已经是僵尸状态，并且 initproc 正在等待子进程，唤醒 initproc
            if (proc->state == PROC_ZOMBIE) {
                if (initproc->wait_state == WT_CHILD) {
                    wakeup_proc(initproc);
                }
            }
        }
    }
    // 恢复中断，退出临界区
    local_intr_restore(intr_flag);
    
    // 调度器切换到其他进程执行，当前进程将不会再运行。
    schedule();

    // 如果 schedule 返回，panic。
    panic("do_exit will not return!! %d.\n", current->pid);
}
```

do_exit函数完成的任务是：安全终止当前用户进程，在确保关键内核进程（如 `idleproc` 和 `initproc`）不会被错误退出的前提下，释放当前进程的内存资源，设置其状态为僵尸进程，保存退出码，重新将其所有子进程托付给 `initproc`，并在需要时唤醒其父进程或 `initproc`，最后交由调度器切换运行其它进程，从而完成一次完整的进程退出流程。

进程通过上述函数，可以进行状态转换：

![image.png](images/image%2013.png)

# 实现效果

![image.png](images/image%2014.png)

![image.png](images/image%2015.png)