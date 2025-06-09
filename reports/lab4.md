# LAB4 内核线程管理

## 练习1：分配并初始化一个进程控制块

在 `proc.h` 中，我们找到了进程控制块的定义：

```c
struct proc_struct {
    enum proc_state state;                      // Process state
    int pid;                                    // Process ID
    int runs;                                   // the running times of Process
    uintptr_t kstack;                           // Process kernel stack
    volatile bool need_resched;                 // bool value: need to be rescheduled to release CPU?
    struct proc_struct *parent;                 // the parent process
    struct mm_struct *mm;                       // Process's memory management field
    struct context context;                     // Switch here to run process
    struct trapframe *tf;                       // Trap frame for current interrupt
    uintptr_t cr3;                              // CR3 register: the base addr of Page Directory Table(PDT)
    uint32_t flags;                             // Process flag
    char name[PROC_NAME_LEN + 1];               // Process name
    list_entry_t list_link;                     // Process link list 
    list_entry_t hash_link;                     // Process hash list
};
```

我们的任务是分配并初始化一个进程控制块，依照指导书，需要初始化的 `proc_struct` 结构中的成员变量至少包括：`state`/`pid`/`runs`/`kstack`/`need_resched`/`parent`/`mm`/`context`/`tf`/`cr3`/`flags`/`name`。依照参考书，把 `proc_struct` 中有些成员量赋为特殊值，其他各个成员变量清零即可，特殊成员为：

```
 proc->state = PROC_UNINIT;  设置进程为"初始"态
 proc->pid = -1;             设置进程 pid 的未初始化值
 proc->cr3 = boot_cr3;       使用内核页目录表的基址
```

此时进程块还未赋值，我们初始化为：

```c
static struct proc_struct *
alloc_proc(void) {
    struct proc_struct *proc = kmalloc(sizeof(struct proc_struct));
    if (proc != NULL) {    
    //LAB4:EXERCISE1 YOUR CODE
    /*
     * below fields in proc_struct need to be initialized
     *       enum proc_state state;                      // Process state
     *       int pid;                                    // Process ID
     *       int runs;                                   // the running times of Process
     *       uintptr_t kstack;                           // Process kernel stack
     *       volatile bool need_resched;                 // bool value: need to be rescheduled to release CPU?
     *       struct proc_struct *parent;                 // the parent process
     *       struct mm_struct *mm;                       // Process's memory management field
     *       struct context context;                     // Switch here to run process
     *       struct trapframe *tf;                       // Trap frame for current interrupt
     *       uintptr_t cr3;                              // CR3 register: the base addr of Page Directory Table(PDT)
     *       uint32_t flags;                             // Process flag
     *       char name[PROC_NAME_LEN + 1];               // Process name
     */
        proc->state = PROC_UNINIT;   // 未初始化状态
        proc->pid = -1;
        proc->runs = 0;
        proc->kstack = 0;
        proc->need_resched = 0;
        proc->parent = NULL;
        proc->mm = NULL;
        memset(&(proc->context), 0, sizeof(struct context));
        proc->tf = NULL;
        proc->cr3 = boot_cr3;        // 页目录设置为内核页目录表的基址
        proc->flags = 0;
        memset(proc->name, 0, PROC_NAME_LEN);
    }
}
```

注意其中 `context` 字段和 `name` 字段等非指针字段需要显式清零，`context` 未清零可能导致进程切换时加载随机值，引发特权级错误或内核崩溃。`name` 是字符数组（非指针），未清零时可能含随机数据，导致 `strcmp` 等字符串操作越界或逻辑错误。

> 请说明 `proc_struct` 中 `struct context context` 和 `struct trapframe *tf` 成员变量含义和在本实验中的作用是啥？

`context`：进程的上下文，用于进程切换（参见 `switch.S`）。可以看到 `context` 保存了各个寄存器的值，在 uCore 中，所有的进程在内核中也是相对独立的（例如独立的内核堆栈以及上下文等等）。使用 `context` 保存寄存器的目的就在于在内核态中能够进行上下文之间的切换。实际利用 `context` 进行上下文切换的函数是在 `kern/process/switch.S` 中定义 `switch_to`。

```c
//proc.h
struct context {
    uint32_t eip;
    uint32_t esp;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uint32_t esi;
    uint32_t edi;
    uint32_t ebp;
};
```

`tf`：中断帧的指针，总是指向内核栈的某个位置：当进程从用户空间跳到内核空间时，中断帧记录了进程在被中断前的状态。当内核需要跳回用户空间时，需要调整中断帧以恢复让进程继续执行的各寄存器值。除此之外，uCore 内核允许嵌套中断。因此为了保证嵌套中断发生时 `tf` 总是能够指向当前的 `trapframe`，uCore 在内核栈上维护了 `tf` 的链，在 `trap.c::trap` 函数可以看到具体实现。

```c
struct trapframe {
    struct pushregs tf_regs;
    uint16_t tf_gs;
    uint16_t tf_padding0;
    uint16_t tf_fs;
    uint16_t tf_padding1;
    uint16_t tf_es;
    uint16_t tf_padding2;
    uint16_t tf_ds;
    uint16_t tf_padding3;
    uint32_t tf_trapno;
    /* below here defined by x86 hardware */
    uint32_t tf_err;
    uintptr_t tf_eip;
    uint16_t tf_cs;
    uint16_t tf_padding4;
    uint32_t tf_eflags;
    /* below here only when crossing rings, such as from user to kernel */
    uintptr_t tf_esp;
    uint16_t tf_ss;
    uint16_t tf_padding5;
} __attribute__((packed));
```

## 练习2：为新创建的内核线程分配资源

`kernel_thread` 函数通过调用 `do_fork` 函数完成具体内核线程的创建工作，`do_kernel` 函数会调用 `alloc_proc` 函数来分配并初始化一个进程控制块，但 `alloc_proc` 只是找到了一小块内存用以记录进程的必要信息，并没有实际分配这些资源。ucore 一般通过 `do_fork` 实际创建新的内核线程。`do_fork` 的作用是，创建当前内核线程的一个副本，它们的执行上下文、代码、数据都一样，但是存储位置不同。在这个过程中，需要给新内核线程分配资源，并且复制原进程的状态。

```c
/* 
 * do_fork - 父进程创建一个新的子进程
 * @clone_flags: 用于指导如何克隆子进程的标志位
 * @stack:       父进程的用户栈指针。如果 stack==0，表示 fork 一个内核线程
 * @tf:          陷阱帧信息，会被复制到子进程的 proc->tf 中
 */
int
do_fork(uint32_t clone_flags, uintptr_t stack, struct trapframe *tf) {
    int ret = -E_NO_FREE_PROC;
    struct proc_struct *proc;
    if (nr_process >= MAX_PROCESS) {
        goto fork_out;
    }
    ret = -E_NO_MEM;
    //LAB4:EXERCISE2 YOUR CODE
    /*
     * 一些有用的宏、函数和定义，你可以在下面的实现中使用它们：
     * 宏或函数：
     *   alloc_proc:   创建一个 proc 结构体并初始化字段（lab4:exercise1）
     *   setup_kstack: 分配 KSTACKPAGE 大小的页面作为进程的内核栈
     *   copy_mm:      根据 clone_flags 决定是复制还是共享当前进程的 mm 结构
     *                 如果 clone_flags & CLONE_VM，则"共享"；否则"复制"
     *   copy_thread:  在进程的内核栈顶设置陷阱帧，
     *                 并设置进程的内核入口点和栈
     *   hash_proc:    将 proc 加入 proc 哈希列表
     *   get_pid:      为进程分配一个唯一的 pid
     *   wakeup_proc:  设置 proc->state = PROC_RUNNABLE
     * 变量：
     *   proc_list:    进程集合的列表
     *   nr_process:   进程集合的数量
     */

    //    1. 调用 alloc_proc 分配一个 proc_struct
    //    2. 调用 setup_kstack 为子进程分配内核栈
    //    3. 根据 clone_flag 调用 copy_mm 复制或共享 mm
    //    4. 调用 copy_thread 设置 proc_struct 中的 tf 和 context
    //    5. 将 proc_struct 插入 hash_list 和 proc_list
    //    6. 调用 wakeup_proc 使新的子进程变为可运行状态
    //    7. 使用子进程的 pid 设置返回值
	
fork_out:
    return ret;

bad_fork_cleanup_kstack:
    put_kstack(proc);
bad_fork_cleanup_proc:
    kfree(proc);
    goto fork_out;
}
```

依照指导书，我需要对控制块中的每个成员变量进行正确的设置，要完成的步骤有：

- 调用 `alloc_proc`，首先获得一块用户信息块。
- 为进程分配一个内核栈。
- 复制原进程的内存管理信息到新进程（但内核线程不必做此事）
- 复制原进程上下文到新进程
- 将新进程添加到进程列表
- 唤醒新进程
- 返回新进程号

代码如下：

```c
// 1. 调用 alloc_proc 分配一个 proc_struct
if((proc = alloc_proc()) == NULL)
    goto fork_out;
proc->parent = current;
// 2. 调用 setup_kstack 为子进程分配内核栈
if(setup_kstack(proc) != 0)
    goto bad_fork_cleanup_proc;
// 3. 调用 copy_mm 根据 clone_flag 复制或共享内存管理结构
if(copy_mm(clone_flags, proc) != 0)
    goto bad_fork_cleanup_kstack;
// 4. 调用 copy_thread 在 proc_struct 中设置 tf 和 context
copy_thread(proc, stack, tf);
// 5. 将 proc_struct 插入 hash_list 和 proc_list
bool intr_flag;
local_intr_save(intr_flag);
{
    proc->pid = get_pid();
    hash_proc(proc);
    list_add(&proc_list, &(proc->list_link));
    nr_process ++;
}
local_intr_restore(intr_flag);
// 6. 调用 wakeup_proc 使新的子进程变为可运行状态
wakeup_proc(proc);
// 7. 使用子进程的 pid 设置返回值
ret = proc->pid;
```

需要说明的是，这里一定要加上 `{}` 来与 `local_intr_save/restore` 配合实现临界区保护，避免中断在 `list_add` 后、`nr_process++` 前触发，如果不加，仅第一行 `proc->pid = get_pid()` 受关中断保护。

> 请说明 ucore 是否做到给每个新 fork 的线程一个唯一的 id？请说明你的分析和理由。

查看 `get_pid()` 的实现逻辑：

```c
get_pid(void) {
    static_assert(MAX_PID > MAX_PROCESS);
    struct proc_struct *proc;
    list_entry_t *list = &proc_list, *le;
    static int next_safe = MAX_PID, last_pid = MAX_PID;
    // 以递增的方式分配一个 PID
    if (++ last_pid >= MAX_PID) {
        last_pid = 1;
        goto inside;
    }
    if (last_pid >= next_safe) {
    inside:
        next_safe = MAX_PID;
    repeat:
        // 从链表头开始遍历，遍历所有进程
        le = list;
        while ((le = list_next(le)) != list) {
            proc = le2proc(le, list_link);     // 获取进程控制块
            if (proc->pid == last_pid) {       // 是否 pid 相同，若相同，重新分配
                if (++ last_pid >= next_safe) {
                    if (last_pid >= MAX_PID) {
                        last_pid = 1;
                    }
                    next_safe = MAX_PID;
                    goto repeat;
                }
            }
            // 记录大于 last_pid 的最小 pid
            else if (proc->pid > last_pid && next_safe > proc->pid) {
                next_safe = proc->pid;
            }
        }
    }
    return last_pid;
}
```

可以看到，在 `get_pid` 中先是以递增的方式来分配 pid，然后遍历了所有进程检查是否存在 pid 冲突，若存在冲突，则重新分配 pid，故 ucore 做到了给每个新 fork 的线程一个唯一的 id。

## 实验结果

![image.png](images/image%2011.png)

![image.png](images/image%2012.png)