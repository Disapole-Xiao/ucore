# LAB6 调度器

## 练习1：使用 Round Robin 调度算法

`proc_struct` 定义增加了几行用于调度

```c
struct proc_struct {
    enum proc_state state;                      // Process state
    int pid;                                    // Process ID
    int runs;                                   // the running times of Proces
    uintptr_t kstack;                           // Process kernel stack
    volatile bool need_resched;                 // bool value: need to be rescheduled to release CPU?
    struct proc_struct *parent;                 // the parent process
    struct mm_struct *mm;                       // Process's memory management field
    struct context context;                     // Switch here to run process
    struct trapframe *tf;                       // Trap frame for current interrupt
    uintptr_t cr3;                              // CR3 register: the base addr of Page Directroy Table(PDT)
    uint32_t flags;                             // Process flag
    char name[PROC_NAME_LEN + 1];               // Process name
    list_entry_t list_link;                     // Process link list 
    list_entry_t hash_link;                     // Process hash list
};
```

### `sched_class` 中各个函数指针的用法

该结构体函数指针来定义调度器应当实现的一系列操作，每种调度算法都应实现这一组函数，我们将每个函数指针的用法标注在了注释里：

```c
struct sched_class {
    // 当前调度类的名字
    const char *name;
    // 初始化运行队列，用于设置链表、清空任务数等
    void (*init)(struct run_queue *rq);
    // 进程入队：将一个可运行的进程加入调度器的就绪队列（加锁状态下调用）
    void (*enqueue)(struct run_queue *rq, struct proc_struct *proc);
    // 进程出队：将进程从调度器的就绪队列中移除（如阻塞、退出时）
    void (*dequeue)(struct run_queue *rq, struct proc_struct *proc);
    // 选择下一个可运行进程：调度核心逻辑。不同调度策略实现不同的选择逻辑
    struct proc_struct *(*pick_next)(struct run_queue *rq);
    // 时钟 tick 处理：每个时间片减少时被调用。用于更新时间片、设置是否需要调度
    void (*proc_tick)(struct run_queue *rq, struct proc_struct *proc);
};
```

### 结合 ucore 代码描述 RR 调度算法执行过程

RR 调度算法的核心思想是将处理器时间划分为一个个固定长度的时间片，就绪队列中的每个进程轮流使用 CPU，每次最多执行一个时间片，如果一个进程在时间片用尽之前完成了执行，则立即释放 CPU，否则，等时间片用完后将该进程移到队尾，并调度下一个进程。

通过实现 `sched_class` 中的一组函数，完成了 Round Robin 调度算法的实现，涉及到进程调度时，调用其中的函数即可。

```c
struct sched_class default_sched_class = {
    .name = "RR_scheduler",      // 调度器名称
    .init = RR_init,             // 初始化函数
    .enqueue = RR_enqueue,       // 入队函数
    .dequeue = RR_dequeue,       // 出队函数
    .pick_next = RR_pick_next,   // 选择下一个运行的进程
    .proc_tick = RR_proc_tick,   // 时钟滴答处理函数
};
```

#### 初始化 RR 调度器对应的运行队列

当系统启动或调度器初始化时，调用：

```c
static void
RR_init(struct run_queue *rq) {
    list_init(&(rq->run_list));   // 初始化运行队列链表
    rq->proc_num = 0;             // 当前运行队列中的进程数置为 0
}
```

初始化函数如下，其前驱和后继都指向自己

```c
static inline void
list_init(list_entry_t *elm) {
    elm->prev = elm->next = elm;
}
```

`RR_init` 完成了初始化运行队列并将该队列进程数设为 0

#### 将一个进程加入到 RR 调度器的运行队列中

查看 `run_queue` 结构体，找到定义如下，发现其采用了双向链表来实现，

```c
struct run_queue {
    list_entry_t run_list;
    unsigned int proc_num;
    int max_time_slice;
    // For LAB6 ONLY
    skew_heap_entry_t *lab6_run_pool;
};
struct list_entry {
    struct list_entry *prev, *next;
};
```

当一个进程创建或唤醒时，它需要加入调度器的运行队列：

```c
static void
RR_enqueue(struct run_queue *rq, struct proc_struct *proc) {
    assert(list_empty(&(proc->run_link)));          // 确保进程不在其他队列中
    list_add_before(&(rq->run_list), &(proc->run_link));  // 加入到运行队列头部

    // 初始化进程的时间片
    if (proc->time_slice == 0 || proc->time_slice > rq->max_time_slice) {
        proc->time_slice = rq->max_time_slice;      // 限制最大时间片
    }

    proc->rq = rq;          // 设置进程所在的运行队列
    rq->proc_num ++;        // 队列中的进程数加一
}
```

其中，`list_add_before` 函数将 `proc->run_link` 节点插入到了 `rq->run_list` 前：

```c
static inline void
list_add_before(list_entry_t *listelm, list_entry_t *elm) {
    __list_add(elm, listelm->prev, listelm);
}
static inline void
__list_add(list_entry_t *elm, list_entry_t *prev, list_entry_t *next) {
    prev->next = next->prev = elm;
    elm->next = next;
    elm->prev = prev;
}
```

效果如下：

```c
原链表：
    A <-> B <-> C
调用：
    list_add_before(C, X)
结果：
    A <-> B <-> X <-> C
```

![b9cb94fa9346d9c98bdae8d2b1edcf0.jpg](b9cb94fa9346d9c98bdae8d2b1edcf0.jpg)

每次有新进程加入时，该算法会将其插入到 `run_list→prev` 和 `run_list` 之间，使得 `run_list` 指向的 `next` 为先进入的进程，即 `run_list` 的 `next` 始终指向先进入队列的进程，出队时则出队 `run_list` 的 `next` 指向的进程，符合 FIFO。

`RR_enqueue` 还给其设置了时间片，RR 调度算法分配时间片的思想是将处理器时间划分为一个个固定长度的时间片，就绪队列中的每个进程轮流使用 CPU，每次最多执行一个时间片。之后修改了队列和进程结构体中涉及到了的其他属性值（`proc->rq`、`rq->proc_num`）

#### 从运行队列中移除一个进程

当一个进程阻塞、退出等，需要从调度器中移除：

```c
static void
RR_dequeue(struct run_queue *rq, struct proc_struct *proc) {
    assert(!list_empty(&(proc->run_link)) && proc->rq == rq);  // 保证进程在此队列中
    list_del_init(&(proc->run_link));   // 从链表中删除并重新初始化节点
    rq->proc_num --;                    // 队列中的进程数减一
}
```

其中，`list_del_init` 函数完成了从链表中删除并重新初始化节点的工作

```c
static inline void
list_del_init(list_entry_t *listelm) {
    list_del(listelm);
    // 初始化进程节点而非运行队列
    list_init(listelm);
}
static inline void
list_del(list_entry_t *listelm) {
    __list_del(listelm->prev, listelm->next);
}
static inline void
__list_del(list_entry_t *prev, list_entry_t *next) {
    prev->next = next;
    next->prev = prev;
}
```

效果如下：

```c
原链表：
    A <-> B <-> C
调用：
    list_del(B)
结果：
    A <-> C
```

#### 从运行队列中选择下一个要运行的进程

```c
static struct proc_struct *
RR_pick_next(struct run_queue *rq) {
    list_entry_t *le = list_next(&(rq->run_list));  // 获取队头元素
    if (le != &(rq->run_list)) {
        return le2proc(le, run_link);               // 转换为 proc_struct 指针
    }
    return NULL;    // 若无进程可运行，返回 NULL
}
static inline list_entry_t *
list_next(list_entry_t *listelm) {
    return listelm->next;
}
```

可以看到，`list_next` 函数直接用 `rq->run_list` 的 `next` 指向的进程节点作为下一个要运行的进程，若其指向 `run_list`，则说明无进程可运行，返回 `NULL`（初始化时，队列头尾均指向 `run_list`），若不是，则完成了相应的 `list_entry_t` 转化为 `proc_struct` 结构体的任务并返回。RR 调度算法中，就绪队列中的每个进程轮流使用 CPU，这体现了 RR 的先进先出（FIFO）轮转原则。

#### 时钟滴答处理函数

```c
static void
RR_proc_tick(struct run_queue *rq, struct proc_struct *proc) {
    if (proc->time_slice > 0) {
        proc->time_slice --;    // 时间片递减
    }
    if (proc->time_slice == 0) {
        proc->need_resched = 1; // 时间片用尽，标记需要重新调度
    }
}
```

每次时钟 tick 时，当前运行进程的 `time_slice--`，如果 `time_slice == 0`，则设置 `proc->need_resched = 1`，表示需要触发调度

### 简要说明设计实现"多级反馈队列调度算法"

设计时，依照 `sched_class` 提供的一组函数来实现：

- 初始化时，初始化多个队列，即每一级的链表结构，并初始化每一级的进程数为 0，同时设置每一级的最大时间片（可以随级别增加而递增）。
- 入队时，将一个进程加入到它当前优先级队列中。可以设计函数先获取该进程当前的优先级，再依照该优先级队列的调度算法将其插入队列，并更新队列和进程结构体中相应的其他属性。
- 出队时，将进程从其所在优先级的运行队列中移除。先找到该进程所在优先级的队列，再从相应队列删除该节点。
- 选择下一个运行的进程时，选择策略是"最高优先级非空队列的队头进程"，可以从高到低优先级依次查找第一个非空的队列，找到队头节点，返回对应的 `proc_struct` 指针。如果所有队列为空，返回 `NULL`。
- 时钟 tick 时，将当前运行进程的 `time_slice` 减 1。如果时间片耗尽，将进程从当前队列出队，如果其不在最低优先级队列，则将其降级到下一优先级并重新入队，同时设置 `need_resched = 1`，触发调度器重新选择进程。

## 练习2：实现 Stride Scheduling 调度算法

Stride Scheduling 调度算法主要思想如下：

1. 为每个 runnable 的进程设置一个当前状态 stride，表示该进程当前的调度权。另外定义其对应的 pass 值，表示对应进程在调度后，stride 需要进行的累加值。
2. 每次需要调度时，从当前 runnable 态的进程中选择 stride 最小的进程调度。
3. 对于获得调度的进程 P，将对应的 stride 加上其对应的步长 pass（只与进程的优先权有关系）。
4. 在一段固定的时间之后，回到 2. 步骤，重新调度当前 stride 最小的进程。可以证明，如果令 `P.pass = BigStride / P.priority` 其中 `P.priority` 表示进程的优先权（大于 1），而 `BigStride` 表示一个预先定义的大常数，则该调度方案为每个进程分配的时间将与其优先级成正比。

调度器类定义已在 `default_sched_stride_c` 中给出，实现 `sched_class` 提供的一组函数并注释掉 RR 的 `sched_class` 即可：

```c
/*  stride 调度器类定义 */
struct sched_class default_sched_class = {
     .name = "stride_scheduler",
     .init = stride_init,
     .enqueue = stride_enqueue,
     .dequeue = stride_dequeue,
     .pick_next = stride_pick_next,
     .proc_tick = stride_proc_tick,
};
```

在上述的实现描述中，对于每一次 `pick_next` 函数，我们都需要完整地扫描来获得当前最小的 stride 及其进程。这在进程非常多的时候是非常耗时和低效的，考虑到其调度选择于优先队列的抽象逻辑一致，我们考虑使用优化的优先队列数据结构实现该调度。

本实验中提供的优先队列接口如下：

```c
// 优先队列节点的结构
typedef struct skew_heap_entry  skew_heap_entry_t;
// 初始化一个队列节点
void skew_heap_init(skew_heap_entry_t *a);
// 将节点 b 插入至以节点 a 为队列头的队列中去，返回插入后的队列
skew_heap_entry_t  *skew_heap_insert(skew_heap_entry_t  *a,
 skew_heap_entry_t  *b, compare_f comp);
// 将节点 b 插入从以节点 a 为队列头的队列中去，返回删除后的队列
skew_heap_entry_t  *skew_heap_remove(skew_heap_entry_t  *a, skew_heap_entry_t  *b, compare_f comp);
```

在 Lab6 中，运行池（`lab6_run_pool`）被实现为一个斜堆（skew heap），用来作为"带优先级的运行任务池"，支持高效选出优先级最高的任务来执行。斜堆的特点是，父节点的优先级 ≥ 子节点。

```c
struct run_queue {
    list_entry_t run_list;
    unsigned int proc_num;
    int max_time_slice;
    // For LAB6 ONLY
    skew_heap_entry_t *lab6_run_pool;
};
struct skew_heap_entry {
     struct skew_heap_entry *parent, *left, *right;
};
```

### init

- 初始化调度器类的信息（如果有的话）。

- 初始化当前的运行队列为一个空的容器结构。（比如和 RR 调度算法一样，初始化为一个有序列表）

参考 RR 调度算法和注释，我们写出代码如下：

```c
/*
 * stride_init 初始化运行队列 rq，正确设置成员变量包括：
 *
 *   - run_list：初始化后应为空链表
 *   - lab6_run_pool：初始化为 NULL
 *   - proc_num：设置为 0
 *   - max_time_slice：不需要在此初始化，由调用者赋值
 *
 * 提示：参考 libs/list.h 中的链表操作函数
 */
static void
stride_init(struct run_queue *rq) {
     /* LAB6：你的代码 
      * (1) 初始化就绪进程列表：rq->run_list
      * (2) 初始化运行池：rq->lab6_run_pool
      * (3) 设置进程数量：rq->proc_num 为 0       
      */
     list_init(&(rq->run_list));
     rq->lab6_run_pool = NULL;
     rq->proc_num = 0;
}
```

### enqueue

- 初始化刚进入运行队列的进程 proc 的 stride 属性。

- 将 proc 插入放入运行队列中去（注意：这里并不要求放置在队列头部）。

`skew_heap_insert` 的作用是将节点 b 插入至以节点 a 为队列头的队列中去，返回插入后的队列，注意 `run_queue` 结构体中 `lab6_run_pool` 是指针，而 `proc_struct` 中 `lab6_run_pool` 不是，故其作为参数时前面需要加上 `&`，比较函数已在 `default_sched_stride.c` 其他部分给出（`proc_stride_comp_f`）。剩下代码参考 RR 调度算法和注释写出：

```c
/*
 * stride_enqueue 将进程 proc 插入运行队列 rq。
 * 该函数应验证/初始化 proc 的相关成员，然后将 lab6_run_pool 节点
 * 加入队列（此处使用优先队列）。同时需要更新 rq 结构的元数据。
 *
 * proc->time_slice 表示分配给进程的时间片，应设置为 rq->max_time_slice。
 * 
 * 提示：参考 libs/skew_heap.h 中的优先队列操作函数
 */
static void
stride_enqueue(struct run_queue *rq, struct proc_struct *proc) {
     /* LAB6：你的代码 
      * (1) 将 proc 正确插入 rq
      * 注意：可以使用 skew_heap 或 list。重要函数：
      *         skew_heap_insert：向斜堆插入条目
      *         list_add_before：向链表尾部插入条目   
      * (2) 重新计算 proc->time_slice
      * (3) 设置 proc->rq 指向 rq
      * (4) 增加 rq->proc_num 计数
      */
     skew_heap_insert(rq->lab6_run_pool, &(proc->lab6_run_pool), proc_stride_comp_f);
     if (proc->time_slice == 0 || proc->time_slice > rq->max_time_slice) {
         proc->time_slice = rq->max_time_slice;
     }
     proc->rq = rq;
     rq->proc_num++;
}
```

### dequeue

- 从运行队列中删除相应的元素。

`skew_heap_remove` 的作用是将节点 b 插入从以节点 a 为队列头的队列中去，返回删除后的队列，参考 RR 调度算法和注释写出：

```c
/*
 * stride_dequeue 从运行队列 rq 中移除进程 proc，
 * 通过 skew_heap_remove 操作完成。记得更新 rq 结构。
 *
 * 提示：参考 libs/skew_heap.h 中的优先队列操作函数
 */
static void
stride_dequeue(struct run_queue *rq, struct proc_struct *proc) {
     /* LAB6：你的代码 
      * (1) 从 rq 正确移除 proc
      * 注意：可以使用 skew_heap 或 list。重要函数：
      *         skew_heap_remove：从斜堆移除条目
      *         list_del_init：从链表移除条目
      */
     skew_heap_remove(rq->lab6_run_pool, &(proc->lab6_run_pool), proc_stride_comp_f);
     rq->proc_num--;
}
```

### pick next

- 返回其中 stride 值最小的对应进程。

- 更新对应进程的 stride 值，即 `pass = BIG_STRIDE / P->priority; P->stride += pass`。

`rq->lab6_run_pool` 指向的是当前就绪队列中 stride 值最小的进程对应的堆节点，`le2proc` 宏的作用是找回 `rq->lab6_run_pool` 所属的 `proc_struct *`，也就是恢复"这个节点代表哪个进程"。
其他部分代码按照注释编写即可，根据指导手册，`Priority > 1`，所以这里没有考虑 `p->lab6_priority=0` 的情况。

```c
/*
 * stride_pick_next 从运行队列中选择 stride 值最小的元素，
 * 返回对应的进程指针。进程指针通过 le2proc 宏计算得到，
 * 参见 kern/process/proc.h 定义。如果队列为空则返回 NULL。
 *
 * 选择进程结构后，记得更新其 stride 属性：
 * (stride += BIG_STRIDE / priority)
 *
 * 提示：参考 libs/skew_heap.h 中的优先队列操作函数
 */
static struct proc_struct *
stride_pick_next(struct run_queue *rq) {
     /* LAB6：你的代码 
      * (1) 获取 stride 值最小的 proc_struct 指针 p
             (1.1) 如果使用 skew_heap，可用 le2proc 从 rq->lab6_run_pool 获取 p
             (1.2) 如果使用链表，需要遍历链表找到最小 stride 值的 p
      * (2) 更新 p 的 stride 值：p->lab6_stride
      * (3) 返回 p
      */
     if(rq->lab6_run_pool!=NULL)
          return NULL;
     struct proc_struct *p = le2proc(rq->lab6_run_pool, lab6_run_pool);
		 p->lab6_stride += BIG_STRIDE / p->lab6_priority;
     return p;
}
```

### proc tick

- 检测当前进程是否已用完分配的时间片。如果时间片用完，应该正确设置进程结构的相关标记来引起进程切换。

- 一个 process 最多可以连续运行 `rq.max_time_slice` 个时间片。

参考 RR 调度算法和注释即可写出：

```c
/*
 * stride_proc_tick 处理当前进程的 tick 事件。
 * 应检查当前进程的时间片是否耗尽，并更新 proc 结构。
 * proc->time_slice 表示剩余时间片，
 * proc->need_resched 是进程切换的标志变量。
 */
static void
stride_proc_tick(struct run_queue *rq, struct proc_struct *proc) {
     /* LAB6：你的代码 */
    if (proc->time_slice > 0) {
        proc->time_slice --;
    }
    if (proc->time_slice == 0) {
        proc->need_resched = 1;
    }
}
```

### BIG_STRIDE 选择

令 `PASS_MAX` 为进程在一个时间片中能够增加的最大步进步长，对每次 Stride 调度器的调度步骤中，有其最大的步进值 `STRIDE_MAX` 和最小的步进值 `STRIDE_MIN` 之差：

`STRIDE_MAX - STRIDE_MIN <= PASS_MAX`

有了该结论，在加上之前对优先级有 `Priority > 1` 限制，我们有 `STRIDE_MAX - STRIDE_MIN <= BIG_STRIDE`，于是我们只要将 `BigStride` 取在某个范围之内，即可保证对于任意两个 Stride 之差都会在机器整数表示的范围之内。

查看优先队列比较函数

```c
/* 用于比较两个 skew_heap_node_t 及其对应进程的函数 */
static int
proc_stride_comp_f(void *a, void *b)
{
     struct proc_struct *p = le2proc(a, lab6_run_pool);
     struct proc_struct *q = le2proc(b, lab6_run_pool);
     int32_t c = p->lab6_stride - q->lab6_stride;
     if (c > 0) return 1;
     else if (c == 0) return 0;
     else return -1;
}
```

`lab6_stride` 是 `uint32_t`，无符号 32 位整数，范围是 0 到 4,294,967,295，即从 0 到 2^32-1，（十六进制表示为 0x00000000 到 0xFFFFFFFF），可以看到，在比较函数里，是用 `lab6_stride` 的有符号 32 位整数形式来比较，范围是 -2,147,483,648 到 2,147,483,647，即 -2^31-1 到 2^31（十六进制表示为 0x80000000 到 0x7FFFFFFF）。

通过之前 `STRIDE_MAX - STRIDE_MIN <= BIG_STRIDE` 的结论，当两个 stride 值之差小于等于 0x7FFFFFFF 时，即 `int32_t` 的最大值时，在将其转换为 `int32_t` 后，结果值不会超出 `int32_t` 的表示范围（即不会发生溢出），并且正负号表示的大小关系正确。

故我们这里设定 `BIG_STRIDE` 为 0x7FFFFFFF。

## 实验结果

![image.png](images/image%2016.png)

![image.png](images/image%2017.png)