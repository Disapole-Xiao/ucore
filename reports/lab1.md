# LAB1 系统软件启动过程

## 练习2：使用 qemu 执行并调试 lab1 中的软件

```bash
 $ cd labcodes_answer/lab1_result/
 $ make lab1-mon
```

进入到 `lab1_result` 目录下，使用 `less` 命令查看 `Makefile` 里的 `lab1-mon` 功能

![image.png](images/image.png)

第一个功能为让 qemu 把它执行的指令给记录下来放到 `q.log`，第二个功能为与 gdb 结合来可以调试执行中的 Bootloader

![image.png](images/image%201.png)

第二行表示 qemu 和 gdb 之间使用网络端口 1234 进行通讯，第四行表示从 `0x7c00` 开始跟踪代码运行，第六行表示获取当前 `$pc`（程序计数器）的值，并从该地址开始，反汇编 **2 条** 机器指令，并以汇编代码形式显示。

![image.png](images/image%202.png)

显示了对应的两条反汇编

![image.png](images/image%203.png)

在 `boots/bootasm.S` 中看到对应的代码比较，发现是一样的

![image.png](images/image%204.png)

![image.png](images/image%205.png)

使用 `continue` 命令，ucore 运行

## 练习4：分析 bootloader 加载 ELF 格式的 OS 的过程

通过阅读 `bootmain.c`，了解 bootloader 如何加载 ELF 文件。通过分析源代码和通过 qemu 来运行并调试 bootloader&OS

> bootloader 如何读取硬盘扇区的？

首先了解到磁盘 IO 地址和对应功能如下：
    
| IO 地址 | 功能 |
| --- | --- |
| 0x1f0 | 读数据，当 0x1f7 不为忙状态时，可以读。 |
| 0x1f2 | 要读写的扇区数，每次读写前，你需要表明你要读写几个扇区。最小是 1 个扇区 |
| 0x1f3 | 如果是 LBA 模式，就是 LBA 参数的 0-7 位 |
| 0x1f4 | 如果是 LBA 模式，就是 LBA 参数的 8-15 位 |
| 0x1f5 | 如果是 LBA 模式，就是 LBA 参数的 16-23 位 |
| 0x1f6 | 第 0~3 位：如果是 LBA 模式就是 24-27 位；第 4 位：为 0 主盘，为 1 从盘 |
| 0x1f7 | 状态和命令寄存器。操作时先给命令，再读取，如果不是忙状态就从 0x1f0 端口读数据 |

参看 `boot/bootmain.c` 中的 `readsect` 函数实现，得到读一个扇区流程如下：

1. 等待磁盘准备好
2. 发出读取扇区的命令
3. 等待磁盘准备好
4. 把磁盘扇区数据读到指定内存

```c
static void
readsect(void *dst, uint32_t secno) {
    // 等待磁盘准备好
    waitdisk();
    // 发出读取扇区的命令
    outb(0x1F2, 1);                         // 表明需要读写一个扇区
    // 扇区编号为32位，一次只能传输四位，分四个端口传输给扇区
    outb(0x1F3, secno & 0xFF);              
    outb(0x1F4, (secno >> 8) & 0xFF);
    outb(0x1F5, (secno >> 16) & 0xFF);
    outb(0x1F6, ((secno >> 24) & 0xF) | 0xE0);
    outb(0x1F7, 0x20);                      // 发出读指令：0x20

    // 等待磁盘准备好
    waitdisk();

    // 把磁盘扇区数据读到指定内存
    insl(0x1F0, dst, SECTSIZE / 4);
}
```

> bootloader 是如何加载 ELF 格式的 OS？

ELF header 在文件开始处描述了整个文件的组织。ELF 的文件头包含整个执行文件的控制结构，其定义为：

```c
struct elfhdr {
  uint magic;  // must equal ELF_MAGIC
  uchar elf[12];
  ushort type;
  ushort machine;
  uint version;
  uint entry;  // 程序入口的虚拟地址
  uint phoff;  // program header 表的位置偏移
  uint shoff;
  uint flags;
  ushort ehsize;
  ushort phentsize;
  ushort phnum; // program header 表中的入口数目
  ushort shentsize;
  ushort shnum;
  ushort shstrndx;
};
```

其中提到的 program header 描述了与程序执行直接相关的目标文件结构信息，用来在文件中定位各个段的映像，同时包含其他一些用来为程序创建进程映像所必需的信息。可执行文件的程序头部是一个 program header 结构的数组， 每个结构描述了一个段或者系统准备程序执行所必需的其它信息，其定义如下：

```c
struct proghdr {
  uint type;   // 段类型
  uint offset;  // 段相对文件头的偏移值
  uint va;     // 段的第一个字节将被放到内存中的虚拟地址
  uint pa;
  uint filesz;
  uint memsz;  // 段在内存映像中占用的字节数
  uint flags;
  uint align;
};
```

目标文件的 "段" 包含一个或者多个 "节区"（section） ，也就是 "段内容（Segment Contents）" 。程序头部仅对于可执行文件和共享目标文件有意义。可执行目标文件在 ELF 头部的 `e_phentsize` 和 `e_phnum` 成员中给出其自身程序头部的大小。

通过 `bootmain.c` 可以看到，根据 `elfhdr` 和 `proghdr` 的结构描述，bootloader 就可以完成对 ELF 格式的 ucore 操作系统的加载过程。

```c
void bootmain(void) {
    // read the 1st page off disk
    readseg((uintptr_t)ELFHDR, SECTSIZE * 8, 0);

    // is this a valid ELF?
    if (ELFHDR->e_magic != ELF_MAGIC) {
        goto bad;
    }

    struct proghdr *ph, *eph;

    // load each program segment (ignores ph flags)
    ph = (struct proghdr *)((uintptr_t)ELFHDR + ELFHDR->e_phoff);
    eph = ph + ELFHDR->e_phnum;
    for (; ph < eph; ph ++) {
        readseg(ph->p_va & 0xFFFFFF, ph->p_memsz, ph->p_offset);
    }

    // call the entry point from the ELF header
    // note: does not return
    ((void (*)(void))(ELFHDR->e_entry & 0xFFFFFF))();

bad:
    outw(0x8A00, 0x8A00);
    outw(0x8A00, 0x8E00);

    /* do nothing */
    while (1);
}
```

## 练习5：实现函数调用堆栈跟踪函数

### 基础知识

- **EIP**：控制程序执行流程，指向下一条指令，即当前函数的返回地址。
- **ESP**：其内存放着一个指针，该指针永远指向系统栈最上面一个栈帧的栈顶。
- **EBP**：其内存放着一个指针，该指针永远指向系统栈最上面一个栈帧的底部。

几乎所有本地编译器都会在每个函数体之前插入类似如下的汇编指令：

```c
pushl   %ebp
movl   %esp , %ebp
```

栈结构如下：

```
+|  栈底方向     | 高位地址
 |    ...       |
 |    ...       |
 |  参数3        |
 |  参数2        |
 |  参数1        |
 |  返回地址     |
 |  上一层[ebp]  | <-------- [ebp]
 |  局部变量     |  低位地址
```

可以看出，`ebp` 寄存器中存储着栈中的一个地址（原 `ebp` 入栈后的栈顶），从该地址为基准，向上（栈底方向）能获取返回地址、参数值，向下（栈顶方向）能获取函数局部变量值，而该地址处又存储着上一层函数调用时的 `ebp` 值。

### 实验要求

输出的内容有：**ebp**（当前栈帧的基址指针）、**eip**（当前函数中下一条将要执行的指令地址），**args**（当前函数调用时传递的参数，显示 4 个参数），**源代码位置**（指当前 eip（返回地址）对应的源代码位置和函数信息）

### 实现思路

观察需要得到的输出，发现每一帧里 ebp、eip 地址在不断增大，由于栈往低地址增长，所以我们需要从栈顶向栈底来输出每一帧的所需信息，我们首先用 `read_ebp()`、`read_eip()` 函数来获得当前栈顶的帧对应信息。

由之前的栈结构图可知，从现 ebp 往上，我们可以看出 eip（返回地址）在 `ebp+1` 的位置，即 `ebp[1]`，原 ebp 在现 ebp 指向的位置，即 `ebp[0]`，由 ebp 向上能获取参数值，其在 `ebp+2` 的位置，我们按照示例输出打印 4 个参数值，接下来，我们只差获取源代码位置，我们使用 `print_debuginfo()` 函数来得到，注意这里需要传入的参数是 `eip-1`，而不是 `eip`，因为 eip 指向的是函数返回后的下一条指令，我们需要显示的是调用发生的位置。由此循环，我们可以倒退得到每一个栈帧的信息。

按照思路，写下对应代码如下：

![image.png](images/image%206.png)

实现效果如下：

![image.png](images/image%207.png)

### 最后一行的含义

最后一行的堆栈帧信息表明这已经到了操作系统启动流程的最底层，没有函数调用该函数。

## 练习6：完善中断初始化和处理

### 中断描述符表

在 `mmu.h` 中可以找到，中断描述符表项定义如下：

```c
struct gatedesc {
    unsigned gd_off_15_0 : 16;        // low 16 bits of offset in segment
    unsigned gd_ss : 16;            // segment selector
    unsigned gd_args : 5;            // # args, 0 for interrupt/trap gates
    unsigned gd_rsv1 : 3;            // reserved(should be zero I guess)
    unsigned gd_type : 4;            // type(STS_{TG,IG32,TG32})
    unsigned gd_s : 1;                // must be 0 (system)
    unsigned gd_dpl : 2;            // descriptor(meaning new) privilege level
    unsigned gd_p : 1;                // Present
    unsigned gd_off_31_16 : 16;        // high bits of offset in segment
};
```

一个表项占 8 个字节，其中段选择子和偏移地址用来代表中断处理程序入口地址，具体先通过选择子查找 GDT 对应段描述符，得到该代码段的基址，基址加上偏移地址为中断处理程序入口地址。

### idt_init

`SETGATE` 定义宏：

```c
#define SETGATE(gate, istrap, sel, off, dpl) {            \
    (gate).gd_off_15_0 = (uint32_t)(off) & 0xffff;        \
    (gate).gd_ss = (sel);                                \
    (gate).gd_args = 0;                                    \
    (gate).gd_rsv1 = 0;                                    \
    (gate).gd_type = (istrap) ? STS_TG32 : STS_IG32;    \
    (gate).gd_s = 0;                                    \
    (gate).gd_dpl = (dpl);                                \
    (gate).gd_p = 1;                                    \
    (gate).gd_off_31_16 = (uint32_t)(off) >> 16;        \
}
```

五个参数的含义分别为：

- `gate`：中断描述符
- `istrap`：标识是中断还是系统调用，唯一区别在于，中断会清空 IF 标志，不允许被打断
- `sel`：表示段选择子
- `off`：偏移量（`__vectors` 里面的内容）
- `dpl`：访问权限

可以看出，`SETGATE` 填充了 `gatedesc` 数组，可以生成一个中断描述符表项。

我们的任务是利用 `SETGATE` 填充 `idt` 数组内容，即依次对所有中断入口进行初始化。描述符传入 `idt` 数组每一项，`istrap` 设置为 0，`sel` 段选择子为 `GD_KTEXT`（因为 `gdt_init` 时候是这个数），`off` 偏移量就是传入 `vector` 的内容（`vector` 定义在 `vector.S`），权限设置为内核态。再用 `SETGATE` 设置特定中断门，最后用 `lidt(&idt_pd)` 加载中断描述符表寄存器（IDTR），完成任务。

![image.png](images/image%208.png)

### trap

`TICK_NUM` 定义为 100，有中断产生时，`ticks+1`，如果中断数累计是 `TICK_NUM` 的倍数（操作系统每遇到 100 次时钟中断时），调用 `print_ticks` 子程序，向屏幕上打印一行文字 "100 ticks"。按照注释编写即可。

![image.png](images/image%209.png)

实现效果如下：

![image.png](images/image%2010.png)
