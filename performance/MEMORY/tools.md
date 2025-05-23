术语

■ 主内存：也称为物理内存，它描述了计算机的快速数据存储区域，通常以 DRAM 的形式提供。
■ 虚拟内存：主内存的抽象，它（几乎）是无限的，并且是无争用的。虚拟内存不是真正的内存。
■ 驻留内存：当前驻留在主内存中的内存。
■ 匿名内存：没有文件系统位置或路径名的内存。它包括进程地址空间（称为堆）的工作数据。
■ 地址空间：内存上下文。每个进程和内核都有虚拟地址空间。
■ Segment：为特定目的而标记的虚拟内存区域，例如用于存储可执行或可写页面。
■ 指令文本：指内存中的 CPU 指令，通常位于一个段中。
■ OOM：当内核检测到可用内存不足时，内存不足。
■ 页：操作系统和 CPU 使用的内存单位。从历史上看，它是 4 KB 或 8 KB。现代处理器对较大的尺寸具有多种页面大小支持。
■ Page fault：无效的内存访问。这些是使用按需虚拟内存时发生的正常情况。
■ 分页：主内存和存储设备之间的页面传输。
■ 交换：Linux 使用术语 swapping 来指代到交换设备的匿名分页（交换页的传输）。在 Unix 和其他操作系统中，交换是主内存和交换设备之间整个进程的传输。本书使用了该术语的 Linux 版本。
■ 交换：用于分页匿名数据的磁盘区域。它可以是存储设备上的一个区域（也称为物理交换设备）或文件系统文件（称为交换文件）。一些工具使用术语 swap 来指代虚拟内存（这令人困惑且不正确）。


主内存利用率可以计算为已用内存与总内存。文件系统缓存使用的内存可以被视为未使用，因为它可供应用程序重用。

如果内存需求超过主内存量，则主内存将达到饱和。然后，操作系统可以通过使用分页、进程交换（如果支持）以及在 Linux 上使用 OOM killer（稍后介绍）来释放内存。这些活动中的任何一个都是主内存饱和的指标。

■ 利用率：正在使用的内存量和可用内存量。应检查物理内存和虚拟内存。
■ 饱和度：执行页面扫描、分页、交换和 Linux OOM 杀手牺牲的程度，作为缓解内存压力的措施。
■ 错误：软件或硬件错误


对于内存，描述使用情况包括确定内存的使用位置和数量：

■ 系统范围的物理和虚拟内存利用率 
■ 饱和程度：交换和 OOM 终止 
■ 内核和文件系统缓存内存使用情况 
■ 每个进程的物理和虚拟内存使用情况 
■ 内存资源控制的使用情况（如果存在）


这里列出了其他特征作为需要考虑的问题，在彻底研究记忆问题时，也可以作为检查表：

■ 应用程序的工作集大小 （WSS） 是多少？
■ 内核内存用在哪儿？每块板？
■ 有多少文件系统缓存是活动的，而不是非活动的？
■ 进程内存用于何处（指令、缓存、缓冲区、对象等）？
■ 为什么进程要分配内存（调用路径）？
■ 为什么内核要分配内存（调用路径）？
■ 进程库映射有什么奇怪的地方（例如，随时间变化）？
■ 哪些进程正在积极换出？
■ 以前换掉了哪些进程？
■ 进程或内核是否存在内存泄漏？
■ 在 NUMA 系统中，内存在内存节点之间的分布情况如何？
■ IPC 和内存停顿周期率是多少？
■ 内存总线的平衡程度如何？
■ 与远程内存 I/O 相比，执行了多少本地内存 I/O？


它们通常按照可用内存减少的使用顺序排列。

这些方法是：
■ Free list：未使用（也称为空闲内存）且可立即分配的页面列表。这通常实现为多个免费页面列表，每个区域组 （NUMA） 一个。
■ Page cache：文件系统缓存。名为 swappiness 的可调参数设置系统应倾向于从页面高速缓存中释放内存而不是交换的程度
■ 交换：这是由分页守护程序 kswapd 进行的分页，它查找最近未使用的页面以添加到空闲列表中，包括应用程序内存。这些文件被分页出来，这可能涉及写入基于文件系统的交换文件或交换设备。当然，仅当配置了交换文件或设备时，此选项才可用。
■ 收缩：当超过内存不足阈值时，可以指示内核模块和内核 slab 分配器立即释放任何可以轻松释放的内存。这也称为收缩。
■ OOM killer：内存不足杀手将通过查找并杀死一个牺牲进程来释放内存，该进程使用 select_bad_process（） 找到，然后通过调用 oom_kill_process（） 杀死。这可能会在系统日志 （/var/log/messages） 中记录为 “Out of memory： Kill pro cess” 消息。


内存的关键指标是

■ 利用率：使用百分比，可从可用内存推断 
■ 饱和度：交换、OOM 终止

请检查 static 配置的以下方面：

■ 总共有多少主内存？
■ 应用程序配置为使用多少内存（它们自己的配置）
■ 应用程序使用哪些内存分配器？
■ 主内存的速度是多少？它是最快的类型 （DDR5） 吗？
■ 主内存是否经过全面测试（例如，使用 Linux memtester）
■ 操系统架构是什么？NUMA，UMA？
■ 操作系统是否能识别 NUMA？它是否提供 NUMA 可调参数？
■ 内存是附加到同一个插槽，还是在多个插槽之间分配？
■ 存在多少内存总线
■ CPU 缓存的数量和大小是多少？TLB？
■ BIOS 设置是什么？
■ 是否配置并使用了大型页面？
■ 超额使用可用且已配置
■ 还有哪些其他系统内存可调参数正在使用中？
■ 是否有软件施加的内存限制（资源控制）？


perf:
系统范围内堆栈跟踪的样本页面错误（RSS 增长），直到 Ctrl-C：
# perf record -e page-faults -a -g

记录 PID 1843 的所有页面错误和堆栈跟踪，持续 60 秒：
# perf record -e page-faults -c 1 -p 1843 -g -- sleep 60

通过 brk（2） 记录堆增长，直到 Ctrl-C：
# perf record -e syscalls:sys_enter_brk -a -g

在 NUMA 系统上录制页面迁移
# perf record -e migrate:mm_migrate_pages -a

对所有 kmem 事件进行计数，每秒打印一次报告：
# perf stat -e 'kmem:*' -a -I 1000

对所有 vmscan 事件进行计数，每秒打印一份报告：
# perf stat -e 'vmscan:*' -a -I 1000

计算所有内存压缩事件，每秒打印一次报告：
# perf stat -e 'compaction:*' -a -I 1000

使用堆栈跟踪跟踪 kswapd 唤醒事件，直到 Ctrl-C：
# perf record -e vmscan:mm_vmscan_wakeup_kswapd -ag

分析给定命令的内存访问：
# perf mem record command

总结内存配置文件：
# perf mem report


bpftrace:
按用户堆栈和进程对 libc malloc（） 请求字节数求和（开销高）：
#  bpftrace -e 'uprobe:/lib/x86_64-linux-gnu/libc.so.6:malloc {
    @[ustack, comm] = sum(arg0); }'
  
PID 181 的用户堆栈对 libc malloc（） 请求字节数求和 （高开销）
# bpftrace -e 'uprobe:/lib/x86_64-linux-gnu/libc.so.6:malloc /pid == 181/ {
    @[ustack] = sum(arg0); 
}'

将 PID 181 的用户堆栈的 libc malloc（） 请求字节数显示为 2 的幂直方图（高开销）：
#  bpftrace -e 'uprobe:/lib/x86_64-linux-gnu/libc.so.6:malloc /pid == 181/ 
{
    @[ustack] = hist(arg0); 
}'

按内核堆栈跟踪对内核 kmem 缓存分配字节数求和：
bpftrace -e 't:kmem:kmem_cache_alloc { @bytes[kstack] = sum(args->bytes_alloc); }'

按代码路径对进程堆扩展 （brk（2）） 进行计数
#  bpftrace -e 'tracepoint:syscalls:sys_enter_brk { @[ustack, comm] = count(); }'

按进程对页面错误进行计数：
# bpftrace -e 'software:page-fault:1 { @[comm, pid] = count(); }'

按用户级堆栈跟踪对用户页面错误进行计数
# bpftrace -e 't:exceptions:page_fault_user { @[ustack, comm] = count(); }'
按跟踪点对 vmscan作进行计数
# bpftrace -e 'tracepoint:vmscan:* { @[probe] = count(); }'

按进程计数 swapins：
# bpftrace -e 'kprobe:swap_readpage { @[comm, pid] = count(); }'

计数页面迁移：
# bpftrace -e 'tracepoint:migrate:mm_migrate_pages { @ = count(); }'

跟踪压缩事件：
# bpftrace -e 't:compaction:mm_compaction_begin { time(); }'

在 libc 中列出 USDT 探针：
# bpftrace -l 'usdt:/lib/x86_64-linux-gnu/libc.so.6:*'

列出内核 kmem 跟踪点：
# bpftrace -l 't:kmem:*'

列出所有内存子系统 （mm） 跟踪点：
# bpftrace -l 't:*:mm_*'