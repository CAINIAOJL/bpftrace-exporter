1. mpstat -P ALL 1  ->  json 
2. vmstat 
3. uptime 

vmstat
■ r：运行队列长度 - 可运行线程的总数 
■ us： 用户时间百分比 
■ sy： 系统时间（内核） 百分比 
■ id： 空闲百分比 
■ wa： 等待 I/O 百分比，用于测量线程在磁盘上被阻止时的 CPU 空闲情况 I/O 
■ st：被盗百分比，对于虚拟化环境，显示为其他租户提供服务所花费的 CPU 时间

mpstat
■ CPU：逻辑 CPU ID，或全部用于摘要 
■ %usr：用户时间，不包括 %nice 
■ %nice：优先级较高的进程的用户时间 
■ %sys：系统时间（内核） 
■ %iowait：I/O 等待 
■ %irq：硬件中断 CPU 使用率 
■ %soft：软件中断 CPU 使用率 
■ %steal：为其他租户提供服务所花费的时间 
■ %guest：在来宾虚拟机中花费的 CPU 时间 
■ %gnice： 运行 niced 客户机 
■ %idle 的 CPU 时间：空闲

描述 CPU 工作负载的基本属性是：
■ CPU 负载平均值（利用率饱和） 
■ 用户时间与系统时间的比率 
■ 系统调用速率 
■ 自愿上下文切换速率 
■ 中断速率

检查表：
■ 系统范围内的 CPU 利用率是多少？每个 CPU？每个核心？
■ CPU 负载的并行度如何？它是单线程的吗？有多少个线程？
■ 哪些应用程序或用户正在使用 CPU？多少？
■ 哪些内核线程正在使用 CPU？多少？
■ 中断的 CPU 使用率是多少？
■ CPU 互连利用率是多少？
■ 为什么要使用 CPU（用户级和内核级调用路径）？
■ 会遇到哪些类型的失速循环？

下面是一个示例工作负载描述，旨在展示如何同时表示这些属性：

在平均 48 个 CPU 的应用程序服务器上，白天的平均负载在 30 到 40 之间变化。用户/系统比率为 95/5，因为这是 CPU 密集型工作负载。大约有 325 K 个系统调用/秒，大约有 80 K 个自愿上下文切换/秒

CPU 的关键指标包括：
■ 利用率：繁忙
■ 饱和度百分比：运行队列长度或计划程序延迟

对于 CPU 性能，请检查静态配置的以下方面

■ 有多少个 CPU 可供使用？它们是核心吗？硬件线程？
■ GPU 或其他加速器是否可用且正在使用中？
■ CPU 架构是单处理器还是多处理器？
■ CPU 缓存的大小是多少？它们是否共享？
■ CPU 时钟速度是多少？它是动态的（例如，Intel Turbo Boost 和 SpeedStep）？这些动态功能在 BIOS 中是否已启用？
■ BIOS 中启用或禁用了哪些其他与 CPU 相关的功能？例如，turboboost、总线设置、省电设置？
■ 此处理器型号是否存在性能问题（错误）？它们是否列在处理器勘误表中？
■ 什么是微码版本？它是否包括针对安全漏洞（例如 Spectre/Meltdown）的影响性能的缓解措施？
■ 此 BIOS 固件版本是否存在性能问题（错误）？
■ 是否存在软件施加的 CPU 使用限制（资源控制）？它们是什么？

负载的度量方法是当前资源使用情况 （利用率） 加上排队的请求 （饱和度）

PSI 首次提供了一种规范的方法来查看资源压力随着资源的发展而增加，并为三个主要资源（内存、CPU 和 IO）提供了新的压力指标。

1. some表示由于缺乏资源而增加了延迟：虽然 CPU 完成的总工作量可能保持不变，但某些任务花费的时间更长。

2. 较高的数字表示总体吞吐量的损失 – 由于缺少资源，完成的工作量会减少。full


perf on CPU:

perf（1） 是官方的 Linux 分析器，一个具有许多功能的多功能工具。第 13 章提供了 perf（1） 的摘要。本节介绍其在 CPU 分析中的使用情况。

# 单行
以下单行代码都很有用，并演示了用于 CPU 分析的不同 perf（1） 功能。以下部分将更详细地介绍一些内容。

指定命令的 CPU 上函数示例，频率为 99 赫兹：
# perf record -F 99 command

系统范围内的 CPU 堆栈跟踪示例（通过帧指针）持续 10 秒：
#  perf record -F 99 -a -g -- sleep 10

PID 的 CPU 堆栈跟踪示例，使用 dwarf （dbg info） 展开堆栈：
# perf record -F 99 -p PID --call-graph dwarf -- sleep 10

通过 exec 记录新的进程事件：
# perf record -e sched:sched_process_exec -a

使用堆栈跟踪记录上下文切换事件 10 秒：
# perf record -e sched:sched_switch -a -g -- sleep 10

10 秒的 CPU 迁移示例：
# perf record -e migrations -a -- sleep 10

记录所有 CPU 迁移 10 秒：
# perf record -e migrations -a -c 1 -- sleep 10

将 perf.data 显示为文本报表，其中包含合并的数据以及计数和百分比：
# perf report -n --stdio

列出所有 perf.data 事件，并带有 data 标头（推荐）：
# perf script --header

显示整个系统的 PMC 统计信息，持续 5 秒：
# perf stat -a -- sleep 5

显示命令的 CPU 最后一级高速缓存 （LLC） 统计信息：
# perf stat -e LLC-loads,LLC-load-misses,LLC-stores,LLC-prefetches command

每秒显示系统范围内的内存总线吞吐量
# perf stat -e uncore_imc/data_reads/,uncore_imc/data_writes/ -a -I 1000

显示每秒上下文切换的速率：
# perf stat -e sched:sched_switch -a -I 1000

显示每秒非自愿上下文切换的速率（之前的状态为 TASK_RUNNING）：
# perf stat -e sched:sched_switch --filter 'prev_state == 0' -a -I 1000

显示每秒模式切换和上下文切换的速率：
# perf stat -e cpu_clk_unhalted.ring0_trans,cs -a -I 1000

记录调度程序配置文件 10 秒：
# perf sched record -- sleep 10

从调度程序配置文件显示每个进程的调度程序延迟：
# perf sched latency

列出计划程序配置文件中的每个事件计划程序延迟：
#  perf sched timehist

bpftrace 工具

使用参数跟踪新进程
# bpftrace -e 'tracepoint:syscalls:sys_enter_execve { join(args->argv); }'

按进程对 syscall 进行计数：
# bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[pid, comm] = count(); }'

按 syscall 探测名称对 syscall 进行计数：
# bpftrace -e 'tracepoint:syscalls:sys_enter_* { @[probe] = count(); }'

99 赫兹的运行进程名称示例：
# bpftrace -e 'profile:hz:99 { @[comm] = count(); }'

系统范围内 49 赫兹的示例用户和内核堆栈，进程名称为：
# bpftrace -e 'profile:hz:49 { @[kstack, ustack, comm] = count(); }'

49 赫兹的用户级堆栈示例，对于 PID 189：
# bpftrace -e 'profile:hz:49 /pid == 189/ { @[ustack] = count(); }'

对于 PID 189，用户级堆栈以 49 赫兹深度 5 帧进行采样：
# bpftrace -e 'profile:hz:49 /pid == 189/ { @[ustack(5)] = count(); }'

49 赫兹的用户级堆栈示例，适用于名为 “mysqld” 的进程：
# bpftrace -e 'profile:hz:49 /comm == "mysqld"/ { @[ustack] = count(); }'

对内核 CPU 调度程序跟踪点进行计数
#  bpftrace -e 'tracepont:sched:* { @[probe] = count(); }'

计算上下文切换事件的 CPU 外内核堆栈：
# bpftrace -e 'tracepont:sched:sched_switch { @[kstack] = count(); }'

对以 “vfs_” 开头的内核函数调用进行计数：
#  bpftrace -e 'kprobe:vfs_* { @[func] = count(); }'

通过 pthread_create（） 跟踪新线程：
# bpftrace -e 'u:/lib/x86_64-linux-gnu/libpthread-2.27.so:pthread_create {printf("%s by %s (%d)\n", probe, comm, pid); }'