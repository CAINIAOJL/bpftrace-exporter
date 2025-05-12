操作延迟 = 时间（操作完成）- 时间（操作请求）

文件系统中的时间百分比 = 100 * 总阻塞文件系统延迟/应用程序事务时间

举个具体的例子，一个应用程序事务需要 200 毫秒，在此期间，它在多个文件系统 I/O 上总共等待 180 毫秒。应用程序被文件系统阻塞的时间为 90%（100 * 180 毫秒/200 毫秒）。消除文件系统延迟可以将性能提高多达 10 倍。

再举一个例子，如果一个应用程序事务需要 200 毫秒，在此期间，文件系统中只花费了 2 毫秒，那么文件系统（以及整个磁盘 I/O 堆栈）对事务运行时间的贡献仅为 1%。这个结果非常有用，因为它可以将性能调查引导到延迟的真正来源

以下是描述文件系统工作负载的基本属性：

■ 操作速率和操作类型 
■ 文件 I/O 吞吐量 
■ 文件 I/O 大小 
■ 读/写比率 
■ 同步写入比率 
■ 随机与顺序文件偏移访问

检查表：

■ 文件系统缓存命中率是多少？失误率？
■ 文件系统缓存容量和当前使用情况是多少？
■ 还存在哪些其他缓存（directory、inode、buffer），它们的统计信息是什么？
■ 过去是否尝试过调整文件系统？是否有任何文件系统参数设置为其默认值以外的值？
■ 哪些应用程序或用户正在使用文件系统？
■ 正在访问哪些文件和目录？已创建并已删除？
■ 是否遇到任何错误？这是由于无效请求还是文件系统出现问题？
■ 为什么会发出文件系统 I/O（用户级调用路径）？
■ 应用程序直接（同步）请求文件系统 I/O 的程度如何？
■ I/O 到达时间的分布情况

检查结果性能

■ 平均文件系统作延迟是多少？
■ 是否存在任何高延迟异常值？
■ 什么是操作延迟的完整分布？
■ 文件系统或磁盘 I/O 的系统资源控制是否存在并处于活动状态？

文件系统性能的关键指标包括

■ 运行速率 
■ 运行延迟


对于文件系统性能，请检查静态配置的以下方面

■ 挂载并主动使用了多少个文件系统？
■ 文件系统记录大小是多少？
■ 是否启用了访问时间戳？
■ 启用了哪些其他文件系统选项（压缩、加密...）？
■ 文件系统缓存是如何配置的？最大尺寸？其他缓存（directory、inode、buffer）是如何配置的？
■ 二级缓存是否存在且正在使用中？
■ 存在和正在使用多少个存储设备？
■ 存储设备配置是什么？RAID？
■ 使用哪些文件系统类型？
■ 文件系统（或内核）的版本是什么？
■ 是否有应考虑的文件系统错误/补丁？
■ 是否有用于文件系统 I/O 的资源控制？

可能测试的典型因素包括

■ 操作类型：读取、写入和其他文件系统作的速率 
■ I/O 大小：1 字节，最大 1 MB 或更大 
■ 文件偏移模式：随机或顺序 
■ 随机访问模式：均匀、随机或帕累托分布 
■ 写入类型：异步或同步 （O_SYNC） 
■ 工作集大小：它在文件系统缓存中的适应程度
■ 并发性：并行 I/O 数量或执行 I/O 的线程数 
■ 内存映射：通过 mmap（2） 而不是 read（2）/write（2） 访问文件 
■ 缓存状态：文件系统缓存是“冷”（未填充）还是“暖” 
■ 文件系统可调参数：可能包括压缩、重复数据删除等


使用 process name 通过 openat（2） 打开的跟踪文件
# bpftrace -e 't:syscalls:sys_enter_openat { printf("%s %s\n", comm,
    str(args->filename)); }'

按 syscall 类型对读取的系统调用进行计数：
# bpftrace -e 'tracepoint:syscalls:sys_enter_*read* { @[probe] = count(); }'

按 syscall 类型对写入 syscall 进行计数： 
# bpftrace -e 'tracepoint:syscalls:sys_enter_*write* { @[probe] = count(); }

显示 read（） syscall 请求大小的分布情况：
# bpftrace -e 'tracepoint:syscalls:sys_enter_read { @ = hist(args->count); }'

显示 read（） syscall 读取字节（和错误）的分布：
# bpftrace -e 'tracepoint:syscalls:sys_exit_read { @ = hist(args->ret); }'

按错误代码计算 read（） syscall 错误：
#  bpftrace -e 't:syscalls:sys_exit_read /args->ret < 0/ { @[- args->ret] = count(); }'

对 VFS 调用进行计数
# bpftrace -e 'kprobe:vfs_* { @[probe] = count(); }'

对 PID 181 的 VFS 调用进行计数：
#  bpftrace -e 'kprobe:vfs_* /pid == 181/ { @[probe] = count(); }'

计数 ext4 个跟踪点：
# bpftrace -e 'tracepoint:ext4:* { @[probe] = count(); }'

对 xfs 跟踪点进行计数：
# bpftrace -e 'tracepoint:xfs:* { @[probe] = count(); }'

按进程名称和用户级堆栈对 ext4 文件读取进行计数：
# bpftrace -e 'kprobe:ext4_file_read_iter { @[ustack, comm] = count(); }'

跟踪 ZFS spa_sync（） 次：
# bpftrace -e 'kprobe:spa_sync { time("%H:%M:%S ZFS spa_sync()\n"); }'

按进程名称和 PID 对 dcache 引用进行计数：
#  bpftrace -e 'kprobe:lookup_fast { @[comm, pid] = count(); }'


# To free pagecache:
        echo 1 > /proc/sys/vm/drop_caches
# To free reclaimable slab objects (includes dentries and inodes):
        echo 2 > /proc/sys/vm/drop_caches
# To free slab objects and pagecache:
        echo 3 > /proc/sys/vm/drop_caches