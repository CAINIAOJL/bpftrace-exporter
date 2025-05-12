USE方法

■ 利用率：接口忙于发送或接收帧的时间 
■ 饱和度：由于接口充分利用而导致额外排队、缓冲或阻塞的程度 
■ 错误： 对于接收：校验和错误、帧太短（小于数据链路报头）或太长、冲突（不太可能与交换网络一起）;对于传输：延迟冲突（接线错误）


以下是要测量的最基本特征：

■ 网络接口吞吐量：RX 和 TX，每秒字节数 
■ 网络接口 IOPS：RX 和 TX，每秒帧数 TCP 
■ 连接速率：主动和被动，每秒连接数

检查表：

■ 平均数据包大小是多少？RX，TX？
■ 每一层的协议细分是什么？
■ 对于传输协议：TCP、UDP（可以包括 QUIC）。
■ 哪些 TCP/UDP 端口处于活动状态？每秒字节数，每秒连接数？
■ 广播和组播数据包的速率是多少？
■ 哪些进程正在积极使用网络？


延迟可能表现为：

■ 每个间隔的平均值：最好按客户端/服务器对执行，以隔离中间网络中的差异 
■ 完整分布：作为直方图或热图
■ 每次操作延迟：列出每个事件的详细信息，包括源和目标 IP 地址


网络监控的关键指标

■ 吞吐量：每秒接收和传输的网络接口字节数，理想情况下对于每个接口 
■ 连接数：每秒 TCP 连接数，作为网络负载的另一个指示 
■ 错误：包括丢弃的数据包计数器 
■ TCP 重新传输：也可用于记录与网络问题的相关性 
■ TCP 乱序数据包：也可能导致性能问题


TCP 行为，包括：

■ TCP（套接字）发送/接收缓冲区的使用 
■ TCP 积压队列的使用 
■ 由于积压队列已满而导致内核丢弃 
■ 拥塞窗口大小，包括零大小的通告 
■ 在 TCP TIME_WAIT间隔期间收到的 SYN

请检查静态配置的以下方面：

■ 有多少个网络接口可供使用？目前正在使用中吗？
■ 网络接口的最大速度是多少？
■ 当前协商的网络接口速度是多少？
■ 网络接口是协商为半双工还是全双工？
■ 为网络接口配置了什么MTU？
■ 网络接口是否中继？
■ 设备驱动程序存在哪些可调参数？IP 层？TCP 层？
■ 是否有任何可调参数与默认值不同？
■ 路由是如何配置的？什么是默认网关？
■ 数据路径中网络组件（所有组件，包括交换机和路由器背板）的最大吞吐量是多少？
■ 数据路径的最大 MTU 是多少，是否发生碎片？
■ 数据路径中是否有任何无线连接？他们是否受到干扰？
■ 是否启用了转发？系统是否充当路由器？
■ DNS 是如何配置的？服务器有多远？
■ 网络接口固件的版本或任何其他网络硬件是否存在已知的性能问题（错误）？
■ 网络设备驱动程序是否存在已知的性能问题（错误）？
■ 内核 TCP/IP 堆栈？
■ 存在哪些防火墙？是否存在软件施加的网络吞吐量限制（资源控制）？它们是什么？

这些控件可以包括以下类型的控件：

■ 网络带宽限制：内核应用的不同协议或应用程序允许的带宽（最大吞吐量）。
■ IP 服务质量 （QoS）：由网络组件（例如路由器）执行的网络流量的优先级排序。这可以通过不同的方式实现： IP 报头包括服务类型 （ToS） 位，包括优先级;此后，这些位已针对较新的 QoS 方案重新定义，包括差分服务（请参见部分 10.4.1 协议，在 IP 标题下）。出于相同的目的，其他协议制定者可能还实施了其他优先级。
■ 数据包延迟：额外的数据包延迟（例如，使用 Linux tc-netem（8）），可用于在测试性能时模拟其他网络


可以测试的典型因素包括

■ 方向：发送或接收 
■ 协议：TCP 或 UDP，以及端口
■ 线程数 
■ 缓冲区大小
■ 接口 MTU 大小

nstat 工具

关键指标包括： 
■ IpInReceives：入站 IP 数据包。
■ IpOutRequests：出站 IP 数据包。
■ TcpActiveOpens： TCP 活动连接（connect（2） 套接字 syscall）。
■ TcpPassiveOpens： TCP 被动连接（accept（2） 套接字系统调用）。
■ TcpInSegs：TCP 入站分段。
■ TcpOutSegs：TCP 出站段。
■ TcpRetransSegs：TCP 重传段。与 TcpOutSegs 比较重传比率


nicstat（1） 对于 USE 方法特别有用，因为它提供 utilization 和 saturation 值。

# 单行
以下单行代码非常有用，并演示了不同的 bpftrace 功能。

通过 PID 和进程名称对套接字 accept（2） 进行计数：
# bpftrace -e 't:syscalls:sys_enter_accept* { @[pid, comm] = count(); }'

按 PID 和进程名称对套接字连接 （2） 进行计数：
# bpftrace -e 't:syscalls:sys_enter_connect { @[pid, comm] = count(); }'

按用户堆栈跟踪对 socket connect（2） 进行计数：
# bpftrace -e 't:syscalls:sys_enter_connect { @[ustack, comm] = count(); }'

按方向、CPU 上的 PID 和进程名称对套接字发送/接收进行计数：
# bpftrace -e 'k:sock_sendmsg,k:sock_recvmsg { @[func, pid, comm] = count(); }'

根据 CPU 上的 PID 和进程名称对套接字发送/接收字节进行计数：
# bpftrace -e 'kr:sock_sendmsg,kr:sock_recvmsg /(int32)retval > 0/ { @[pid, comm] =sum((int32)retval); }'

按 CPU 上的 PID 和进程名称对 TCP 连接进行计数：
# bpftrace -e 'k:tcp_v*_connect { @[pid, comm] = count(); }'

按 CPU 上的 PID 和进程名称对 TCP 接受进行计数：
# bpftrace -e 'k:inet_csk_accept { @[pid, comm] = count(); }'

按 CPU 上的 PID 和进程名称计算 TCP 发送/接收次数：
# bpftrace -e 'k:tcp_sendmsg,k:tcp_recvmsg { @[func, pid, comm] = count(); }'

TCP 发送字节数作为直方图：
# bpftrace -e 'k:tcp_sendmsg { @send_bytes = hist(arg2); }'

TCP 接收字节数作为直方图：
# bpftrace -e 'kr:tcp_recvmsg /retval >= 0/ { @recv_bytes = hist(retval); }'

按类型和远程主机对 TCP 重新传输进行计数（假设为 IPv4）：
# bpftrace -e 't:tcp:tcp_retransmit_* { @[probe, ntop(2, args->saddr)] = count(); }'

计算所有 TCP 函数（给 TCP 增加高开销）：
# bpftrace -e 'k:tcp_* { @[func] = count(); }'

按 CPU 上的 PID 和进程名称对 UDP 发送/接收进行计数：
# bpftrace -e 'k:udp*_sendmsg,k:udp*_recvmsg { @[func, pid, comm] = count(); }'

UDP 发送字节作为直方图：
# bpftrace -e 'k:udp_sendmsg { @send_bytes = hist(arg2); }'

UDP 接收字节数作为直方图：
# bpftrace -e 'kr:udp_recvmsg /retval >= 0/ { @recv_bytes = hist(retval); }'

计数传输内核堆栈跟踪：
# bpftrace -e 't:net:net_dev_xmit { @[kstack] = count(); }'

显示每个设备的接收 CPU 直方图：
# bpftrace -e 't:net:netif_receive_skb { @[str(args->name)] = lhist(cpu, 0, 128, 1); }'

对 ieee80211 层函数进行计数（为数据包增加高开销）：
# bpftrace -e 'k:ieee80211_* { @[func] = count(); }'

计算所有 ixgbevf 设备驱动程序功能（为 ixgbevf 增加高开销）：
# bpftrace -e 'k:ixgbevf_* { @[func] = count(); }'

对所有 iwl 设备驱动程序跟踪点进行计数（给 iwl 增加高开销）：
# bpftrace -e 't:iwlwifi:*,t:iwlwifi_io:* { @[probe] = count(); }'