#!/usr/bin/env python3
from scapy.all import IP, TCP, UDP, ICMP, sendpfast, RandIP, RandShort
import argparse
import threading
import time
import random

def generate_icmp_traffic(interface, target_ip, count_per_thread, rate):
    """生成ICMP流量"""
    packet = IP(src=RandIP(), dst=target_ip)/ICMP()
    sendpfast(packet, pps=rate, loop=count_per_thread, iface=interface)

def generate_tcp_traffic(interface, target_ip, target_port, count_per_thread, rate):
    """生成TCP流量"""
    packet = IP(src=RandIP(), dst=target_ip)/TCP(sport=RandShort(), dport=target_port, flags="S")
    sendpfast(packet, pps=rate, loop=count_per_thread, iface=interface)

def generate_udp_traffic(interface, target_ip, target_port, count_per_thread, rate):
    """生成UDP流量"""
    packet = IP(src=RandIP(), dst=target_ip)/UDP(sport=RandShort(), dport=target_port)/("X" * random.randint(10, 100))
    sendpfast(packet, pps=rate, loop=count_per_thread, iface=interface)

def traffic_worker(interface, protocol, target_ip, target_port, count_per_thread, rate):
    """流量生成工作线程"""
    if protocol.lower() == "icmp":
        generate_icmp_traffic(interface, target_ip, count_per_thread, rate)
    elif protocol.lower() == "tcp":
        generate_tcp_traffic(interface, target_ip, target_port, count_per_thread, rate)
    elif protocol.lower() == "udp":
        generate_udp_traffic(interface, target_ip, target_port, count_per_thread, rate)
    else:
        print(f"不支持的协议: {protocol}")

def main():
    parser = argparse.ArgumentParser(description="高性能网络流量生成器")
    parser.add_argument("-i", "--interface", required=True, help="网络接口名称")
    parser.add_argument("-p", "--protocol", choices=["icmp", "tcp", "udp"], default="udp", help="协议类型")
    parser.add_argument("-d", "--destination", required=True, help="目标IP地址")
    parser.add_argument("--dport", type=int, default=80, help="目标端口 (TCP/UDP)")
    parser.add_argument("-t", "--threads", type=int, default=4, help="线程数量")
    parser.add_argument("-c", "--count", type=int, default=1000000, help="每个线程发送的数据包总数")
    parser.add_argument("--pps", type=int, default=1000, help="每秒发送的数据包数 (PPS)")
    parser.add_argument("--duration", type=int, help="持续发送的时间 (秒)，与--count互斥")
    
    args = parser.parse_args()
    
    print(f"配置:")
    print(f"  接口: {args.interface}")
    print(f"  协议: {args.protocol.upper()}")
    print(f"  目标: {args.destination}:{args.dport}")
    print(f"  线程: {args.threads}")
    
    if args.duration:
        print(f"  持续时间: {args.duration}秒")
        print(f"  速率: {args.pps} PPS/线程")
    else:
        print(f"  总数据包数: {args.count * args.threads}")
        print(f"  速率: {args.pps} PPS/线程")
    
    print("\n按 Ctrl+C 停止发送...")
    
    try:
        threads = []
        
        if args.duration:
            # 基于时间的流量生成
            count_per_thread = args.pps * args.duration
            for _ in range(args.threads):
                t = threading.Thread(
                    target=traffic_worker,
                    args=(args.interface, args.protocol, args.destination, args.dport, count_per_thread, args.pps)
                )
                threads.append(t)
                t.start()
            
            # 等待所有线程完成
            for t in threads:
                t.join()
        else:
            # 基于固定包数的流量生成
            count_per_thread = args.count
            for _ in range(args.threads):
                t = threading.Thread(
                    target=traffic_worker,
                    args=(args.interface, args.protocol, args.destination, args.dport, count_per_thread, args.pps)
                )
                threads.append(t)
                t.start()
            
            # 等待所有线程完成
            for t in threads:
                t.join()
    
    except KeyboardInterrupt:
        print("\n用户中断，停止发送流量...")
    except Exception as e:
        print(f"发生错误: {e}")

if __name__ == "__main__":
    main()