package net

import(
	"net"
	"fmt"
	"unsafe"
	//"encoding/binary"
    Log "github.com/CAINIAOJL/bpftrace-exporter/Firewall/XDP/log"
)

//注意网络字节序的问题
//bpf_trace_printk: Checking IP: 158a8c0, Port: 50196
func Ip4ToNetworkOrderUint32(ipStr string) (uint32, error) {
    ip := net.ParseIP(ipStr)
    if ip == nil {
        return 0, fmt.Errorf("invalid IP address: %s", ipStr)
    }
    ip = ip.To4()
    if ip == nil {
        return 0, fmt.Errorf("not an IPv4 address: %s", ipStr)
    }

    return *(*uint32)(unsafe.Pointer(&ip[0])), nil
}

func Ip6ToNetworkOrderBytes(ipStr string) ([16]byte, error) {
    ip := net.ParseIP(ipStr)
    if ip == nil {
        return [16]byte{}, fmt.Errorf("invalid IP address: %s", ipStr)
    }
    ip = ip.To16()
    if ip == nil {
        return [16]byte{}, fmt.Errorf("not an IPv6 address: %s", ipStr)
    }
    var result [16]byte
    copy(result[:], ip)  // 直接拷贝16字节
    return result, nil
}

func JudgeIpIsCidr(Ip string) bool {
	var is_cidr bool
	_, _, err := net.ParseCIDR(Ip)
	if err != nil {
		is_cidr = false
	} else {
		is_cidr = true
	}
	return is_cidr
}

//区分v4/v6
func ParseIp4Or6(Ip string, is_ipv4 *bool) (interface{}, bool) {
	ip := net.ParseIP(Ip) 
	if ip == nil {
		Log.LogV(fmt.Sprintf("【ParseIp4Or6】error when parse Ip, invalid ip: %s in limit configuration, please check your config file", Ip), 3)
		return nil, false
	} 
	ip = ip.To4()
	if ip == nil {
		ip6, err := Ip6ToNetworkOrderBytes(net.ParseIP(Ip).String())
		if err != nil {
			Log.LogV(err.Error(), 3)
			return nil, false
		}
		*is_ipv4 = false
        return ip6, true
	} else {
		ip4, err := Ip4ToNetworkOrderUint32(net.ParseIP(Ip).String())
		if err != nil {
			Log.LogV(err.Error(),3)
			return nil, false
		}
		*is_ipv4 = true
        return ip4, true
    }
} 

func ParseIp4Or6Cidr(Ip string) (*net.IPNet) {
    _, ipnet, err := net.ParseCIDR(Ip)
    if err != nil {
        Log.LogV(fmt.Sprintf("【ParseIp4Or6Cidr】error when parse cidr ip: %s, err is %s", Ip, err.Error()), 3)
        return nil
    }
    return ipnet
}