package XDP

import (
	"fmt"
	"log"
	"net"
	"runtime"
	"time"
	"unsafe"
	Ebpf_map "github.com/CAINIAOJL/bpftrace-exporter/Firewall/XDP/ebpf"
	Log "github.com/CAINIAOJL/bpftrace-exporter/Firewall/XDP/log"
	Net "github.com/CAINIAOJL/bpftrace-exporter/Firewall/XDP/net"
	Struct "github.com/CAINIAOJL/bpftrace-exporter/Firewall/XDP/strcut"
	"github.com/cilium/ebpf"
)

/*
eg.
    BPF_MAP_TYPE_LRU_PERCPU_HASH的使用注意点
	需要：统计每个 CPU 核心的独立数据（如每个 CPU 的丢包计数、连接数）。
	不需要：全局规则（如端口白名单），所有 CPU 共享同一份规则
*/

func Init_Xdp_Config(obj *ebpf.Collection, Iterface string, Initial bool, ifindex int) bool {
	
	Xdp_Config := Struct.Now_Xdp_Config

	if (len(Xdp_Config.Interfaces) == 0) {
		Log.LogV("error when finding No interface for config file, It is not a error, please check your config file", 2)
	} else {
		for name, inface := range Xdp_Config.Interfaces {
			if (name == Iterface) {
				for rule_name, rule := range inface.Rules {
					if rule_name == "white" {
						Log.LogV(fmt.Sprintf(" Adding white rule for interface: %s", Iterface), 1)
						if ok := Add_rule_wb(obj, rule, Struct.Map_Rule, Struct.Map_Rule6, ifindex, rule_name); !ok {
							return false
						}
					} else if rule_name == "black" {
						Log.LogV(fmt.Sprintf(" Adding black rule for interface: %s", Iterface), 1)
						if ok := Add_rule_wb(obj, rule, Struct.Map_Rule, Struct.Map_Rule6, ifindex, rule_name); !ok {
							return false
						}
					}
				}

				for category, tb := range inface.Limit {
					Log.LogV(fmt.Sprintf(" Adding limit for interface: %s", name), 1)
					if(Limit_Token_bucket(obj, tb, name, Initial, ifindex, category)) {
						Add_rule_global_limit(obj, tb, ifindex, category)
					}
				}
			}
		}
	}	
	return true		
}

func Add_rule_wb(obj *ebpf.Collection, rule Struct.Rule, wb4 string, wb6 string, ifindex int, Type string) bool {
	var action int
	if Type == "white" {
		action = Struct.XDP_PASS		
	} else if Type == "black" {
		action = Struct.XDP_DROP
	} else {
		Log.LogV(fmt.Sprintf("【Add_rule_wb】error when identifing invaild Rule: %s, check config file please!", Type), 3)
		return false
	}
	
	var key4 Struct.IpIfindex
	var key6 Struct.Ip6Ifindex
	Log.LogV(fmt.Sprintf("【Add_rule_wb】Success: find interface's index is %d in this server", ifindex), 1)

	//v4
	for Ip, Ports := range rule.Ip4s {				
		ipkey, err := Net.Ip4ToNetworkOrderUint32(Ip)
		if err != nil {
			ip, ipnet, err2 := net.ParseCIDR(Ip)
			if (err2 != nil) {
				Log.LogV(fmt.Sprintf("【Add_rule_wb】error when parsing %s is invalid ip:%s or invalid cidr:%s", ip, err.Error(), err2.Error()), 3)
				return false
			} else {
				Log.LogV(fmt.Sprintf("【Add_rule_wb】Success: %s is cidr, ip is %s, ipnet is %s", Ip, ip, ipnet), 1)
				ProcessCidr4(obj, ip, ipnet, action, ifindex)
			}
			continue
		}

		inner_map := Ebpf_map.CreateNewInnerMap(ebpf.Hash, uint32(2), uint32(1), uint32(Struct.MAX_IFACES_PORTS), 0)
		for _, port := range Ports {
			err := inner_map.Put(port, uint8(action))
			if err != nil {
				Log.LogV(fmt.Sprintf("【Add_rule_wb】error when updating inner map which parent map is %s map'fd is %d, err is %s", wb4, inner_map.FD(), err), 3)
				return false
			}
		}
		parentMap := obj.Maps[wb4]
		if parentMap == nil {
			Log.LogV(fmt.Sprintf("【Add_rule_wb】error when try to find map: %s!", wb4), 3)
			return false
		}
		key4.Ip = ipkey
		key4.Ifindex = uint32(ifindex)
		if err := parentMap.Put(key4, uint32(inner_map.FD())); err != nil {
			Log.LogV(fmt.Sprintf("【Add_rule_wb】error when update map: %s, err is %s", wb4, err), 3)
			return false
		}
		Log.LogV(fmt.Sprintf("【Add_rule_wb】(rule: %s)Success to add rule for Ipv4: %s",Type, Ip), 1)
	}
	
	//v6
	for Ip, Ports := range rule.Ip6s {
		ip := net.ParseIP(Ip)
		if ip == nil || ip.To16() == nil {
			ip, ipnet, err := net.ParseCIDR(Ip)
			if err != nil {
				Log.LogV(fmt.Sprintf("【Add_rule_wb】error when parsing %s is invalid ip or invalid cidr:%s", Ip, err.Error()), 3)
				return false
			} else {
				Log.LogV(fmt.Sprintf("【Add_rule_wb】Success: %s is cidr: ip is %s, ipnet is %s", Ip, ip, ipnet), 1)
				ProcessCidr6(obj, ip, ipnet, action, ifindex)
			}
			continue
		}
							
		var ipKey [16]byte
		copy(ipKey[:], ip.To16())
							
		inner_map := Ebpf_map.CreateNewInnerMap(ebpf.Hash, uint32(2), uint32(1), uint32(Struct.MAX_IFACES_PORTS), 0)
		for _, port := range Ports {
			err := inner_map.Put(port, uint8(action))
			if err != nil {
				Log.LogV(fmt.Sprintf("【Add_rule_wb】error when Updating inner map which parent map is %s, map'fd is %d, err is %s", wb6, inner_map.FD(), err.Error()), 3)
				return false
			}
		}
		parentMap := obj.Maps[wb6]
		if parentMap == nil {
			Log.LogV(fmt.Sprintf("【Add_rule_wb】error when finding map: %s ", wb6), 3)
			return false
		}

		key6.IP = ipKey
		key6.Ifindex = uint32(ifindex)

		if err := parentMap.Put(key6, uint32(inner_map.FD())); err != nil {
			Log.LogV(fmt.Sprintf("【Add_rule_wb】error when update map: %s, err is %s", wb6, err), 3)
			return false
		}
		Log.LogV(fmt.Sprintf("【Add_rule_wb】(rule: %s)Success to add rule for Ipv6: %s",Type, Ip), 1)
	}
	return true
}

func ProcessCidr4(obj *ebpf.Collection, ip net.IP, ipnet *net.IPNet, action int, ifindex int) bool {
	var cidrkey4 Struct.Lpm_key4
	var children_fd uint32
	var inter_map *ebpf.Map

	size, _ := ipnet.Mask.Size()
	if size < 0 || size > 32 {
        Log.LogV(fmt.Sprintf("【ProcessCidr4】error when find invalid IPv4 prefix length: %d, please check you config file!", size), 3)
		return false
	}

	Ip, err := Net.Ip4ToNetworkOrderUint32(ipnet.IP.String())
	if err != nil {
		Log.LogV(fmt.Sprintf("【ProcessCidr4】error when converting ip: %s to uint32, err is %s", ip.String(), err.Error()), 3)
		return false
	}
	cidrkey4.Ip = Ip
	cidrkey4.Prefixlen = uint32(size)

	Lpm_Map := obj.Maps[Struct.Map_Lpm_Rule]
	if Lpm_Map == nil {
		Log.LogV(fmt.Sprintf("【ProcessCidr4】error when trying to find Map: %s !", Struct.Map_Lpm_Rule), 3)
		return false
	}

	err = Lpm_Map.Lookup(uint32(ifindex + 1), &children_fd)
	if err != nil {
		inter_map = Ebpf_map.CreateNewInnerMap(ebpf.LPMTrie, uint32(unsafe.Sizeof(cidrkey4)), 1, uint32(Struct.MAX_IFACES), 0x01)
	} else {
		inter_map, err = ebpf.NewMapFromID(ebpf.MapID(children_fd))
		if err != nil {
			Log.LogV(fmt.Sprintf("【ProcessCidr4】error when trying to find inner map which parent map is %s, inner map'fd is %d, err is %s",Struct.Map_Lpm_Rule, inter_map.FD(), err), 3)
			return false
		}
	}
	err = inter_map.Put(cidrkey4, uint8(action))
	if err != nil {
		Log.LogV(fmt.Sprintf("【ProcessCidr4】error when puting elem into inner map which parent map is %s, inner map'fd is %d, err is %s", Struct.Map_Lpm_Rule, inter_map.FD(), err), 3)
		return false
	}

	//所有网口号加上1，0不做映射！！重点，参考katran中对于服务器id的map的设计，0不做映射
	err = Lpm_Map.Put(uint32(ifindex + 1), uint32(inter_map.FD()))
	if err != nil {
		Log.LogV(fmt.Sprintf("【ProcessCidr4】error when updating map: %s fd is %d, err is %s",Struct.Map_Lpm_Rule, Lpm_Map.FD(), err.Error()), 3)
		return false
	}
	Log.LogV(fmt.Sprintf("【ProcessCidr4】Success to add rule for Ipv4/Mask: %s", ipnet), 1)
	
	return true
}

//注意prefixlen不是简单的一个数字，他代表ip的前缀位数
func ProcessCidr6(obj *ebpf.Collection, ip net.IP, ipnet *net.IPNet, action int, ifindex int) bool {
	var cidrkey6 Struct.Lpm_key6
	var children_fd uint32
	var inter_map *ebpf.Map
	size, _ := ipnet.Mask.Size()
	if size < 0 || size > 128 {
        Log.LogV(fmt.Sprintf("【ProcessCidr6】error when find invalid IPv6 prefix length: %d, please check you config file!", size), 3)
		return false
    }
	ip6, err := Net.Ip6ToNetworkOrderBytes(ipnet.IP.String())
	if err != nil {
		Log.LogV(err.Error(), 3)
		return false
	}

	copy(cidrkey6.Ip[:], ip6[:])
	cidrkey6.Prefixlen = uint32(size)

	Lpm_Map := obj.Maps[Struct.Map_Lpm_Rule6]

	err = Lpm_Map.Lookup(uint32(ifindex + 1), &children_fd)
	if err != nil {
		inter_map = Ebpf_map.CreateNewInnerMap(ebpf.LPMTrie, uint32(unsafe.Sizeof(cidrkey6)), 1, uint32(Struct.MAX_IFACES), 0x01)
	} else {
		inter_map, err = ebpf.NewMapFromID(ebpf.MapID(children_fd))
		if err != nil {
			Log.LogV(fmt.Sprintf("【ProcessCidr6】error when finding inner map which parent map is %s, map'fd is %d, err is %s", Struct.Map_Lpm_Rule6,  children_fd, err.Error()), 3)
			return false
		}
	}
	err = inter_map.Put(cidrkey6, uint8(action))
	if err != nil {
		Log.LogV(fmt.Sprintf("【ProcessCidr6】error when puting elem into inner map which parent map is %s, map'fd is %d, err is %s", Struct.Map_Lpm_Rule6, inter_map.FD(), err.Error()), 3)
		return false
	}
	err = Lpm_Map.Put(uint32(ifindex + 1), uint32(inter_map.FD()))
	if err != nil {
		Log.LogV(fmt.Sprintf("【ProcessCidr6】error when updating map: %s fd is %d, err is %s",Struct.Map_Lpm_Rule6, Lpm_Map.FD(), err.Error()), 3)
		return false
	}
	Log.LogV(fmt.Sprintf("【ProcessCidr6】Success to add rule for Ipv6/Mask: %s", ipnet), 1)
	return true
}

func DisplayStats(pc *ebpf.Map) {
	for {
		var value []Struct.Package_Count
    	err := pc.Lookup(uint32(0), &value)
    	if err != nil {
        	Log.LogV(fmt.Sprintf("【DisplayStats】error when lookup map: map_Package_Count, err is %s", err.Error()), 3)
        	time.Sleep(time.Second)
        	continue
    	}
    
    	// 计算每个 CPU 核心的统计总和
    	allowedTotal := uint64(0)
    	passedTotal := uint64(0)
    	activeDroppedTotal := uint64(0)
    	passiveDroppedTotal := uint64(0)

		for i := 0; i < runtime.NumCPU(); i++ {
			allowedTotal += value[i].Allowed
			passedTotal += value[i].Passed
			activeDroppedTotal += value[i].Dropped.Active_Dropped
			passiveDroppedTotal += value[i].Dropped.Passive_Dropped
		}

		log.Printf("Allowed: %d, Passed: %d, Active Dropped: %d, Passive Dropped: %d",
        allowedTotal, passedTotal, activeDroppedTotal, passiveDroppedTotal)

		time.Sleep(1 * time.Second)
	}
}

func Limit_Token_bucket(obj *ebpf.Collection, tb Struct.TokenBucket, iface string, Intial bool, ifindex int, category string) bool {
	var is_ipv4 bool
	var tokens Struct.Token_Bucket_Value
	var tb_key Struct.Token_Bucket_key 
	var tb_key46 Struct.Tokens_Rate_Burst_Key

	tokens.Tokens = uint64(tb.Tokens)
	tokens.Last_update_time = 0

	if category == "All" {
		tb_key.Category = uint8(Struct.Global_index)
		tb_key.Ifindex = uint32(ifindex)
	} else if category == "TCP" {
		tb_key.Category = uint8(Struct.Tcp_index)
		tb_key.Ifindex = uint32(ifindex)
	} else if category == "UDP" {
		tb_key.Category = uint8(Struct.Udp_index)
		tb_key.Ifindex = uint32(ifindex)
	} else {
		if ip46, ok := Net.ParseIp4Or6(category, &is_ipv4); ok {
			if is_ipv4 {
				ip4, err := ip46.(uint32)
				if !err {
					Log.LogV(fmt.Sprintf("【Limit_Token_bucket】error when Known limit'proto: %s, please check your config file!", category), 3)
					return false
				}
				tb_key46.Ip4 = ip4
				tb_key46.Ifindex = uint32(ifindex)
			} else {
				ip6, err := ip46.([16]byte)
				if !err {
					Log.LogV(fmt.Sprintf("【Limit_Token_bucket】error when Known limit'proto: %s, please check your config file!", category), 3)
					return false
				}
				tb_key46.Ip6 = ip6
				tb_key46.Ifindex = uint32(ifindex)
			}
		}
	}
	
	if category == "TCP" || category == "UDP" || category == "All" {
		Map_Put_Operation(obj, Struct.Map_Token_Bucket_global, tb_key, tokens, nil)
	} else {
		if is_ipv4 {
			Map_Put_Operation(obj, Struct.Map_Token_Bucket_Ip, tb_key46, tokens, nil)
		} else {
			Map_Put_Operation(obj, Struct.Map_Token_Bucket_Ip6, tb_key46, tokens, nil)
		}
	}

	return true
}

func Add_rule_global_limit(obj *ebpf.Collection, tb Struct.TokenBucket, ifindex int, category string) {
	Burst := tb.Burst
	Rate := tb.Rate
	var is_ipv4 bool

	var tb_key Struct.Token_Bucket_key 
	var tb_key46 Struct.Tokens_Rate_Burst_Key

	if category == "All" {
		tb_key.Category = uint8(Struct.Global_index)
		tb_key.Ifindex = uint32(ifindex)
		if Burst > 0 && Rate > 0 {
			Map_Put_Operation(obj, Struct.Map_Tb_Burst_Rate_global, tb_key, uint64(Burst), uint64(Rate))
		}
	} else if category == "TCP" {
		tb_key.Category = uint8(Struct.Tcp_index)
		tb_key.Ifindex = uint32(ifindex)
		if Burst > 0 && Rate > 0 {
			Map_Put_Operation(obj, Struct.Map_Tb_Burst_Rate_global, tb_key, uint64(Burst), uint64(Rate))
		}
	} else if category == "UDP" {
		tb_key.Category = uint8(Struct.Udp_index)
		tb_key.Ifindex = uint32(ifindex)
		if Burst > 0 && Rate > 0 {
			Map_Put_Operation(obj, Struct.Map_Tb_Burst_Rate_global, tb_key, uint64(Burst), uint64(Rate))
		}
	} else {
		//区分v4/v6
		if ip46, ok := Net.ParseIp4Or6(category, &is_ipv4); ok {
			if is_ipv4 {
				ip4, err := ip46.(uint32)
				if !err {
					Log.LogV(fmt.Sprintf("【Add_rule_global_limit】error when Known limit'proto: %s, please check your config file!", category), 3)
					return
				}
				tb_key46.Ip4 = ip4
				tb_key46.Ifindex = uint32(ifindex)
			} else {
				ip6, err := ip46.([16]byte)
				if !err {
					Log.LogV(fmt.Sprintf("【Add_rule_global_limit】error when Known limit'proto: %s, please check your config file!", category), 3)
					return
				}
				tb_key46.Ip6 = ip6
				tb_key46.Ifindex = uint32(ifindex)
			}
		}
		if(is_ipv4) {
			Map_Put_Operation(obj, Struct.Map_Tb_Rate_Burst_Pre_Ip, tb_key46, uint64(Burst), uint64(Rate))
		} else {
			Map_Put_Operation(obj, Struct.Map_Tb_Rate_Burst_Pre_Ip6, tb_key46, uint64(Burst), uint64(Rate))
		}
	}
}

func Map_Put_Operation(obj *ebpf.Collection, Map_name string, key interface{}, value1 interface{}, value2 interface{}) bool {
	if Map_name == Struct.Map_Token_Bucket_global {
		return Map_Put_Operation_Tokens_Bucket_proto(obj, Map_name, key, value1, false)
	} else if Map_name == Struct.Map_Tb_Burst_Rate_global {
		return Map_Put_Operation_Tokens_Bucket_Rate_Burst_proto(obj, Map_name, key, value1, value2, false)
	} else if Map_name == Struct.Map_Tb_Rate_Burst_Pre_Ip {
		return Map_Put_Operation_Tokens_Bucket_Rate_Burst_proto(obj, Map_name, key, value1, value2, true)
	} else if Map_name == Struct.Map_Tb_Rate_Burst_Pre_Ip6 {
		return Map_Put_Operation_Tokens_Bucket_Rate_Burst_proto(obj, Map_name, key, value1, value2, true)
	} else if Map_name == Struct.Map_Token_Bucket_Ip {
		return Map_Put_Operation_Tokens_Bucket_proto(obj, Map_name, key, value1, true)
	} else if Map_name == Struct.Map_Token_Bucket_Ip6 {
		return Map_Put_Operation_Tokens_Bucket_proto(obj, Map_name, key, value1, true)
	}
	return true
}

func Map_Put_Operation_Tokens_Bucket_proto(obj *ebpf.Collection, Map_name string, key interface{}, value interface{}, is_ip bool) bool {
	ebpf_Map := Ebpf_map.Lookup_Map(obj, Map_name)
	
	var ok bool
	var tb_value Struct.Token_Bucket_Value

	tb_value, ok = value.(Struct.Token_Bucket_Value)
	if !ok {
		Log.LogV(fmt.Sprintf("【Map_Put_Operation_Tokens_Bucket_proto】error when Put %s, value type is not []Token_Bucket_Value", Map_name), 3)
		return false
	}

	if !is_ip {
		var tb_key Struct.Token_Bucket_key
		tb_key, ok = key.(Struct.Token_Bucket_key)
		if !ok {
			Log.LogV(fmt.Sprintf("【Map_Put_Operation_Tokens_Bucket_proto】error when Putinging map: %s, key type is not Toekn_Bucket_key", Map_name), 3)
			return false
		}

		err := ebpf_Map.Put(tb_key, tb_value)
		if err != nil {
			Log.LogV(fmt.Sprintf("【Map_Put_Operation_Tokens_Bucket_proto】error when Put map: %s err is %s", Map_name, err.Error()), 3)
			return false
		}

		Log.LogV(fmt.Sprintf("【Map_Put_Operation_Tokens_Bucket_proto】Success when Put map: %s", Map_name), 1)
	} else {
		var tb_key Struct.Tokens_Rate_Burst_Key
		tb_key, ok = key.(Struct.Tokens_Rate_Burst_Key)

		if !ok {
			Log.LogV(fmt.Sprintf("【Map_Put_Operation_Tokens_Bucket_proto】error when Put map: %s, key type is not Tokens_Rate_Burst_Key", Map_name), 3)
			return false
		}

		err := ebpf_Map.Put(tb_key, tb_value)
		if err != nil {
			Log.LogV(fmt.Sprintf("【Map_Put_Operation_Tokens_Bucket_proto】error when Put map: %s, err is %s", Map_name, err.Error()), 3)
			return false
		}

		Log.LogV(fmt.Sprintf("【Map_Put_Operation_Tokens_Bucket_proto】Success when Put map %s", Map_name), 1)
	}
	return true
}

func Map_Put_Operation_Tokens_Bucket_Rate_Burst_proto(obj *ebpf.Collection, Map_name string, key interface{}, value1 interface{}, value2 interface{}, is_ip bool) bool {
	ebpf_Map := Ebpf_map.Lookup_Map(obj, Map_name)

	var tb_value Struct.Tokens_Rate_Burst_value
	var rate, burst uint64
	var ok bool
	burst, ok = value1.(uint64)
	if !ok {
		Log.LogV(fmt.Sprintf("【Map_Put_Operation_Tokens_Bucket_Rate_Burst_proto】error when Put map: %s, (burst) key type is not uint64", Map_name), 3)
		return false
	}
	rate, ok = value2.(uint64)
	if !ok {
		Log.LogV(fmt.Sprintf("【Map_Put_Operation_Tokens_Bucket_Rate_Burst_proto】error when Put map %s, (rate) value type is not uint64", Map_name), 3)
		return false
	}
	if !is_ip {
		var tb_key Struct.Token_Bucket_key
		tb_key, ok = key.(Struct.Token_Bucket_key)
		if !ok {
			Log.LogV(fmt.Sprintf("【Map_Put_Operation_Tokens_Bucket_Rate_Burst_proto】error when Put map %s, (Toekn_Bucket_key) key type is not Toekn_Bucket_key", Map_name), 3)
			return false
		}
		tb_value.Burst = burst
		tb_value.Rate = rate
		err := ebpf_Map.Put(tb_key, tb_value)
		if err != nil {
			Log.LogV(fmt.Sprintf("【Map_Put_Operation_Tokens_Bucket_Rate_Burst_proto】error when Put map %s, err is %s", Map_name, err.Error()), 3)
			return false
		}
	} else {
		var tb_key Struct.Tokens_Rate_Burst_Key
		tb_key, ok = key.(Struct.Tokens_Rate_Burst_Key)
		if !ok {
			Log.LogV(fmt.Sprintf("【Map_Put_Operation_Tokens_Bucket_Rate_Burst_proto】error when Put map %s, key type is not Tokens_Rate_Burst_Key", Map_name), 3)
			return false
		}
		tb_value.Burst = burst
		tb_value.Rate = rate
		err := ebpf_Map.Put(tb_key, tb_value)
		if err != nil {
			Log.LogV(fmt.Sprintf("【Map_Put_Operation_Tokens_Bucket_Rate_Burst_proto】error when Put map %s, err is %s", Map_name, err), 3)
			return false
		} 
	}
	return true
}