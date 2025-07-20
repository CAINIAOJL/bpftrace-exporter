package XDP

import (
	"fmt"
	"log"
	"net"
	"os"
	"unsafe"

	Ebpf_map "github.com/CAINIAOJL/bpftrace-exporter/Firewall/XDP/ebpf"
	Log "github.com/CAINIAOJL/bpftrace-exporter/Firewall/XDP/log"
	Net "github.com/CAINIAOJL/bpftrace-exporter/Firewall/XDP/net"
	Struct "github.com/CAINIAOJL/bpftrace-exporter/Firewall/XDP/strcut"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/r3labs/diff/v3"
	"gopkg.in/yaml.v3"
)

func ExchangeNewOldConfig(Temp_Xdp_Config Struct.Xdp_Config) {
	bytes, err := yaml.Marshal(Temp_Xdp_Config)
    if err != nil {
        Log.LogV(fmt.Sprintf("【ExchangeNewOldConfig】error when store the old config, err is %s", err.Error()), 3)
    }
    if err := yaml.Unmarshal(bytes, &Struct.Pre_Xdp_Config); err != nil {
        Log.LogV(fmt.Sprintf("【ExchangeNewOldConfig】error when store the old config, err is %s", err.Error()), 3)
    }
}

func ParseConfig(configPath string, is_first bool) {
	data, err := os.ReadFile(configPath)
	Temp_Xdp_Config := Struct.Xdp_Config{}
	if err != nil {
		Log.LogV(fmt.Sprintf("【ParseConfig】error when parse xdp config, err is %s", err.Error()), 1)
		return
	}

	if err := yaml.Unmarshal(data, &Temp_Xdp_Config); err != nil {
		log.Fatalf("【ParseConfig】error when unmarshal the config file(yaml), err is %s", err.Error())
	}
	if is_first {
		Struct.Now_Xdp_Config = Temp_Xdp_Config
		ExchangeNewOldConfig(Temp_Xdp_Config)
		ConfigLogInFile(Struct.Pre_Xdp_Config)
	} else {
		Log.LogV("【ParseConfig】New config are: ", 1)
		Struct.Now_Xdp_Config = Temp_Xdp_Config
		ConfigLogInFile(Struct.Now_Xdp_Config)

		ProcessDiffConfig(Struct.Obj, CompareConfigs())
		ExchangeNewOldConfig(Temp_Xdp_Config)
	}
}

// ========== 配置变更对比 ==========
func CompareConfigs() (*diff.Changelog) {
	Log.LogV("【CompareConfigs】config diff are below：", 1)
	var changelog diff.Changelog
	var err error

	differ, _ := diff.NewDiffer(diff.SliceOrdering(true)) 
	changelog, err = differ.Diff(Struct.Pre_Xdp_Config, Struct.Now_Xdp_Config)
	if err != nil {
		Log.LogV(fmt.Sprintf("【CompareConfigs】error when diffing configs, err is %s", err.Error()), 3)
	}

	if len(changelog) == 0 {
		Log.LogV("【CompareConfigs】no change between new and old config", 1)
		return nil
	}

	for _, change := range changelog {
		Log.LogV(fmt.Sprintf("路径: %v", change.Path), 1)
		Log.LogV(fmt.Sprintf(" - From: %v", change.From), 1)
		Log.LogV(fmt.Sprintf(" - To:   %v", change.To), 1)
		Log.LogV_N()
	}
	
	return &changelog
}

func ConfigLogInFile(config Struct.Xdp_Config) {
	if len(config.Interfaces) == 0 {
		log.Println("配置文件中未包含 Interface 配置")
		return
	}

	for ifName, iface := range config.Interfaces {
		Log.LogV(fmt.Sprintf("Interface name: %s", ifName), 1)
		for ruleType, rule := range iface.Rules {
			Log.LogV(fmt.Sprintf("    Rule type: %s", ruleType), 1)

			for ip4, ports := range rule.Ip4s {
				Log.LogV(fmt.Sprintf("        IPv4: %s", ip4), 1)
				for _, port := range ports {
					Log.LogV(fmt.Sprintf("            Port: %d", port), 1)
				}
			}

			for ip6, ports := range rule.Ip6s {
				Log.LogV(fmt.Sprintf("        IPv6: %s", ip6), 1)
				for _, port := range ports {
					Log.LogV(fmt.Sprintf("            Port: %d", port), 1)
				}
			}
		}

		// Limit 部分
		Log.LogV("    Limit Configuration:", 1)
		for proto, tb := range iface.Limit {
			Log.LogV(fmt.Sprintf("        Protocol: %s", proto), 1)
			Log.LogV(fmt.Sprintf("            Burst: %d", tb.Burst), 1)
			Log.LogV(fmt.Sprintf("            Rate: %d", tb.Rate), 1)
			Log.LogV(fmt.Sprintf("            Tokens: %d", tb.Tokens), 1)
		}

		Log.LogV_N() // 假设这是打印空行或换行
	}
}

func ClearAllRulesForInterface(iface string) {
	Log.LogV(fmt.Sprintf("【ClearAllRulesForInterface】clear xdp program in %s", iface), 1)
	if Struct.AttachedLinks[Struct.Iface2Index[iface]] == nil {
		Log.LogV(fmt.Sprintf("【ClearAllRulesForInterface】There is no xdp prog in %s", iface), 2)
		return
	}
	Struct.AttachedLinks[Struct.Iface2Index[iface]].Close() 

	delete(Struct.AttachedLinks, Struct.Iface2Index[iface])
}

func FillOptsOfRuleMap(ruleType string, ipType string, Ip string, opt *Struct.MapOperation) (res bool) {
	if ruleType == "white" {
		if ipType == "Ip4s" {
			if res = Net.JudgeIpIsCidr(Ip); res {
				opt.MapType = Struct.Map_Lpm_Rule
				return true
			}
			opt.MapType = Struct.Map_Rule
		} else if ipType == "Ip6s" {
			if res = Net.JudgeIpIsCidr(Ip); res {
				opt.MapType = Struct.Map_Lpm_Rule6
				return true
			}
			opt.MapType = Struct.Map_Rule6
		}
	} else if ruleType == "black" {
		if ipType == "Ip4s" {
			if res = Net.JudgeIpIsCidr(Ip); res {
				opt.MapType = Struct.Map_Lpm_Rule
				return true
			}
			opt.MapType = Struct.Map_Rule
		} else if ipType == "Ip6s" {
			if res = Net.JudgeIpIsCidr(Ip); res {
				opt.MapType = Struct.Map_Lpm_Rule6
				return true
			}
			opt.MapType = Struct.Map_Rule6
		}
	}
	return false
}

func ProcessDiffConfig(obj *ebpf.Collection, changelog *diff.Changelog) bool {
	Struct.InterfaceRuleDel 			= make(map[string]int)
	Struct.InterfaceRuleTotalOld 		= make(map[string]int)

	Struct.InterfaceLimitDel 			= make(map[string]int)
	Struct.InterfaceLimitTotalOld  		= make(map[string]int)

	New_iface := []string{}

	optsOfrule := []Struct.MapOperation{}
	optsOflimit := make(map[string]*Struct.LimitOperation)

	for _, change := range *changelog {
		path := change.Path

		if len(path) >= 6 && path[0] == "Interfaces" && path[2] == "Rules" {
			iface, ruleType, ipType, ip := path[1], path[3], path[4], path[5]
			New_iface = append(New_iface, iface)
			switch change.Type {

			case diff.DELETE:
				Struct.InterfaceRuleDel[iface]++
				opts := Struct.MapOperation{
					Action:   Struct.OPT_ACTION_DEL,
					IfName:   iface,
					RuleType: ruleType,
					IPType:   ipType,
					IP:       ip,
					FromPortLists: []uint16{},
				}
		
				ok := FillOptsOfRuleMap(ruleType, ipType, ip, &opts)

				if len(path) == 6 {
					opts.FullMode = true 
					if ok {
						opts.IsCidr = true
						Struct.InterfaceRuleDel[iface]++
					} else {
						opts.IsCidr = false
						opts.FromPortLists = change.From.([]uint16)
						Struct.InterfaceRuleDel[iface] += len(change.From.([]uint16))
					}
				} else {
					opts.FullMode = false
					opts.FromPort = change.From.(uint16)
				}
				optsOfrule = append(optsOfrule, opts)

			case diff.CREATE:
				opts := Struct.MapOperation{
					Action:   Struct.OPT_ACTION_ADD,
					IfName:   iface,
					RuleType: ruleType,
					IPType:   ipType,
					IP:       ip,
				}
				
				ok := FillOptsOfRuleMap(ruleType, ipType, ip, &opts)

				if len(path) == 6 {
					opts.FullMode = true
					if ok {
						opts.IsCidr = true
					} else {
						opts.IsCidr = false
						opts.ToPortList = change.To.([]uint16)
					}
				} else {
					opts.FullMode = false
					opts.ToPort = change.To.(uint16)
				}
				optsOfrule = append(optsOfrule, opts)

			case diff.UPDATE:
				opts := Struct.MapOperation{
					Action:   Struct.OPT_ACTION_UPD,
					IfName:   iface,
					RuleType: ruleType,
					IPType:   ipType,
					IP:       ip,
					FromPort: change.From.(uint16),
					ToPort: change.To.(uint16),
				}
				FillOptsOfRuleMap(ruleType, ipType, ip, &opts)
				optsOfrule = append(optsOfrule, opts)
			}
		} else if len(path) == 5 && path[0] == "Interfaces" && path[2] == "Limit" {
			iface, proto, field := path[1], path[3], path[4]
			New_iface = append(New_iface, iface)
			switch change.Type {

			case diff.DELETE:
				Struct.InterfaceLimitDel[iface] += 1
				opt := optsOflimit[iface+proto]
				if opt == nil {
					optsOflimit[iface+proto] = &Struct.LimitOperation{
									Proto: proto,
									Action: Struct.OPT_ACTION_DEL,
									IfName: iface,
									TRB: make(map[string][]int64),
					}
					opt = optsOflimit[iface+proto]
				}
				if _, exist := opt.TRB[field]; !exist {
					opt.TRB[field] = make([]int64, 2)
				}
				opt.TRB[field][0] = change.From.(int64)

			case diff.CREATE:
				opt := optsOflimit[iface+proto]
				if opt == nil {
					optsOflimit[iface+proto] = &Struct.LimitOperation{
									Action: Struct.OPT_ACTION_ADD,
									Proto: proto,
									IfName: iface,
									TRB: make(map[string][]int64),
					}
					opt = optsOflimit[iface+proto]
				}
				if _, exist := opt.TRB[field]; !exist {
					opt.TRB[field] = make([]int64, 2)
				}
				opt.TRB[field][1] = change.To.(int64)

			case diff.UPDATE:
				opt := optsOflimit[iface+proto]
				if opt == nil {
					optsOflimit[iface+proto] = &Struct.LimitOperation{
									Action: Struct.OPT_ACTION_UPD,
									Proto: proto,
									IfName: iface,
									TRB: make(map[string][]int64),
					}
					opt = optsOflimit[iface+proto]
				}
				if _, exist := opt.TRB[field]; !exist {
					opt.TRB[field] = make([]int64, 2)
				}
				opt.TRB[field][1] = change.To.(int64)
				opt.TRB[field][0] = change.From.(int64)
			}
		} else {
			Log.LogV(fmt.Sprintf("【ProcessDiffConfig】error when parse diff's change which is %v", change), 3)
			return false
		}
	}

	for iface, intf := range Struct.Pre_Xdp_Config.Interfaces {
		count := 0
		for _, rule := range intf.Rules {
			for _, Ports := range rule.Ip4s {
				count += len(Ports)
			}
			for _, Ports := range rule.Ip6s {
				count += len(Ports)
			}
		}
		Struct.InterfaceRuleTotalOld[iface] = count
		Struct.InterfaceLimitTotalOld[iface] = 3 * len(intf.Limit)
	}

	for iface, _ := range Struct.Pre_Xdp_Config.Interfaces {
		ruleTotal := Struct.InterfaceRuleTotalOld[iface]
		limitTotal := Struct.InterfaceLimitTotalOld[iface]

		ruleDel := Struct.InterfaceRuleDel[iface]
		limitDel := Struct.InterfaceLimitDel[iface]

		if ruleDel >= ruleTotal && limitDel >= limitTotal {
			ClearAllRulesForInterface(iface) 
		}
	}

	for _, iface := range New_iface {
		_, ok := Struct.Iface2Index[iface]
		if !ok {
			ifindex, err := net.InterfaceByName(iface)
			if err != nil {
				Log.LogV(fmt.Sprintf("【ProcessDiffConfig】error when finding ifindex of %s, please check your config file", iface), 2)
				return false
			}
			xdp_link, err := link.AttachXDP(link.XDPOptions{
					Program: obj.Programs[Struct.XDP_PROGRAM_NAME],
					Interface: ifindex.Index, 
			})
			if err != nil {
				Log.LogV(fmt.Sprintf("【ProcessDiffConfig】error when attaching xdp program for %s, err is %v", iface, err), 3)
				return false
			}
			Struct.AttachedLinks[Struct.Iface2Index[iface]] = xdp_link
			Struct.Iface2Index[iface] = ifindex.Index
		}
	}

	for _, opt := range optsOfrule {
		ProcessOptOfMap(obj, &opt, nil)
	}
	for _, opt := range optsOflimit {
		ProcessOptOfMap(obj, nil, opt)
	}
	return true
}

func ProcessOptOfMap(obj *ebpf.Collection, Mopt *Struct.MapOperation, Lopt *Struct.LimitOperation) bool {
	var Moptok, Loptok bool
	
	if Mopt != nil {
		switch Mopt.MapType {

		case Struct.Map_Rule:
			var Keyv4 Struct.IpIfindex
			ipkey, err := Net.Ip4ToNetworkOrderUint32(Mopt.IP)
			if err != nil {
				Log.LogV(fmt.Sprintf("【ProcessOptOfMap】error when parse proto: %s, err is %s", Mopt.IP, err.Error()), 3)
				return false
			}
			Keyv4.Ip = ipkey
			Keyv4.Ifindex = uint32(Struct.Iface2Index[Mopt.IfName])

			switch Mopt.Action {

			case Struct.OPT_ACTION_ADD: //从nil到有
				Moptok = AddRuleMapOpt(obj, Keyv4, Mopt)
			case Struct.OPT_ACTION_DEL: //从有到nil
				Moptok = DelRuleMapOpt(obj, Keyv4, Mopt)
			case Struct.OPT_ACTION_UPD:
				Moptok = UpdRuleMapOpt(obj, Keyv4, Mopt)	
			}	
		case Struct.Map_Rule6:
			var key6 Struct.Ip6Ifindex
			ipkey, err := Net.Ip6ToNetworkOrderBytes(Mopt.IP)
			if err != nil {
				Log.LogV(fmt.Sprintf("【ProcessOptOfMap】error when parse proto: %s, err is %s", Mopt.IP, err.Error()), 3)
			}
			key6.IP = ipkey
			key6.Ifindex = uint32(Struct.Iface2Index[Mopt.IfName])

			switch Mopt.Action{

			case Struct.OPT_ACTION_ADD:
				Moptok = AddRuleMapOpt(obj, key6, Mopt)
			case Struct.OPT_ACTION_DEL:
				Moptok = DelRuleMapOpt(obj, key6, Mopt)
			case Struct.OPT_ACTION_UPD:
				Moptok = UpdRuleMapOpt(obj, key6, Mopt)
			}
		case Struct.Map_Lpm_Rule:
			ipnet := Net.ParseIp4Or6Cidr(Mopt.IP)
			if ipnet == nil {
				return false
			}
			var key4 Struct.Lpm_key4
			size, _ := ipnet.Mask.Size()
			key4.Prefixlen = uint32(size)
			ip, _ := Net.Ip4ToNetworkOrderUint32(ipnet.IP.String())
			key4.Ip = ip

			switch Mopt.Action {
			case Struct.OPT_ACTION_ADD:
				Moptok = AddOrDelRuleLpmMapOpt(obj, key4, Mopt, true)
			case Struct.OPT_ACTION_DEL:
				Moptok = AddOrDelRuleLpmMapOpt(obj, key4, Mopt, false)
			}
		case Struct.Map_Lpm_Rule6:
			ipnet := Net.ParseIp4Or6Cidr(Mopt.IP)
			if ipnet == nil {
				return false
			}
			var key6 Struct.Lpm_key6
			size, _ := ipnet.Mask.Size()
			key6.Prefixlen = uint32(size)
			ip, _ := Net.Ip6ToNetworkOrderBytes(ipnet.IP.String())
			key6.Ip = ip

			switch Mopt.Action {
			case Struct.OPT_ACTION_ADD:
				Moptok = AddOrDelRuleLpmMapOpt(obj, key6, Mopt, true)
			case Struct.OPT_ACTION_DEL:
				Moptok = AddOrDelRuleLpmMapOpt(obj, key6, Mopt, false)
			}
		}
	}

	if Lopt != nil {
		var tb_key Struct.Token_Bucket_key
		tb_key.Ifindex = uint32(Struct.Iface2Index[Lopt.IfName])
		var tb_key46 Struct.Tokens_Rate_Burst_Key
		tb_key46.Ifindex = uint32(Struct.Iface2Index[Lopt.IfName])
		var is_ipv4, is_proto bool
		is_proto = false
		if Lopt.Proto == "All" {
			tb_key.Category = uint8(Struct.Global_index)
			is_proto = true
		} else if Lopt.Proto == "TCP" {
			tb_key.Category = uint8(Struct.Tcp_index)
			is_proto = true
		} else if Lopt.Proto == "UDP" {
			tb_key.Category = uint8(Struct.Udp_index)
			is_proto = true
		} else {
			if ip46,ok := Net.ParseIp4Or6(Lopt.Proto, &is_ipv4); ok {
				if is_ipv4 {
					ip4, err := ip46.(uint32)
					if !err {
						Log.LogV(fmt.Sprintf("【ProcessOptOfMap】error when parse proto: %s", Lopt.Proto), 3)
						return false
					}
					tb_key46.Ip4 = ip4
				} else {
					ip6, err := ip46.([16]byte)
					if !err {
						Log.LogV(fmt.Sprintf("【ProcessOptOfMap】error when parse proto: %s", Lopt.Proto), 3)
						return false
					}
					tb_key46.Ip6 = ip6
				}
			}
		}	
		switch Lopt.Action {

		case Struct.OPT_ACTION_ADD:
			if is_proto {
				Loptok = AddOrDelLimitMapOpt(obj, Lopt, tb_key, false, true)
			} else {
				Loptok = AddOrDelLimitMapOpt(obj, Lopt, tb_key46, is_ipv4, true)
			}
		case Struct.OPT_ACTION_DEL:
			if is_proto  {
				Loptok = AddOrDelLimitMapOpt(obj, Lopt, tb_key, false, false)
			} else {
				Loptok = AddOrDelLimitMapOpt(obj, Lopt, tb_key46, is_ipv4, false)
			}
		case Struct.OPT_ACTION_UPD:
			if is_proto {
				Loptok = UpdLimitMapOpt(obj, Lopt, tb_key, false)
			} else {
				Loptok = UpdLimitMapOpt(obj, Lopt, tb_key46, is_ipv4)
			}
		}
	}

	if Mopt != nil && Lopt == nil {
		return Moptok
	}
	if Lopt != nil && Mopt == nil {
		return Loptok
	}
	if Lopt == nil && Mopt == nil {
		return false
	}
	return Moptok && Loptok
}

func AddRuleMapOpt(obj *ebpf.Collection, key interface{}, opt *Struct.MapOperation) bool {
	ebpf_map := Ebpf_map.Lookup_Map(obj, opt.MapType)
	
	action := 0
	if opt.RuleType == "white" {
		action = Struct.XDP_PASS
	} else if opt.RuleType == "black" {
		action = Struct.XDP_DROP
	}
	var key4 Struct.IpIfindex
	var key6 Struct.Ip6Ifindex
	var ok bool

	key4, ok = key.(Struct.IpIfindex)
	if !ok {
		//不是v4， 就是v6
		key6 = key.(Struct.Ip6Ifindex)
	}

	if opt.FullMode {
		inner_map := Ebpf_map.CreateNewInnerMap(ebpf.Hash, uint32(2), uint32(1), uint32(Struct.MAX_IFACES_PORTS), 0)
		for _, port := range opt.ToPortList {
			err := inner_map.Put(port, uint8(action))
			if err != nil {
				Log.LogV(fmt.Sprintf("【AddRuleMapOpt】error when updating inner map which parent map is %s, map'fd is %d, err is %s ", opt.MapType, inner_map.FD(), err.Error()), 3)
				return false
			}
		}
		Log.LogV(fmt.Sprintf("【AddRuleMapOpt】Success: Add port %v to inner map %d", opt.ToPortList, inner_map.FD()), 1)
		if ok {
			//v4
			err := ebpf_map.Put(key4, uint32(inner_map.FD()))
			if err != nil {
				Log.LogV(fmt.Sprintf("【AddRuleMapOpt】error when updating map: %s, err is %s [key: %v]", opt.MapType, err.Error(), key4), 3)
				return false
			}
			Log.LogV(fmt.Sprintf("【AddRuleMapOpt】Add key %v value %v to inner map %d", key4, opt.ToPortList, inner_map.FD()), 1)
		} else {
			err := ebpf_map.Put(key6, uint32(inner_map.FD()))
			if err != nil {
				Log.LogV(fmt.Sprintf("【AddRuleMapOpt】error when updating map %s, err is %s [key: %v]", opt.MapType, err.Error(), key6), 3)
				return false
			}
			Log.LogV(fmt.Sprintf("【AddRuleMapOpt】Add key %v value %v to inner map %d", key6, opt.ToPortList, inner_map.FD()), 1)
		}
	} else {
		var children_fd uint32
		var children_map *ebpf.Map
		var err error
		if ok {
			err = ebpf_map.Lookup(key4, &children_fd)
		} else {
			err = ebpf_map.Lookup(key6, &children_fd)
		}
		if err != nil {
		Log.LogV(fmt.Sprintf("【AddRuleMapOpt】error when look up elem in map: %s, err is %s ", opt.MapType, err.Error()), 3)
			return false
		}
		children_map, err = ebpf.NewMapFromID(ebpf.MapID(children_fd))

		if err != nil {
			Log.LogV(fmt.Sprintf("【AddRuleMapOpt】error when find inner map which parent map is %s err is %s", opt.MapType, err.Error()), 3)
			return false
		}

		err = children_map.Put(opt.ToPort, uint8(action))
		if err != nil {
			Log.LogV(fmt.Sprintf("【AddRuleMapOpt】error when put elem in map: %s, err is %s", opt.MapType, err.Error()), 3)
			return false
		}
		Log.LogV(fmt.Sprintf("【AddRuleMapOpt】Success: Add port %d to inner map %d", opt.ToPort, children_map.FD()), 1)
		if ok {
			err := ebpf_map.Update(key4, uint32(children_map.FD()), ebpf.UpdateAny)
			if err != nil {
				Log.LogV(fmt.Sprintf("【AddRuleMapOpt】error when update map: %s, err is %s [key: %v]", opt.MapType, err.Error(), key4), 3)
				return false
			}
			Log.LogV(fmt.Sprintf( "【AddRuleMapOpt】Success when update elem in map: %s [key: %v value: %d]", opt.MapType, key4, opt.ToPort), 1)
		} else {
			err := ebpf_map.Update(key6, uint32(children_map.FD()), ebpf.UpdateAny)
			if err != nil {
				Log.LogV(fmt.Sprintf("【AddRuleMapOpt】error when update map: %s, err is %s [key: %v]", opt.MapType, err.Error(), key6), 3)
				return false
			}
			Log.LogV(fmt.Sprintf( "【AddRuleMapOpt】success when update elem in map: %s [key: %v value: %d]", opt.MapType, key6, opt.ToPort), 1)
		}
	}
	return true
}

func DelRuleMapOpt(obj *ebpf.Collection, key interface{}, opt *Struct.MapOperation) bool {
	ebpf_map := Ebpf_map.Lookup_Map(obj, opt.MapType)
	
	var key4 Struct.IpIfindex
	var key6 Struct.Ip6Ifindex
	var ok bool
	var err error
	key4, ok = key.(Struct.IpIfindex)
	if !ok {
		key6, _ = key.(Struct.Ip6Ifindex)
	}

	if opt.FullMode {
		if ok {
			err = ebpf_map.Delete(key4)
			if err != nil {
				Log.LogV(fmt.Sprintf("【DelRuleMapOpt】error when deleting elem in map: %s, err is %s", opt.MapType, err.Error()), 3)
			return false
		}
			Log.LogV(fmt.Sprintf("【DelRuleMapOpt】Success delete port full mode [key: %v value: %v]",key4, opt.FromPortLists), 1);
		} else {
			err = ebpf_map.Delete(key6)
			if err != nil {
				Log.LogV(fmt.Sprintf("【DelRuleMapOpt】error when deleting elem in map: %s, err is %s", opt.MapType, err.Error()), 3)
				return false
			}
			Log.LogV(fmt.Sprintf("【DelRuleMapOpt】Success delete port full mode [key: %v value: %v]",key6, opt.FromPortLists), 1);
		}
	} else {
		var children_fd uint32
		if ok {
			err = ebpf_map.Lookup(key4, &children_fd)
		} else {
			err = ebpf_map.Lookup(key6, &children_fd)
		}
		if err != nil {
			Log.LogV(fmt.Sprintf("【DelRuleMapOpt】error when look up elem in map: %s, err is %s", opt.MapType, err.Error()), 3)
			return false
		}
		children_map, err := ebpf.NewMapFromID(ebpf.MapID(children_fd))
		if err != nil {
			Log.LogV(fmt.Sprintf("【DelRuleMapOpt】error when find inner map which parent map is %s, map's fd is %d, err is %s", opt.MapType, children_fd, err.Error()), 3)
			return false
		}

		err = children_map.Delete(opt.FromPort)
		if err != nil {
			Log.LogV(fmt.Sprintf("【DelRuleMapOpt】error when delete elem in map which parent map is %s, map'fd is %d, err is %s", opt.MapType, children_map.FD(), err.Error()), 3)
			return false
		}

		if ok {
			err = ebpf_map.Update(key4, uint32(children_map.FD()), ebpf.UpdateAny)
			if err != nil {
				Log.LogV(fmt.Sprintf("【DelRuleMapOpt】error when update elem in map: %s, err is %s [key: %v]", opt.MapType, err.Error(), key4), 3)
				return false
			}
			Log.LogV(fmt.Sprintf("【DelRuleMapOpt】Success delete some port [key: %v value: %d]", key4, opt.FromPort), 1);
		} else {
			err = ebpf_map.Update(key6, uint32(children_map.FD()), ebpf.UpdateAny)
			if err != nil {
				Log.LogV(fmt.Sprintf("【DelRuleMapOpt】error when update elem in map: %s, err is %s [key: %v]", opt.MapType, err.Error(), key6), 3)
				return false
			}
			Log.LogV(fmt.Sprintf("【DelRuleMapOpt】Success delete some port [key: %v value: %d]", key6, opt.FromPort), 1);
		}
	}
	return true
}

func UpdRuleMapOpt(obj *ebpf.Collection, key interface{}, opt *Struct.MapOperation) bool {
	ebpf_map := Ebpf_map.Lookup_Map(obj, opt.MapType)

	action := 0
	if opt.RuleType == "white" {
		action = Struct.XDP_PASS
	} else if opt.RuleType == "black" {
		action = Struct.XDP_DROP
	}

	var key4 Struct.IpIfindex
	var key6 Struct.Ip6Ifindex
	var ok bool
	var err error
	key4, ok = key.(Struct.IpIfindex)
	if !ok {
		key6 = key.(Struct.Ip6Ifindex)
	}

	var children_fd uint32
	if ok {
		err = ebpf_map.Lookup(&key4, &children_fd)
	} else {
		err = ebpf_map.Lookup(&key6, &children_fd)
	}
	if err != nil {
		Log.LogV(fmt.Sprintf("【UpdRuleMapOpt】error when look up elem in map: %s, err is %s", opt.MapType, err.Error()), 3)
		return false
	}
	children_map, err := ebpf.NewMapFromID(ebpf.MapID(children_fd))
	if err != nil {
		Log.LogV(fmt.Sprintf("【UpdRuleMapOpt】error when find inner map which parent map is %s, err is %s", opt.MapType, err.Error()), 3)
		return false
	}

	err = children_map.Delete(opt.FromPort)
	if err != nil {
		Log.LogV(fmt.Sprintf("【UpdRuleMapOpt】error when delete elem in map which parent map is %s, err is %s", opt.MapType, err.Error()), 3)
		return false
	}
	Log.LogV(fmt.Sprintf("【UpdRuleMapOpt】Success when delete elem in map which parent map is %s [value: %d]", opt.MapType, opt.FromPort), 1)
	
	err = children_map.Put(opt.ToPort, uint8(action))
	if err != nil {
		Log.LogV(fmt.Sprintf("【UpdRuleMapOpt】error when put elem in map which parent map is %s, err is %s", opt.MapType, err.Error()), 3)
		return false
	}
	Log.LogV(fmt.Sprintf("【UpdRuleMapOpt】Success when update elem in map which parent map is %s", opt.MapType), 1)

	if ok {
		err = ebpf_map.Update(key4, uint32(children_map.FD()), ebpf.UpdateAny)
		if err != nil {
			Log.LogV(fmt.Sprintf("【UpdRuleMapOpt】error when update elem in map: %s, err is %s [key: %v]", opt.MapType, err.Error(), key4), 3)
			return false
		}
		Log.LogV(fmt.Sprintf("【UpdRuleMapOpt】Success when update elem in map: %s [key: %v value: %d]", opt.MapType, key4, opt.ToPort), 1)
	} else {
		err = ebpf_map.Update(key6, uint32(children_map.FD()), ebpf.UpdateAny)
		if err != nil {
			Log.LogV(fmt.Sprintf("【UpdRuleMapOpt】error when update elem in map: %s, err is %s [key: %v]", opt.MapType, err.Error(), key6), 3)
			return false
		}
		Log.LogV(fmt.Sprintf("【UpdRuleMapOpt】Success when update elem in map: %s [key: %v value: %d]", opt.MapType, key6, opt.ToPort), 1)
	}
	return true
}

func AddOrDelRuleLpmMapOpt(obj *ebpf.Collection, key interface{}, opt *Struct.MapOperation, add_or_del bool) bool {
	ebpf_map := Ebpf_map.Lookup_Map(obj, opt.MapType)
	var key4 Struct.Lpm_key4
	var key6 Struct.Lpm_key6
	var ok bool

	action := 0
	if opt.RuleType == "white" {
		action = Struct.XDP_PASS
	} else if opt.RuleType == "black"{
		action = Struct.XDP_DROP
	}

	key4, ok = key.(Struct.Lpm_key4)
	if !ok {
		key6, _ = key.(Struct.Lpm_key6)
	}

	ifindex := Struct.Iface2Index[opt.IfName]

	if ok {
		if add_or_del {
			var children_fd uint32
			err := ebpf_map.Lookup(uint32(ifindex + 1), &children_fd)
			if err != nil {
				Log.LogV(fmt.Sprintf("【AddOrDelRuleLpmMapOpt】error when look up elem in map: %s, err is %s(not a error for lrm map)", opt.MapType, err.Error()), 2)
				children_map := Ebpf_map.CreateNewInnerMap(ebpf.LPMTrie, uint32(unsafe.Sizeof(key4)), 1, uint32(Struct.MAX_IFACES), 0x01)
				err := children_map.Put(key4, uint8(action))
				if err != nil {
					Log.LogV(fmt.Sprintf("【AddOrDelRuleLpmMapOpt】error when put elem into inner map which parent map is %s, map'fd is %d, err is %s", opt.MapType, children_map.FD(), err.Error()), 3)
					return false
				}
				err = ebpf_map.Update(uint32(ifindex + 1), uint32(children_map.FD()), ebpf.UpdateAny)
				if err != nil {
					Log.LogV(fmt.Sprintf("【AddOrDelRuleLpmMapOpt】error when update map %s, err is %s", opt.MapType, err.Error()), 3)
					return false
				}
				Log.LogV(fmt.Sprintf("【AddOrDelRuleLpmMapOpt】Success when add new rule to lpm map: %s [key: %v value: %d]", opt.MapType, key4, action), 1)
			} else {
				children_map, err := ebpf.NewMapFromID(ebpf.MapID(children_fd))
				if err != nil {
					Log.LogV(fmt.Sprintf("【AddOrDelRuleLpmMapOpt】error when find inner map which parent map is %s, err is %s", opt.MapType, err.Error()), 3)
					return false
				}
				err = children_map.Update(key4, uint8(action), ebpf.UpdateAny)
				if err != nil {
					Log.LogV(fmt.Sprintf("【AddOrDelRuleLpmMapOpt】error when update inner map which parent map is %s, err is %s", opt.MapType, err.Error()), 3)
					return false
				}
				err = ebpf_map.Update(uint32(ifindex + 1), uint32(children_map.FD()), ebpf.UpdateAny)
				if err != nil {
					Log.LogV(fmt.Sprintf("【AddOrDelRuleLpmMapOpt】error when update map %s, err is %s", opt.MapType, err.Error()), 3)
					return false
				}
				Log.LogV(fmt.Sprintf("【AddOrDelRuleLpmMapOpt】Success when add new rule to lpm map: %s [key: %v value: %d]", opt.MapType, key4, action), 1)
			}
		} else {
			var children_fd uint32
			err := ebpf_map.Lookup(uint32(ifindex + 1), &children_fd)
			if err != nil {
				Log.LogV(fmt.Sprintf("【AddOrDelRuleLpmMapOpt】error when look up elem in map: %s, err is %s", opt.MapType, err.Error()), 2)
				return false
			}
			children_map, err := ebpf.NewMapFromID(ebpf.MapID(children_fd))
			if err != nil {
				Log.LogV(fmt.Sprintf("【AddOrDelRuleLpmMapOpt】error when find inner map which parent map is %s, err is %s", opt.MapType, err.Error()), 3)
				return false
			}
			err = children_map.Delete(key4)
			if err != nil {
				Log.LogV(fmt.Sprintf("【AddOrDelRuleLpmMapOpt】error when delete elem in map: %s, err is %s",opt.MapType, err.Error()), 3)
				return false
			}
			err = ebpf_map.Update(uint32(ifindex + 1), uint32(children_map.FD()), ebpf.UpdateAny)
			if err != nil {
				Log.LogV(fmt.Sprintf("【AddOrDelRuleLpmMapOpt】error when update map: %s, err is %s", opt.MapType, err), 3)
				return false
			}
			Log.LogV(fmt.Sprintf("【AddOrDelRuleLpmMapOpt】Success when delete old rule to lpm map: %s [key: %v value: %d]", opt.MapType, key4, action), 1)
		}
	} else {
		//v6
		if add_or_del {
			//add
			var children_fd uint32
			err := ebpf_map.Lookup(uint32(ifindex + 1), &children_fd)
			if err != nil {
				Log.LogV(fmt.Sprintf("【AddOrDelRuleLpmMapOpt】error when look up elem in map: %s, err is %s(not a error for lrm map)", opt.MapType, err.Error()), 2)
				children_map := Ebpf_map.CreateNewInnerMap(ebpf.LPMTrie, 20, 1, uint32(Struct.MAX_IFACES), 0x01)
				err := children_map.Put(key6, uint8(action))
				if err != nil {
					Log.LogV(fmt.Sprintf("【AddOrDelRuleLpmMapOpt】error when put elem into inner map which parent map is %s, map'fd is %d, err is %s", opt.MapType, children_map.FD(), err.Error()), 3)
					return false
				}
				err = ebpf_map.Update(uint32(ifindex + 1), uint32(children_map.FD()), ebpf.UpdateAny)
				if err != nil {
					Log.LogV(fmt.Sprintf("【AddOrDelRuleLpmMapOpt】error when update map %s, err is %s", opt.MapType, err.Error()), 3)
					return false
				}
				Log.LogV(fmt.Sprintf("【AddOrDelRuleLpmMapOpt】Success when add new rule to lpm map: %s [key: %v value: %d]", opt.MapType, key6, action), 1)
			} else {
				children_map, err := ebpf.NewMapFromID(ebpf.MapID(children_fd))
				if err != nil {
					Log.LogV(fmt.Sprintf("【AddOrDelRuleLpmMapOpt】error when find inner map which parent map is %s, err is %s", opt.MapType, err.Error()), 3)
					return false
				}
				err = children_map.Update(key6, uint8(action), ebpf.UpdateAny)
				if err != nil {
					Log.LogV(fmt.Sprintf("【AddOrDelRuleLpmMapOpt】error when update inner map which parent map is %s, err is %s", opt.MapType, err.Error()), 3)
					return false
				}
				err = ebpf_map.Update(uint32(ifindex + 1), uint32(children_map.FD()), ebpf.UpdateAny)
				if err != nil {
					Log.LogV(fmt.Sprintf("【AddOrDelRuleLpmMapOpt】error when update map %s, err is %s", opt.MapType, err.Error()), 3)
					return false
				}
				Log.LogV(fmt.Sprintf("【AddOrDelRuleLpmMapOpt】Success when add new rule to lpm map: %s [key: %v value: %d]", opt.MapType, key6, action), 1)
			}
		} else {
			//del
			var children_fd uint32
			err := ebpf_map.Lookup(uint32(ifindex + 1), &children_fd)
			if err != nil {
				Log.LogV(fmt.Sprintf("【AddOrDelRuleLpmMapOpt】error when look up elem in map: %s, err is %s", opt.MapType, err.Error()), 2)
				return false
			}
			children_map, err := ebpf.NewMapFromID(ebpf.MapID(children_fd))
			if err != nil {
				Log.LogV(fmt.Sprintf("【AddOrDelRuleLpmMapOpt】error when find inner map which parent map is %s, err is %s", opt.MapType, err.Error()), 3)
				return false
			}
			err = children_map.Delete(key6)
			if err != nil {
				Log.LogV(fmt.Sprintf("【AddOrDelRuleLpmMapOpt】error when delete elem in map: %s, err is %s",opt.MapType, err.Error()), 3)
				return false
			}
			err = ebpf_map.Update(uint32(ifindex + 1), uint32(children_map.FD()), ebpf.UpdateAny)
			if err != nil {
				Log.LogV(fmt.Sprintf("【AddOrDelRuleLpmMapOpt】error when update map: %s, err is %s", opt.MapType, err), 3)
				return false
			}
			Log.LogV(fmt.Sprintf("【AddOrDelRuleLpmMapOpt】Success when delete old rule to lpm map: %s [key: %v value: %d]", opt.MapType, key6, action), 1)
		}
	}
	return true
}

func AddOrDelLimitMapOpt(obj *ebpf.Collection, opt *Struct.LimitOperation, key interface{}, is_ipv4, add_or_del bool) bool {
	var ebpf_map *ebpf.Map
	var ip_key Struct.Tokens_Rate_Burst_Key
	var tb_key Struct.Token_Bucket_key
	var add_tb_BRvalue, delete_tb_BRvalue Struct.Tokens_Rate_Burst_value
	var add_tb_Tvalue, delete_tb_Tvalue Struct.Token_Bucket_Value

	var is_ip bool

	ip_key, is_ip = key.(Struct.Tokens_Rate_Burst_Key)
	if !is_ip {
		tb_key, _ = key.(Struct.Token_Bucket_key)
	}

	add_tb_Tvalue = Struct.Token_Bucket_Value{
		Tokens: uint64(opt.TRB["Tokens"][1]),
		Last_update_time: 0,
	}
	delete_tb_Tvalue = Struct.Token_Bucket_Value{
		Tokens: uint64(opt.TRB["Tokens"][0]),
		Last_update_time: 0,
	}

	add_tb_BRvalue.Rate = uint64(opt.TRB["Rate"][1])
	add_tb_BRvalue.Burst = uint64(opt.TRB["Burst"][1])
	delete_tb_BRvalue.Rate = uint64(opt.TRB["Rate"][0])
	delete_tb_BRvalue.Burst = uint64(opt.TRB["Burst"][0])

	if !is_ip {
		ebpf_map = Ebpf_map.Lookup_Map(obj, Struct.Map_Token_Bucket_global)
		if add_or_del {
			err := ebpf_map.Put(tb_key, add_tb_Tvalue)
			if err != nil {
				Log.LogV(fmt.Sprintf("【AddOrDelLimitMapOpt】error when put elem into map: %s, err is %s", Struct.Map_Token_Bucket_global, err.Error()), 3)
				return false
			}
			Log.LogV(fmt.Sprintf("【AddOrDelLimitMapOpt】Success limit tokens add [key: %v value: %v]", tb_key, add_tb_Tvalue),1)
		} else {
			err := ebpf_map.Delete(tb_key)
			if err != nil {
				Log.LogV(fmt.Sprintf("【AddOrDelLimitMapOpt】error when delete elem map %s, err: %s", Struct.Map_Token_Bucket_global, err.Error()), 3)
				return false
			}
			Log.LogV(fmt.Sprintf("【AddOrDelLimitMapOpt】Success limit tokens delete [key: %v value: %v]", tb_key, delete_tb_Tvalue),1)
		}
		
		ebpf_map = Ebpf_map.Lookup_Map(obj, Struct.Map_Tb_Burst_Rate_global)
		if add_or_del {
			err := ebpf_map.Put(tb_key, add_tb_BRvalue)
			if err != nil {
				Log.LogV(fmt.Sprintf("【AddOrDelLimitMapOpt】error when put elem into map: %s, err: %s", Struct.Map_Tb_Burst_Rate_global, err.Error()), 3)
				return false
			}
			Log.LogV(fmt.Sprintf("【AddOrDelLimitMapOpt】Success limit br add [key: %v value: %v]", tb_key, add_tb_BRvalue),1)
		} else {
			err := ebpf_map.Delete(tb_key)
			if err != nil {
				Log.LogV(fmt.Sprintf("【AddOrDelLimitMapOpt】error when delete elem map: %s, err: %s", Struct.Map_Tb_Burst_Rate_global, err.Error()), 3)
				return false
			}
			Log.LogV(fmt.Sprintf("【AddOrDelLimitMapOpt】Success limit br delete [key: %v value: %v]", tb_key, delete_tb_BRvalue),1)
		}
	} else {
		if is_ipv4 {
			ebpf_map = Ebpf_map.Lookup_Map(obj, Struct.Map_Token_Bucket_Ip)
			if add_or_del {
				err := ebpf_map.Put(ip_key, add_tb_Tvalue)
				if err != nil {
					Log.LogV(fmt.Sprintf("【AddOrDelLimitMapOpt】error when put elem into map: %s, err is %s", Struct.Map_Token_Bucket_Ip, err.Error()), 3)
					return false
				}
				Log.LogV(fmt.Sprintf("【AddOrDelLimitMapOpt】Success limit tokens add [key: %v value: %v]", ip_key, add_tb_Tvalue),1)
			} else {
				err := ebpf_map.Delete(ip_key)
				if err != nil {
					Log.LogV(fmt.Sprintf("【AddOrDelLimitMapOpt】error when delete elem map %s, err: %s", Struct.Map_Token_Bucket_Ip, err.Error()), 3)
					return false
				}
				Log.LogV(fmt.Sprintf("【AddOrDelLimitMapOpt】Success limit tokens delete [key: %v value: %v]", ip_key, delete_tb_Tvalue),1)
			}

			ebpf_map = Ebpf_map.Lookup_Map(obj, Struct.Map_Tb_Rate_Burst_Pre_Ip)
			if add_or_del {
				err := ebpf_map.Put(ip_key, add_tb_BRvalue)
				if err != nil {
					Log.LogV(fmt.Sprintf("【AddOrDelLimitMapOpt】error when put elem into map: %s, err: %s", Struct.Map_Tb_Rate_Burst_Pre_Ip, err.Error()), 3)
					return false
				}
				Log.LogV(fmt.Sprintf("【AddOrDelLimitMapOpt】Success limit br add [key: %v value: %v]", ip_key, add_tb_BRvalue),1)
			} else {
				err := ebpf_map.Delete(ip_key)
				if err != nil {
					Log.LogV(fmt.Sprintf("【AddOrDelLimitMapOpt】error when delete elem map: %s, err: %s", Struct.Map_Tb_Rate_Burst_Pre_Ip, err.Error()), 3)
					return false
				}
				Log.LogV(fmt.Sprintf("【AddOrDelLimitMapOpt】Success limit br delete [key: %v value: %v]", ip_key, delete_tb_BRvalue),1)
			}
		} else {
			ebpf_map = Ebpf_map.Lookup_Map(obj, Struct.Map_Token_Bucket_Ip6)
			if add_or_del {
				err := ebpf_map.Put(ip_key, add_tb_Tvalue)
				if err != nil {
					Log.LogV(fmt.Sprintf("【AddOrDelLimitMapOpt】error when put elem into map: %s, err is %s", Struct.Map_Token_Bucket_Ip6, err.Error()), 3)
					return false
				}
				Log.LogV(fmt.Sprintf("【AddOrDelLimitMapOpt】Success limit tokens add [key: %v value: %v]", ip_key, add_tb_Tvalue),1)
			} else {
				err := ebpf_map.Delete(ip_key)
				if err != nil {
					Log.LogV(fmt.Sprintf("【AddOrDelLimitMapOpt】error when delete elem map %s, err: %s", Struct.Map_Token_Bucket_Ip6, err.Error()), 3)
					return false
				}
				Log.LogV(fmt.Sprintf("【AddOrDelLimitMapOpt】Success limit tokens delete [key: %v value: %v]", ip_key, delete_tb_Tvalue),1)
			}
			ebpf_map = Ebpf_map.Lookup_Map(obj, Struct.Map_Tb_Rate_Burst_Pre_Ip6)
			if add_or_del {
				err := ebpf_map.Put(ip_key, add_tb_BRvalue)
				if err != nil {
					Log.LogV(fmt.Sprintf("【AddOrDelLimitMapOpt】error when put elem into map: %s, err: %s", Struct.Map_Tb_Rate_Burst_Pre_Ip6, err.Error()), 3)
					return false
				}
				Log.LogV(fmt.Sprintf("【AddOrDelLimitMapOpt】Success limit br add [key: %v value: %v]", ip_key, add_tb_BRvalue),1)
			} else {
				err := ebpf_map.Delete(ip_key)
				if err != nil {
					Log.LogV(fmt.Sprintf("【AddOrDelLimitMapOpt】error when delete elem map: %s, err: %s", Struct.Map_Tb_Rate_Burst_Pre_Ip6, err.Error()), 3)
					return false
				}
				Log.LogV(fmt.Sprintf("【AddOrDelLimitMapOpt】Success limit br delete [key: %v value: %v]", ip_key, delete_tb_BRvalue),1)
			}
		}
	}
	return true
}

func UpdLimitMapOpt(obj *ebpf.Collection, opt *Struct.LimitOperation, key interface{}, is_ipv4 bool) bool {
	var ip_key Struct.Tokens_Rate_Burst_Key
	var tb_key Struct.Token_Bucket_key
	var upd_tb_BRvalue  Struct.Tokens_Rate_Burst_value
	var upd_tb_Tvalue  Struct.Token_Bucket_Value
	var is_ip, is_burst, is_rate bool

	ip_key, is_ip = key.(Struct.Tokens_Rate_Burst_Key)
	if !is_ip {
		tb_key, _ = key.(Struct.Token_Bucket_key)
	}

	if !is_ip {
		for Type, _ := range opt.TRB {
			if Type == "Tokens" {
				upd_tb_Tvalue.Tokens = uint64(opt.TRB["Tokens"][1])
				upd_tb_Tvalue.Last_update_time = uint64(0)
				
				ebpf_map := Ebpf_map.Lookup_Map(obj, Struct.Map_Token_Bucket_global)
				err := ebpf_map.Update(tb_key, upd_tb_Tvalue, ebpf.UpdateAny)
				if err != nil {
					Log.LogV(fmt.Sprintf("【UpdLimitMapOpt】error when update map: %s, err is %s", Struct.Map_Token_Bucket_global, err.Error()), 3)
					return false
				}
				Log.LogV(fmt.Sprintf("【UpdLimitMapOpt】Success limit tokens update [key: %v value: %v]", tb_key, upd_tb_Tvalue), 1)
			} else if Type == "Burst" {
				is_burst = true
			} else if Type == "Rate" {
				is_rate = true
			}
		}
		if is_burst || is_rate {
			ebpf_map := Ebpf_map.Lookup_Map(obj, Struct.Map_Tb_Burst_Rate_global)
			err := ebpf_map.Lookup(tb_key, upd_tb_BRvalue)
			if err != nil {
				Log.LogV(fmt.Sprintf("【UpdRuleMapOpt】error when look up elem in map: %s, err is %s", Struct.Map_Tb_Burst_Rate_global, err.Error()), 3)
				return false
			}
			upd_tb_BRvalue.Burst = uint64(opt.TRB["Burst"][1])
			upd_tb_BRvalue.Rate = uint64(opt.TRB["Rate"][1])
			err = ebpf_map.Update(tb_key, upd_tb_BRvalue, ebpf.UpdateAny)
			if err != nil {
				Log.LogV(fmt.Sprintf("【UpdRuleMapOpt】error when update map %s, err is %s", Struct.Map_Tb_Burst_Rate_global, err.Error()), 3)
				return false
			}
			Log.LogV(fmt.Sprintf("【UpdLimitMapOpt】Success limit br update [key: %v value: %v]", tb_key, upd_tb_BRvalue), 1)
		}
	} else {
		if is_ipv4 {
			for Type, _ := range opt.TRB {
				if Type == "Tokens" {
					upd_tb_Tvalue.Tokens = uint64(opt.TRB["Tokens"][1])
					ebpf_map := Ebpf_map.Lookup_Map(obj, Struct.Map_Token_Bucket_Ip)
					err := ebpf_map.Update(ip_key, upd_tb_Tvalue, ebpf.UpdateAny)
					if err != nil {
						Log.LogV(fmt.Sprintf("【UpdLimitMapOpt】error when update map: %s, err is %s", Struct.Map_Token_Bucket_Ip, err.Error()), 3)
						return false
					}
				} else if Type == "Burst" {
					is_burst = true
				} else if Type == "Rate" {
					is_rate = true
				}
			}
			if is_burst || is_rate {
				ebpf_map := Ebpf_map.Lookup_Map(obj, Struct.Map_Tb_Rate_Burst_Pre_Ip)
				err := ebpf_map.Lookup(ip_key, &upd_tb_BRvalue)
				if err != nil {
					Log.LogV(fmt.Sprintf("【UpdRuleMapOpt】error when look up elem in map: %s, err is %s", Struct.Map_Tb_Rate_Burst_Pre_Ip, err.Error()), 3)
					return false
				}
				upd_tb_BRvalue.Burst = uint64(opt.TRB["Burst"][1])
				upd_tb_BRvalue.Rate = uint64(opt.TRB["Rate"][1])
				err = ebpf_map.Update(ip_key, upd_tb_BRvalue, ebpf.UpdateAny)
				if err != nil {
					Log.LogV(fmt.Sprintf("【UpdRuleMapOpt】error when update map %s, err is %s", Struct.Map_Tb_Rate_Burst_Pre_Ip, err.Error()), 3)
					return false
				}
				Log.LogV(fmt.Sprintf("【UpdLimitMapOpt】Success limit br update [key: %v value: %v]", ip_key, upd_tb_BRvalue), 1)
			}
		} else {
			for Type, _ := range opt.TRB {
				if Type == "Tokens" {
					upd_tb_Tvalue.Tokens = uint64(opt.TRB["Tokens"][1])
					ebpf_map := Ebpf_map.Lookup_Map(obj, Struct.Map_Token_Bucket_Ip6)
					err := ebpf_map.Update(ip_key, upd_tb_Tvalue, ebpf.UpdateAny)
					if err != nil {
						Log.LogV(fmt.Sprintf("【UpdLimitMapOpt】error when update map: %s, err is %s", Struct.Map_Token_Bucket_Ip6, err.Error()), 3)
						return false
					}
				} else if Type == "Burst" {
					is_burst = true
				} else if Type == "Rate" {
					is_rate = true
				}
			}
			if is_burst || is_rate {
				ebpf_map := Ebpf_map.Lookup_Map(obj, Struct.Map_Tb_Rate_Burst_Pre_Ip6)
				err := ebpf_map.Lookup(ip_key, &upd_tb_BRvalue)
				if err != nil {
					Log.LogV(fmt.Sprintf("【UpdRuleMapOpt】error when look up elem in map: %s, err is %s", Struct.Map_Tb_Rate_Burst_Pre_Ip6, err.Error()), 3)
					return false
				}
				upd_tb_BRvalue.Burst = uint64(opt.TRB["Burst"][1])
				upd_tb_BRvalue.Rate = uint64(opt.TRB["Rate"][1])
				err = ebpf_map.Update(ip_key, upd_tb_BRvalue, ebpf.UpdateAny)
				if err != nil {
					Log.LogV(fmt.Sprintf("【UpdRuleMapOpt】error when update map %s, err is %s", Struct.Map_Tb_Rate_Burst_Pre_Ip6, err.Error()), 3)
					return false
				}
				Log.LogV(fmt.Sprintf("【UpdLimitMapOpt】Success limit br update [key: %v value: %v]", ip_key, upd_tb_BRvalue), 1)
			}
		}
	}
	return true
}