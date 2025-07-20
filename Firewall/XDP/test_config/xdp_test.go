package testconfig_test

import (
	"fmt"
	"runtime/debug"
	"testing"

	Init "github.com/CAINIAOJL/bpftrace-exporter/Firewall/XDP/Init"
	Log "github.com/CAINIAOJL/bpftrace-exporter/Firewall/XDP/log"
	Net "github.com/CAINIAOJL/bpftrace-exporter/Firewall/XDP/net"
	Parse "github.com/CAINIAOJL/bpftrace-exporter/Firewall/XDP/parse"
	Struct "github.com/CAINIAOJL/bpftrace-exporter/Firewall/XDP/strcut"
	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
)

type Expected_Rule struct {
	ExpectedRules        Struct.Rule
	Expectedaction       uint8
	ExpectedIface        string       
}

type Expected_Limit struct {
	ExpectedLimit     	map[string]Struct.TokenBucket 
	Expectediface       string 
}

var (
	lo_white_ip_rule_first 			Expected_Rule
	lo_black_ip_rule_first 			Expected_Rule
	ens33_white_ip_rule_first 		Expected_Rule
	ens33_black_ip_rule_first       Expected_Rule
	lo_limit_first                  Expected_Limit
	ens33_limit_first               Expected_Limit

	lo_white_ip_rule_second 		Expected_Rule
	lo_black_ip_rule_second			Expected_Rule

	lo_limit_second                 Expected_Limit

)

func FillLimit(el *Expected_Limit, proto string, tokens, burst, rate int64) {
	limit, exist := el.ExpectedLimit[proto]
	if !exist {
		limit = Struct.TokenBucket{}
	}
	limit.Burst = burst
	limit.Rate = rate
	limit.Tokens = tokens
	el.ExpectedLimit[proto] = limit
}

func ExpectedConfig_InitOfFirst() {
	lo_white_ip_rule_first.Expectedaction = uint8(Struct.XDP_PASS)
	lo_white_ip_rule_first.ExpectedIface = "lo"

	lo_white_ip_rule_first.ExpectedRules = Struct.Rule{
		Ip4s: map[string][]uint16{
			"247.94.70.231": {12567},
			"179.227.59.143/20": {},
			"111.52.201.89": {11230, 12568, 26665},
			"135.107.250.138": {11240},
			"222.93.222.124": {11111, 22222, 33333},
			"223.207.41.215": {11111, 22222, 33333},
		},
		Ip6s: map[string][]uint16{
			"FE88:D5C3:81E2:A3AB:70AF:FCC1:9818:46BA": {11230, 11240},
			"9BE1:0D18:B5F3:AF71:AC82:B208:2E3C:95D2/64": {},
			"DF7B:4867:D29B:AF14:03DB:B8B9:782C:BE6F": {11280, 15689, 25056},
			"19CE:C1EB:71A0:407B:DD97:FC43:C8B4:A2B8": {56201},
			"91A6:78FC:A24A:4108:FCAB:6F1A:91FD:90EF": {11111, 22222, 33333},
			"19B6:D301:2F0A:904D:1DB1:8E99:BC18:900B": {11111, 22222, 33333},
		},
	}

	lo_black_ip_rule_first.Expectedaction = uint8(Struct.XDP_DROP)
	lo_black_ip_rule_first.ExpectedIface = "lo"

	lo_black_ip_rule_first.ExpectedRules = Struct.Rule{
		Ip4s: map[string][]uint16{
			"161.93.187.53": {12560},
			"16.241.137.207/20": {},
			"167.84.79.221": {12540, 13260, 13698},
			"79.116.134.17": {14789},
		},
		Ip6s: map[string][]uint16{
			"29EF:6EFC:05CC:410F:9890:4EA9:83D2:0C71": {12560},
			"4AA3:6E6A:B5FC:83A6:27BD:22B7:00D9:FCD7/64": {},
			"287B:66B8:77DA:536E:D6DC:7F18:ABAF:9C9C": {12501, 16523, 10254},
			"B9CC:C5B3:00B4:53D0:1399:7E93:6A01:8195": {65489},
		},
	}

	lo_limit_first.ExpectedLimit = make(map[string]Struct.TokenBucket)
	lo_limit_first.Expectediface = "lo"
	FillLimit(&lo_limit_first, "All", 250, 500, 1000)
	FillLimit(&lo_limit_first, "84.255.140.57", 250, 500, 1000)
	FillLimit(&lo_limit_first, "C6DD:605B:F294:D152:4AA2:A807:D529:09CB", 250, 500, 1000)
	FillLimit(&lo_limit_first, "147.104.38.135", 250, 500, 1000)
	FillLimit(&lo_limit_first, "FC40:BB7B:C046:84B7:D41E:981C:7433:B021", 250, 500, 1000)

	
	ens33_white_ip_rule_first.Expectedaction = uint8(Struct.XDP_PASS)
	ens33_white_ip_rule_first.ExpectedIface = "ens33"
	ens33_white_ip_rule_first.ExpectedRules = Struct.Rule{
		Ip4s: map[string][]uint16{
			"247.94.70.231": {12567},
			"179.227.59.143/20": {},
			"111.52.201.89": {11230, 12568, 26665},
			"135.107.250.138": {11240},
			"222.93.222.124": {11111, 22222, 33333},
			"223.207.41.215": {11111, 22222, 33333},
		},
		Ip6s: map[string][]uint16{
			"FE88:D5C3:81E2:A3AB:70AF:FCC1:9818:46BA": {11230, 11240},
			"9BE1:0D18:B5F3:AF71:AC82:B208:2E3C:95D2/64": {},
			"DF7B:4867:D29B:AF14:03DB:B8B9:782C:BE6F": {11280, 15689, 25056},
			"19CE:C1EB:71A0:407B:DD97:FC43:C8B4:A2B8": {56201},
			"91A6:78FC:A24A:4108:FCAB:6F1A:91FD:90EF": {11111, 22222, 33333},
			"19B6:D301:2F0A:904D:1DB1:8E99:BC18:900B": {11111, 22222, 33333},
		},
	}

	ens33_black_ip_rule_first.Expectedaction = uint8(Struct.XDP_DROP)	
	ens33_black_ip_rule_first.ExpectedIface = "ens33"
	ens33_black_ip_rule_first.ExpectedRules = Struct.Rule{
		Ip4s: map[string][]uint16{
			"161.93.187.53": {12560},
			"16.241.137.207/20": {},
			"167.84.79.221": {12540, 13260, 13698},
			"79.116.134.17": {14789},
		},
		Ip6s: map[string][]uint16{
			"29EF:6EFC:05CC:410F:9890:4EA9:83D2:0C71": {12560},
			"4AA3:6E6A:B5FC:83A6:27BD:22B7:00D9:FCD7/64": {},
			"287B:66B8:77DA:536E:D6DC:7F18:ABAF:9C9C": {12501, 16523, 10254},
			"B9CC:C5B3:00B4:53D0:1399:7E93:6A01:8195": {65489},
		},
	}

	ens33_limit_first.ExpectedLimit = make(map[string]Struct.TokenBucket)
	ens33_limit_first.Expectediface = "ens33"
	FillLimit(&ens33_limit_first, "All", 250, 500, 1000)
	FillLimit(&ens33_limit_first, "84.255.140.57", 250, 500, 1000)
	FillLimit(&ens33_limit_first, "C6DD:605B:F294:D152:4AA2:A807:D529:09CB", 250, 500, 1000)
	FillLimit(&ens33_limit_first, "147.104.38.135", 250, 500, 1000)
	FillLimit(&ens33_limit_first, "FC40:BB7B:C046:84B7:D41E:981C:7433:B021", 250, 500, 1000)

}

func ExpectedConfig_InitOfSecond() {
	lo_white_ip_rule_second.Expectedaction = uint8(Struct.XDP_PASS)
	lo_white_ip_rule_second.ExpectedIface = "lo"
	lo_white_ip_rule_second.ExpectedRules = Struct.Rule{
		Ip4s: map[string][]uint16{
			"247.94.70.231": {12567, 12568, 15847},
			"172.28.131.63/20": {},
			"111.52.201.89": {11230},
			"113.121.156.152": {11250},
			"222.93.222.124": {11111, 22222, 44444},
			"223.207.41.215": {11111, 55555, 33333},
		},
		Ip6s: map[string][]uint16{
			"FE88:D5C3:81E2:A3AB:70AF:FCC1:9818:46BA": {11230, 11240, 11250},
			"8D51:4233:E508:33B7:6FCB:39AF:EABE:9C66/64": {},
			"DF7B:4867:D29B:AF14:03DB:B8B9:782C:BE6F": {11280},
			"D23E:964E:0F37:63AA:C559:4EF9:2D86:9491": {56321},
			"91A6:78FC:A24A:4108:FCAB:6F1A:91FD:90EF": {11111, 44444, 33333},
			"19B6:D301:2F0A:904D:1DB1:8E99:BC18:900B": {11111, 11223, 55555},
		},
	}

	lo_black_ip_rule_second.Expectedaction = uint8(Struct.XDP_DROP)
	lo_black_ip_rule_second.ExpectedIface = "lo"
	lo_black_ip_rule_second.ExpectedRules = Struct.Rule{
		Ip4s: map[string][]uint16{
			"161.93.187.53": {12560, 12589},
			"63.125.141.118/20": {},
			"167.84.79.221": {12540},
			"115.194.150.41": {54789},
		},
		Ip6s: map[string][]uint16{
			"29EF:6EFC:05CC:410F:9890:4EA9:83D2:0C71": {12560, 21325},
			"239A:255A:D76F:B044:8295:D25C:2042:CDD7/64": {},
			"287B:66B8:77DA:536E:D6DC:7F18:ABAF:9C9C": {12501},
			"9556:F993:306E:A5A2:58A5:B971:B50C:6F7C": {12589},
		},
	}

	lo_limit_second.Expectediface = "lo"
	lo_limit_second.ExpectedLimit = make(map[string]Struct.TokenBucket)

	FillLimit(&lo_limit_second, "TCP", 250, 500, 1000)
	FillLimit(&lo_limit_second, "2.229.60.131", 250, 500, 1000)
	FillLimit(&lo_limit_second, "5AB0:6BA7:C8F9:43FA:C1FA:7084:AD76:D822", 250, 500, 1000)
	FillLimit(&lo_limit_second, "147.104.38.135", 25001, 5007, 100087)
	FillLimit(&lo_limit_second, "FC40:BB7B:C046:84B7:D41E:981C:7433:B021", 25026, 50015, 100056)

}	



func TestXDPDynamicConfig(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("panic recovered: %v\n%s", r, debug.Stack())
		}
	}()
	//第一次初始化配置，验证配置是否加上
	ExpectedConfig_InitOfFirst()
	Init.Go_Init(true, "/home/cainiao/bpftrace-exporter/Firewall/XDP/xdp_old.yaml", "/home/cainiao/bpftrace-exporter/Firewall/build/xdp/xdp.o")
	t.Log("第一次初始化配置完成，解析配置测试：\n")
	AssertConfigOfFirst(t, &lo_white_ip_rule_first, nil)
	AssertConfigOfFirst(t, &lo_black_ip_rule_first, &lo_limit_first)
	AssertConfigOfFirst(t, &ens33_white_ip_rule_first, nil)
	AssertConfigOfFirst(t, &ens33_black_ip_rule_first, &ens33_limit_first)

	//第二次初始化配置，验证配置是否加上
	ExpectedConfig_InitOfSecond()
	Parse.ParseConfig("/home/cainiao/bpftrace-exporter/Firewall/XDP/xdd_new.yaml", false)
	t.Log("第二次初始化配置完成，解析配置测试：\n")
	AssertConfigOfFirst(t, &lo_white_ip_rule_second, nil)
	AssertConfigOfFirst(t, &lo_black_ip_rule_second, &lo_limit_second)

	//第三次初始化配置，验证配置是否加上
	Parse.ParseConfig("/home/cainiao/bpftrace-exporter/Firewall/XDP/xdp_old.yaml", false)
	t.Log("第三次初始化配置完成，解析配置测试：\n")
	AssertConfigOfFirst(t, &lo_white_ip_rule_first, nil)
	AssertConfigOfFirst(t, &lo_black_ip_rule_first, &lo_limit_first)
}

func logRuleFail(t *testing.T, mapName, iface, ip string, port *uint16, err error) {
	ipType := "IP"
	if Net.JudgeIpIsCidr(ip) {
		ipType = "CIDR"
	}

	if port != nil {
		t.Fatalf("[Failed] map: %s | iface: %s | %s: %s | port: %d | err: %s",
			mapName, iface, ipType, ip, *port, err.Error())
	} else {
		t.Fatalf("[Failed] map: %s | iface: %s | %s: %s | err: %s",
			mapName, iface, ipType, ip, err.Error())
	}
}

func logLimitFail(t *testing.T, mapName, iface, proto string, err error) {
	t.Fatalf("[Failed] map: %s | iface: %s | proto: %s | err: %s", mapName, iface, proto, err.Error())
}

func AssertConfigOfFirst(t *testing.T, Expected_Rule *Expected_Rule, Expected_Limit *Expected_Limit) {
	for ip, ports := range Expected_Rule.ExpectedRules.Ip4s {
		ebpf_map := Struct.Obj.Maps[Struct.Map_Rule]
		if len(ports) == 0 {
			ebpf_map := Struct.Obj.Maps[Struct.Map_Lpm_Rule]
			ipnet:= Net.ParseIp4Or6Cidr(ip)
			Log.LogV(fmt.Sprintf("ipnet is %v", ipnet), 1)
			size,_ := ipnet.Mask.Size()
			key4, err := Net.Ip4ToNetworkOrderUint32(ipnet.IP.String())
			if err != nil {
				logRuleFail(t, Struct.Map_Lpm_Rule, Expected_Rule.ExpectedIface, ip, nil, err)
			}
			map_ley := Struct.Lpm_key4 {
				Prefixlen: uint32(size),
				Ip: key4,
			}
			var children_fd uint32
			err = ebpf_map.Lookup(uint32(Struct.Iface2Index[Expected_Rule.ExpectedIface] + 1), &children_fd)
			if err != nil {
				logRuleFail(t, Struct.Map_Lpm_Rule, Expected_Rule.ExpectedIface, ip, nil, err)
			}
			inner_map,err := ebpf.NewMapFromID(ebpf.MapID(children_fd))
			if err != nil {
				logRuleFail(t, Struct.Map_Lpm_Rule, Expected_Rule.ExpectedIface, ip, nil, err)
			}
			var action uint8
			err = inner_map.Lookup(map_ley, &action)
			if err != nil {
				logRuleFail(t, Struct.Map_Lpm_Rule, Expected_Rule.ExpectedIface, ip, nil, err)
			}
			assert.Equal(t, Expected_Rule.Expectedaction, action)
			t.Logf("[Success] map: %s | iface: %s | CIDR: %s | action: %d", Struct.Map_Lpm_Rule, Expected_Rule.ExpectedIface, ip, action)
			continue
		}

		key4, err := Net.Ip4ToNetworkOrderUint32(ip)
		if err != nil {
			logRuleFail(t, Struct.Map_Rule, Expected_Rule.ExpectedIface, ip, nil, err)
		}
		map_key := Struct.IpIfindex {
			Ip: key4,
			Ifindex: uint32(Struct.Iface2Index[Expected_Rule.ExpectedIface]),
		}
		var children_fd uint32
		err = ebpf_map.Lookup(map_key, &children_fd)
		if err != nil {
			logRuleFail(t, Struct.Map_Rule, Expected_Rule.ExpectedIface, ip, nil, err)
		}
		inner_map, err := ebpf.NewMapFromID(ebpf.MapID(children_fd))
		if err != nil {
			logRuleFail(t, Struct.Map_Rule, Expected_Rule.ExpectedIface, ip, nil, err)
		}
		for _, port := range ports {
			var action uint8
			err = inner_map.Lookup(port, &action)
			if err != nil {
				logRuleFail(t, Struct.Map_Rule, Expected_Rule.ExpectedIface, ip, &port, err)
			}
			assert.Equal(t, Expected_Rule.Expectedaction, action)
			t.Logf("[Success] map: %s | iface: %s | IP: %s | port: %d | action: %d", Struct.Map_Rule, Expected_Rule.ExpectedIface, ip, port, action)
		}
	}

	for ip, ports := range Expected_Rule.ExpectedRules.Ip6s {
		ebpf_map := Struct.Obj.Maps[Struct.Map_Rule6]
		if len(ports) == 0 {
			ebpf_map := Struct.Obj.Maps[Struct.Map_Lpm_Rule6]
			ipnet:= Net.ParseIp4Or6Cidr(ip)
			size, _ := ipnet.Mask.Size()
			key6, err := Net.Ip6ToNetworkOrderBytes(ipnet.IP.String())
			if err != nil {
				logRuleFail(t, Struct.Map_Lpm_Rule6, Expected_Rule.ExpectedIface, ip, nil, err)
			}
			map_ley := Struct.Lpm_key6 {
				Prefixlen: uint32(size),
				Ip: key6,
			}
			var children_fd uint32
			err = ebpf_map.Lookup(uint32(Struct.Iface2Index[Expected_Rule.ExpectedIface] + 1), &children_fd)
			if err != nil {
				logRuleFail(t, Struct.Map_Lpm_Rule6, Expected_Rule.ExpectedIface, ip, nil, err)
			}
			inner_map,err := ebpf.NewMapFromID(ebpf.MapID(children_fd))
			if err != nil {
				logRuleFail(t, Struct.Map_Lpm_Rule6, Expected_Rule.ExpectedIface, ip, nil, err)
			}
			var action uint8
			err = inner_map.Lookup(map_ley, &action)
			if err != nil {
				logRuleFail(t, Struct.Map_Lpm_Rule6, Expected_Rule.ExpectedIface, ip, nil, err)
			}
			assert.Equal(t, Expected_Rule.Expectedaction, action)
			t.Logf("[Success] map: %s | iface: %s | CIDR: %s | action: %d", Struct.Map_Lpm_Rule6, Expected_Rule.ExpectedIface, ip, action)
			continue
		}

		key6, err := Net.Ip6ToNetworkOrderBytes(ip)
		if err != nil {
			logRuleFail(t, Struct.Map_Rule6, Expected_Rule.ExpectedIface, ip, nil, err)
		}
		map_key := Struct.Ip6Ifindex {
			IP: key6,
			Ifindex: uint32(Struct.Iface2Index[Expected_Rule.ExpectedIface]),
		}
		var children_fd uint32
		err = ebpf_map.Lookup(map_key, &children_fd)
		if err != nil {
			logRuleFail(t, Struct.Map_Rule6, Expected_Rule.ExpectedIface, ip, nil, err)
		}
		inner_map, err := ebpf.NewMapFromID(ebpf.MapID(children_fd))
		if err != nil {
			logRuleFail(t, Struct.Map_Rule6, Expected_Rule.ExpectedIface, ip, nil, err)
		}
		for _, port := range ports {
			var action uint8
			err = inner_map.Lookup(port, &action)
			if err != nil {
				logRuleFail(t, Struct.Map_Rule6, Expected_Rule.ExpectedIface, ip, &port, err)
			}
			assert.Equal(t, Expected_Rule.Expectedaction, action)
			t.Logf("[Success] map: %s | iface: %s | IP: %s | port: %d | action: %d", Struct.Map_Rule6, Expected_Rule.ExpectedIface, ip, port, action)
		}
	}

	if Expected_Limit != nil {
		for proto, counts := range Expected_Limit.ExpectedLimit {
			//var token_value []Struct.Token_Bucket_Value
			var br_value Struct.Tokens_Rate_Burst_value
			if proto == "All" || proto == "TCP" || proto == "UDP" {
				Log.LogV(fmt.Sprintf("proto: %s, counts: %v",proto, counts), 1)
				var category uint8
				if proto == "All" {
					category = uint8(Struct.Global_index)
				} else if proto == "TCP" {
					category = uint8(Struct.Tcp_index)
				} else if proto == "UDP" {
					category = uint8(Struct.Udp_index)
				}
				token_key := Struct.Token_Bucket_key {
					Ifindex: uint32(Struct.Iface2Index[Expected_Limit.Expectediface]),
					Category: category,
				}
				//动态变化,暂时不检测
				//ebpf_map := Struct.Obj.Maps[Struct.Map_Token_Bucket_global]
				//err := ebpf_map.Lookup(token_key, &token_value)
				//if err != nil {
					//logLimitFail(t, Struct.Map_Token_Bucket_global, Expected_Limit.Expectediface, proto, err)
				//}
				//assert.Equal(t, counts.Tokens, token_value)
				ebpf_map := Struct.Obj.Maps[Struct.Map_Tb_Burst_Rate_global]
				err := ebpf_map.Lookup(token_key, &br_value)
				if err != nil {
					logLimitFail(t, Struct.Map_Tb_Burst_Rate_global, Expected_Limit.Expectediface, proto, err)
				}
				assert.Equal(t, uint64(counts.Burst), br_value.Burst)
				assert.Equal(t, uint64(counts.Rate), br_value.Rate)
				t.Logf("[Success] map: %s | iface: %s | proto: %s | count: %d", Struct.Map_Tb_Burst_Rate_global, Expected_Rule.ExpectedIface, "Burst", counts.Burst)
				t.Logf("[Success] map: %s | iface: %s | proto: %s | count: %d", Struct.Map_Tb_Burst_Rate_global, Expected_Rule.ExpectedIface, "Rate", counts.Rate)
			} else {
				var is_ipv4 bool
				key, ok := Net.ParseIp4Or6(proto, &is_ipv4)
				if ok {
					if is_ipv4 {
						Log.LogV(fmt.Sprintf("proto: %s, counts: %v",proto, counts), 1)
						ebpf_map := Struct.Obj.Maps[Struct.Map_Tb_Rate_Burst_Pre_Ip]
						key4, _ := key.(uint32)
						key := Struct.Tokens_Rate_Burst_Key{
							Ip4: key4,
							Ifindex: uint32(Struct.Iface2Index[Expected_Limit.Expectediface]),
						}
						err := ebpf_map.Lookup(key, &br_value)
						if err != nil {
							logLimitFail(t, Struct.Map_Tb_Rate_Burst_Pre_Ip, Expected_Limit.Expectediface, proto, err)
						}
						assert.Equal(t, uint64(counts.Burst), br_value.Burst)
						assert.Equal(t, uint64(counts.Rate), br_value.Rate)
						t.Logf("[Success] map: %s | iface: %s | proto: %s | count: %d", Struct.Map_Tb_Rate_Burst_Pre_Ip, Expected_Rule.ExpectedIface, "Burst", counts.Burst)
						t.Logf("[Success] map: %s | iface: %s | proto: %s | count: %d", Struct.Map_Tb_Rate_Burst_Pre_Ip, Expected_Rule.ExpectedIface, "Rate", counts.Rate)
					} else {
						Log.LogV(fmt.Sprintf("proto: %s, counts: %v",proto, counts), 1)
						ebpf_map := Struct.Obj.Maps[Struct.Map_Tb_Rate_Burst_Pre_Ip6]
						key6, _ := key.([16]byte)
						key := Struct.Tokens_Rate_Burst_Key{
							Ip6: key6,
							Ifindex: uint32(Struct.Iface2Index[Expected_Limit.Expectediface]),
						}
						err := ebpf_map.Lookup(key, &br_value)
						if err != nil {
							logLimitFail(t, Struct.Map_Tb_Rate_Burst_Pre_Ip6, Expected_Limit.Expectediface, proto, err)
						}
						assert.Equal(t, uint64(counts.Burst), br_value.Burst)
						assert.Equal(t, uint64(counts.Rate), br_value.Rate)
						t.Logf("[Success] map: %s | iface: %s | proto: %s | count: %d", Struct.Map_Tb_Rate_Burst_Pre_Ip6, Expected_Rule.ExpectedIface, "Burst", counts.Burst)
						t.Logf("[Success] map: %s | iface: %s | proto: %s | count: %d", Struct.Map_Tb_Rate_Burst_Pre_Ip6, Expected_Rule.ExpectedIface, "Rate", counts.Rate)
					}
				}
			}
		}
	}

}