package XDP

import (
	"fmt"
	"net"

	//_ "net/http/pprof" debug
	Log "github.com/CAINIAOJL/bpftrace-exporter/Firewall/XDP/log"
	Map "github.com/CAINIAOJL/bpftrace-exporter/Firewall/XDP/map"
	Parse "github.com/CAINIAOJL/bpftrace-exporter/Firewall/XDP/parse"
	Struct "github.com/CAINIAOJL/bpftrace-exporter/Firewall/XDP/strcut"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func Go_Init(intial bool, ConfigPath string, objectPath string) bool /*(*ebpf.Collection, error)*/ {
	var Xdp_Config Struct.Xdp_Config

	Parse.ParseConfig(ConfigPath, intial)
	
	Xdp_Config = Struct.Now_Xdp_Config

	if err := rlimit.RemoveMemlock(); err != nil {
		Log.LogV(fmt.Sprintf("【Go_Init】error when removing rlimit: %s, please use 'sudo' to start the program!", err.Error()), 3)
		return false
	}
	var err error
	Struct.Obj, err = ebpf.LoadCollection(objectPath)

	if err != nil {
		Log.LogV(fmt.Sprintf("【Go_Init】error when loading xdp.o: %s, please check the Environment!", err.Error()), 3)
		return false
	}

	xdpProg := Struct.Obj.Programs[Struct.XDP_PROGRAM_NAME]
	if xdpProg == nil {
		Log.LogV("【Go_Init】error when finding xdp program, please check the Environment", 3)
		return false
	}

	Struct.AttachedLinks = make(map[int]link.Link)
	Struct.Iface2Index = make(map[string]int)

	if len(Xdp_Config.Interfaces) == 0 {
		Log.LogV("【Go_Init】your config file has no Interfaces to attach the xdp porgram!, It not a error!", 2)
		return true
	} else {
		for name, _ := range Xdp_Config.Interfaces {
			ifindex, err := net.InterfaceByName(name)
			if err != nil {
				Log.LogV(fmt.Sprintf("【Go_Init】error when finding interface %s, Maybe has no Interface: %s, please check the config file!", name, name), 3)
				return false
			}
			ifindexs := ifindex.Index
			Log.LogV(fmt.Sprintf("【Go_Init】Success: found the interface %s with index %d", name, ifindex.Index), 1)
			Struct.Iface2Index[name] = ifindexs

			xdp_link, err := link.AttachXDP(link.XDPOptions{
										Program: xdpProg,
										Interface: ifindex.Index,
									}) 
			if err != nil {
				Log.LogV(fmt.Sprintf("【Go_Init】error when attaching xdp program: %s, Maybe use root to start the program!", err.Error()), 3)
				for _, link := range Struct.AttachedLinks {
					link.Close() 
				}
				return false
			}

			Struct.AttachedLinks[Struct.Iface2Index[name]] = xdp_link

			if ok := Map.Init_Xdp_Config(Struct.Obj, name, intial, ifindex.Index); !ok {
				Log.LogV(fmt.Sprintf("【Go_Init】error when initializing the XDP config you provide for interface: %s", name), 3)
				for _, link := range Struct.AttachedLinks {
					link.Close() //关闭连接
				}
				return false
			}

			Log.LogV(fmt.Sprintf("【Go_Init】Success: Interface %s: XDP Config Process successfully", name), 1)	
		}
	}
	return true
}