package main

import (
	"fmt"
	"os"
	//"time"

	Init "github.com/CAINIAOJL/bpftrace-exporter/Firewall/XDP/Init"
	Log "github.com/CAINIAOJL/bpftrace-exporter/Firewall/XDP/log"
	Map "github.com/CAINIAOJL/bpftrace-exporter/Firewall/XDP/map"
	Struct "github.com/CAINIAOJL/bpftrace-exporter/Firewall/XDP/strcut"
)

func main() {
	if ok := Init.Go_Init(true, "/home/cainiao/bpftrace-exporter/Firewall/XDP/xdp.yaml", "/home/cainiao/bpftrace-exporter/Firewall/build/xdp/xdp.o"); !ok {
		panic("init error has occurred")
	}
	//go Log.RingBuf_Log(Init.Obj)
	//debug
	//展示计数
	pc := Struct.Obj.Maps[Struct.Map_Package_Count]
	if pc == nil {
		Log.LogV(fmt.Sprintf("%s not found", Struct.Map_Package_Count), 3)
		os.Exit(1)
	}
	go Map.DisplayStats(pc) 

	for {
		
	}	
}