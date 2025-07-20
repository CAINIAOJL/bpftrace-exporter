package XDP

import (
	//"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	//"os/signal"
	"unsafe"
	//"runtime/debug"
	//"strconv"
	//"syscall"
	"time"
	"log"
	Struct "github.com/CAINIAOJL/bpftrace-exporter/Firewall/XDP/strcut"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

var log_file_path = "/home/cainiao/bpftrace-exporter/Firewall/XDP/log/xdp.log"

var log_level = map[int]string {
	0: "DEBUG",
	1: "INFO",
	2: "WARNING",
	3: "ERROR",
}


func LogV_N() {
	log_file, err := os.OpenFile(log_file_path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Printf("error when openning the logger file: %s", err.Error())
		return
	}
	defer log_file.Close()
	log_file.WriteString("\n")
}


func LogV(message string, level int) {
	if level >= 0 && level <= 3 {
		log_file, err := os.OpenFile(log_file_path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			log.Printf("error when openning the logger file: %s", err.Error())
			return
		}
		defer log_file.Close()
		log_file.WriteString(fmt.Sprintf("[%s]:%s %s\n",time.Now().Format("2006-01-02 15:04:05"), log_level[level], message))
	} else {
		log.Printf("日志等级 %d 无效, 允许范围: 0-3", level)
		return
	}
}

func RingBuf_Log(obj *ebpf.Collection) {
	ringMap := obj.Maps[Struct.Map_RingBuf]
	if ringMap == nil {
		LogV(fmt.Sprintf("%s not found!", Struct.Map_RingBuf), 3)
		return
	}

	reader, err := ringbuf.NewReader(ringMap)
	if err != nil {
		LogV(fmt.Sprintf("Failed to create ringbuf reader: %s", err), 3)
		return
	}
	defer reader.Close()

	//开启goruntine
	//死循环监听
	timer := time.NewTicker(1 * time.Second)
	defer timer.Stop()
	for range timer.C {
		var event Struct.Debug_Log
		record, err := reader.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				LogV("Received signal, exiting..", 1)
				return
			}
			LogV(fmt.Sprintf("Reading from ringbuf failed: %s", err), 3)
			continue
		}
		LogV(fmt.Sprintf("Raw event bytes: % x", record.RawSample), 1)
		LogV(fmt.Sprintf("the sizeof Raw event is %d", unsafe.Sizeof(Struct.Debug_Log{})), 1)
		
		//逐个解析
		//也可以整体解析，注意内存问题
		event.Ip = binary.BigEndian.Uint32(record.RawSample[0:4]) //前四个字节
		copy(event.Ip6[:], record.RawSample[4:20])
		event.Port = binary.BigEndian.Uint16(record.RawSample[20:22])
		event.Protocol = record.RawSample[22]
		event.Mode = record.RawSample[23]
		event.Version = record.RawSample[24]
		//后面补充了三个字节
		protocolStr := Struct.Protocol_Map[uint8(event.Protocol)]
		if protocolStr != "TCP" && protocolStr != "UDP" {
			LogV(fmt.Sprintf("Unknown(%d) protocol", event.Protocol), 3)
			return
		}

		modeStr := Struct.Mode_Map[uint8(event.Mode)]
		if modeStr != "White" && modeStr != "Black" {
			LogV(fmt.Sprintf("Unknown(%d) mode", event.Mode), 3)
			return
		}
		
		switch event.Version {
		case uint8(4):
			ip := net.IPv4(byte(event.Ip >> 24), byte(event.Ip >> 16), byte(event.Ip >> 8), byte(event.Ip))
			LogV(fmt.Sprintf("IPv4 %s Port %d Proto %s Mode %s", ip.String(), event.Port, protocolStr, modeStr), 1)
		case uint8(6):
			ip := net.IP(event.Ip6[:])
			LogV(fmt.Sprintf("IPv6 %s Port %d Proto %s Mode %s", ip.String(), event.Port, protocolStr, modeStr), 1)
		default:
			LogV(fmt.Sprintf("Unknown IP Version %d", event.Version), 2)
		}		
	}
}