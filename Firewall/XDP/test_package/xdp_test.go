package test_test

import (
	"fmt"
	"log"
	"net"
	"testing"

	Init "github.com/CAINIAOJL/bpftrace-exporter/Firewall/XDP/Init"
	Struct "github.com/CAINIAOJL/bpftrace-exporter/Firewall/XDP/strcut"

	"github.com/cilium/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	TargetIp 		string = "192.168.88.139"
	TargetIp6       string = "3FFE:1900:4545:3:200:f8ff:fe21:67cf"
	TargetPort 		int    = 12566
	SrcMac          []byte = []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	DstMac          []byte = []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}
)

type Case struct {
	Input              []byte
	ExpectedRet        int
	Describtion        string
}

type TestCase []Case

var(
	TestCases TestCase
)

type Package struct {
	SrcIp              string 
	SrcIp6             string
	SrcMac             []byte
	DstMac             []byte   
	SrcPort            []uint16
	DstIp              string
	DstIp6             string
	DstPort            uint16
	Mask               uint16
	ExpectedAction     int
	Version            int
}

var (
	packages = []Package{
		{
			SrcMac: SrcMac,
			DstMac: DstMac,
			SrcIp: "247.94.70.231",
			SrcPort: []uint16{12567},
			DstIp: TargetIp,
			DstPort: uint16(TargetPort),
			Mask: 0,
			Version: 4,
			ExpectedAction: Struct.XDP_PASS,
		},
		{
			SrcMac: SrcMac,
			DstMac: DstMac,
			SrcIp: "111.52.201.89",
			SrcPort: []uint16{11230, 11240, 11250},
			DstIp: TargetIp,
			DstPort: uint16(TargetPort),
			Mask: 0,
			Version: 4,
			ExpectedAction: Struct.XDP_PASS,
		},
		{
			SrcMac: SrcMac,
			DstMac: DstMac,
			SrcIp6: "FE88:D5C3:81E2:A3AB:70AF:FCC1:9818:46BA",
			SrcPort: []uint16{11230, 11240, 11250},
			DstIp6: TargetIp6,
			DstPort: uint16(TargetPort),
			Mask: 0,
			Version: 6,
			ExpectedAction: Struct.XDP_PASS,
		},
		{
			SrcMac: SrcMac,
			DstMac: DstMac,
			SrcIp: "161.93.187.53",
			SrcPort: []uint16{12560},
			DstIp: TargetIp,
			DstPort: uint16(TargetPort),
			Mask: 0,
			Version: 4,
			ExpectedAction: Struct.XDP_DROP,
		},
		{
			SrcMac: SrcMac,
			DstMac: DstMac,
			SrcIp: "63.125.128.1",
			SrcPort: []uint16{uint16(TargetPort)},
			DstIp: TargetIp,
			DstPort: uint16(TargetPort),
			Mask: 20,
			Version: 4,
			ExpectedAction: Struct.XDP_DROP,			
		},
		{
			SrcMac: SrcMac,
			DstMac: DstMac,
			SrcIp6: "FE88:D5C3:81E2:A3AB:70AF:FCC1:9818:46BA",
			SrcPort: []uint16{12560},
			DstIp6: TargetIp6,
			DstPort: uint16(TargetPort),
			Mask: 0,
			Version: 6,
			ExpectedAction: Struct.XDP_DROP,			
		},
		{
			SrcMac: SrcMac,
			DstMac: DstMac,
			SrcIp6: "239A:255A:D76F:B044:8295:D25C:2042:CDD7",
			SrcPort: []uint16{12560},
			DstIp6: TargetIp6,
			DstPort: uint16(TargetPort),
			Mask: 64,
			Version: 6,
			ExpectedAction: Struct.XDP_DROP,	
		},
	}
)

func Init_packages() {
	for index, p := range packages {
		//mac层
		eth := layers.Ethernet{
			SrcMAC:       p.SrcMac,
			DstMAC:       p.DstMac,
		}
		if p.Version == 6 {
			eth.EthernetType = layers.EthernetTypeIPv6
			//ip6层
			ip6 := layers.IPv6{
				Version: 6,
				SrcIP: net.ParseIP(p.SrcIp6),
				DstIP: net.ParseIP(p.DstIp6),
				NextHeader: layers.IPProtocolTCP,
				HopLimit: 64,
			}
			for _, port := range p.SrcPort {
				//tcp层
				tcp := layers.TCP{
					SrcPort: layers.TCPPort(port),
					DstPort: layers.TCPPort(p.DstPort),
					Seq:     1,      
					Ack:     0,
					DataOffset: 5,         
					SYN:     true,          
					Window:  65535,        
				}
				err := tcp.SetNetworkLayerForChecksum(&ip6)
				if err != nil {
					log.Print("error when setting network layer for checksum!")
				}
				buf := gopacket.NewSerializeBuffer()
				opts := gopacket.SerializeOptions{
					ComputeChecksums: true,
					FixLengths:       true,
				}
				err = gopacket.SerializeLayers(buf, opts, &eth, &ip6, &tcp)
				if err != nil {
					log.Printf("The %d package,error when unmarshaling packet! err is %s",index, err.Error())
				}
				ca := Case {
						Input: buf.Bytes(),
						ExpectedRet: p.ExpectedAction,
						Describtion: fmt.Sprintf("Test package:ip %s/%d | ip6 %s/%d from port %d to ip %s | ip6 %s from port %d: action: %s",
												p.SrcIp, p.Mask, p.SrcIp6, p.Mask, 
												port, p.DstIp, p.DstIp6, p.DstPort, 
												Struct.Mode_Map[uint8(p.ExpectedAction)]),
				}
				TestCases = append(TestCases, ca)
			}
		} else {
			eth.EthernetType = layers.EthernetTypeIPv4
			//IP层
			ip := layers.IPv4{
				Version:  4,
				TTL:      64,
				SrcIP:    net.ParseIP(p.SrcIp),
				DstIP:    net.ParseIP(p.DstIp),
				Protocol: layers.IPProtocolTCP,
			}
			for _, port := range p.SrcPort {
				//tcp层
				tcp := layers.TCP{
					SrcPort: layers.TCPPort(port),
					DstPort: layers.TCPPort(p.DstPort),
					Seq:     1,                
					Ack:     0,
					DataOffset: 5,           
					SYN:     true,             
					Window:  65535,          
				}
				err := tcp.SetNetworkLayerForChecksum(&ip)
				if err != nil {
					log.Print("error when setting network layer for checksum!")
				}
				buf := gopacket.NewSerializeBuffer()
				opts := gopacket.SerializeOptions{
					ComputeChecksums: true,
					FixLengths:       true,
				}
				err = gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp)
				if err != nil {
					log.Printf("The %d package,error when unmarshaling packet! err is %s",index, err.Error())
				}
				ca := Case {
						Input: buf.Bytes(),
						ExpectedRet: p.ExpectedAction,
						Describtion: fmt.Sprintf("Test package:ip %s/%d | ip6 %s/%d from port %d to ip %s | ip6 %s from port %d: action: %s",
												p.SrcIp, p.Mask, p.SrcIp6, p.Mask, 
												port, p.DstIp, p.DstIp6, p.DstPort, 
												Struct.Mode_Map[uint8(p.ExpectedAction)]),
				}
				TestCases = append(TestCases, ca)
			}
		}
	}
}

func TestXDPProgram(t *testing.T) {
	Init.Go_Init(true, "/home/cainiao/bpftrace-exporter/Firewall/XDP/xdp.yaml", "/home/cainiao/bpftrace-exporter/Firewall/build/xdp/xdp.o")

	Init_packages()
	prog := &ebpf.ProgramSpec{
		Name: "Test pacakge",
		Type: ebpf.XDP,
		AttachType: ebpf.AttachXDP,
		AttachTarget: Struct.Obj.Programs[Struct.XDP_PROGRAM_NAME],
		License: "GPL",
		SectionName: "xdp",
		AttachTo: "lo",
	}

	for _, ca := range TestCases {
		t.Run(ca.Describtion, func(t *testing.T) {
			ret, _, err := prog.AttachTarget.Test(ca.Input)
			if err != nil {
				t.Fatalf("Failed to test XDP program: %v", err)
			}
			if ret != uint32(ca.ExpectedRet) {
				t.Errorf("Unexpected return value: got %d, want %d", ret, ca.ExpectedRet)
			}
		})
	}
}