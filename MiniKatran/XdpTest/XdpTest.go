package xdptest

import (
	"encoding/base64"
	"log"

	MiniBpfAdapter "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/MiniBpfAdapter"
	MiniKatranParm "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/MiniKatranParm"
	MiniLbLoader "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/MiniLB"
	Packageattributes "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/PackageAttributes"
	Structs "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/Structs"
	"github.com/cilium/ebpf"
)

const (
	kTestRepeatCount = 1
)

var kXdpCodes = map[int]string {
	0: "XDP_ABORTED",
	1: "XDP_DROP",
	2: "XDP_PASS",
	3: "XDP_TX",
}


type XdpTester struct {
	Config_ 					MiniKatranParm.TesterConfig
	MiniKatranAdapter_ 			MiniBpfAdapter.MiniBpfAdapter
	MiniKatranLb_      			*MiniLbLoader.MiniLb
	GetGlobalLruRoutedPackets 	uint64
}

func NewXdpTester(config MiniKatranParm.TesterConfig) *XdpTester {
	return &XdpTester{
		Config_: config,
		MiniKatranAdapter_: *MiniBpfAdapter.NewMiniBpfAdapter(true, true),
		GetGlobalLruRoutedPackets: 0,
		MiniKatranLb_: nil,
	}
}

func (xdptester *XdpTester) SetBpfProgFd(prog_fd int) {
	xdptester.Config_.BpfProgfd = prog_fd
}

func (xdptester *XdpTester) SetMiniKatranLb(lb *MiniLbLoader.MiniLb) {
	xdptester.MiniKatranLb_ = lb
}

func (xdptester *XdpTester) ResetTestFixtures(data []Packageattributes.Packageattributes) {
	xdptester.Config_.TestData = data
}

func (xdptester *XdpTester) TestFromFixture(lb *MiniLbLoader.MiniLb) bool {
	return xdptester.runBpfTestFromFixture(kXdpCodes, lb)
}

func (xdpTester *XdpTester) getGlobalLruRoutedPackets() uint64 {
	globalLruStats := xdpTester.MiniKatranLb_.GetGlobalLruStats()
	return globalLruStats.V2
}


//缺少从pcap文件中读取数据包

func (xdptester *XdpTester) runBpfTestFromFixture(kXdpCodes map[int]string, lb *MiniLbLoader.MiniLb) bool {

	//缺少从pcap文件中读取数据包
	var packetsRoutedGlobalLruBefore uint64
	var packetsRoutedGlobalLruAfter uint64
	test_result := ""
	pckt_num := 1
	overallSuccess := true

	for i := 0; i < len(xdptester.Config_.TestData); i++ {
		iterationSuccess := true

		//缺少测试单个数据包

		//缺少数据包测试写入pcap文件，生成测试文件pcap格式

		log.Printf("Running test for pckt #%v with description: %v", pckt_num, xdptester.Config_.TestData[i].Description)
		var data_in []byte
		var err error
		var res int
		//log.Printf("package is %v", xdptester.Config_.TestData[i].InputPacket)
		if data_in, err = base64.StdEncoding.DecodeString(xdptester.Config_.TestData[i].InputPacket); err != nil {
			log.Printf("Failed to decode input packet: %v", err)
			return false
		}
		prog_result := &ebpf.RunOptions{
			Data: make([]byte, len(data_in)),
			DataOut: make([]byte, 1000000),
		}
		copy(prog_result.Data, data_in)
		prog_result.Repeat = kTestRepeatCount
		res = xdptester.MiniKatranAdapter_.TestXdpProg(prog_result, lb.MiniBpfAdapter.Loader.BpfObj[Structs.KBalancerProgPath].Programs[Structs.KBalancerProgName]) 
		if res < 0 {
			log.Printf("failed to run bpf test on pckt #%v", pckt_num)
			pckt_num++
			overallSuccess = false
			continue
		}

		if xdptester.Config_.TestData[i].RoutedThroughGlobalLru {
			packetsRoutedGlobalLruAfter = xdptester.getGlobalLruRoutedPackets()
		}

		packetRoutedThroughGlobalLru := false
		if packetsRoutedGlobalLruAfter - packetsRoutedGlobalLruBefore == 1 {
			packetRoutedThroughGlobalLru = true //全局lru
		}

		ret_val_str, ok := kXdpCodes[res]
		if !ok {
			ret_val_str = "UNKNOWN"
		}

		if ret_val_str != xdptester.Config_.TestData[i].ExpectedReturnValue {
			log.Printf("value from test: %v, expecteed: %v", ret_val_str, xdptester.Config_.TestData[i].ExpectedReturnValue)
			test_result = "\033[31mFailed\033[0m"
			iterationSuccess = false
		}

		//缺少从pcap中读取数据包部分

		if iterationSuccess && xdptester.Config_.TestData[i].RoutedThroughGlobalLru {
			//全局lru 测试结果展示
			if xdptester.Config_.TestData[i].RoutedThroughGlobalLru && !packetRoutedThroughGlobalLru {
				log.Printf("packet should have been routed through global lru, but wasn't")
				test_result = "\033[31mFailed\033[0m"
				iterationSuccess = false
			} else if !xdptester.Config_.TestData[i].RoutedThroughGlobalLru && packetRoutedThroughGlobalLru {
				log.Printf("packet should not have been routed through global lru, but was")
				test_result = "\033[31mFailed\033[0m"
				iterationSuccess = false
			}
		}

		if iterationSuccess {
			test_result = "\033[32mPassed\033[0m"
			actual_out := base64.StdEncoding.EncodeToString(prog_result.DataOut)
			//log.Printf("data out is %v", prog_result.DataOut)
			if actual_out != xdptester.Config_.TestData[i].ExpectedOutputPacket {
				log.Printf("output packet not equal to expected one; expected pkt= %v, actual= %v", xdptester.Config_.TestData[i].ExpectedOutputPacket, actual_out)
				test_result = "\033[31mFailed\033[0m"
				iterationSuccess = false
			}
		}

		overallSuccess = overallSuccess && iterationSuccess

		log.Printf("Test: %v result: %v", xdptester.Config_.TestData[i].Description, test_result)
		//log.Printf("data out is %v", base64.StdEncoding.EncodeToString(prog_result.DataOut))
		pckt_num++
	}
	return overallSuccess
}

