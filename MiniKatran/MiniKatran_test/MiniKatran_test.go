package testing

import (
	"flag"
	"log"
	"os"
	"testing"

	MiniKatranParm "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/MiniKatranParm"
	MiniLbLoader "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/MiniLB"
	Packageattributes "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/PackageAttributes"
	Structs "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/Structs"
	XdpTester "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/XdpTest"
)

var (
	balancer_prog = flag.String("blancer_prog", "/home/cainiao/bpftrace-exporter/MiniKatran/build/balancer.bpf.o", "balancer program")
	test_from_fixtures = flag.Bool("test_from_fixtures", true, "test from fixtures")
	optional_tests = flag.Bool("optional_tests", false, "run optional tests")
	gue = flag.Bool("gue", false, "run gue tests")
	stable_rt = flag.Bool("stable_rt", false, "run stable rt tests")
	tpr = flag.Bool("tpr", false, "run tpr tests")
)

func getTestParam() MiniKatranParm.MiniKatranTestParam {
	if *gue {
		return MiniKatranParm.CreateDefaultTestParam(MiniKatranParm.GUE)
	} else if *tpr {
		return MiniKatranParm.CreateTPRTestParam()
	} else {
		return MiniKatranParm.CreateDefaultTestParam(MiniKatranParm.Default)
	}
}

var kAllFeatures = [4]int{
    Structs.SrcRouting,
    Structs.InlineDecap,
    Structs.GueEncapd,
    Structs.LocalDeliveryOptimization,
}

func tostring(feature int) string {
	switch feature {
	case Structs.SrcRouting:
		return "SrcRouting"
	case Structs.InlineDecap:
		return "InlineDecap"
	case Structs.GueEncapd:
		return "GueEncap"
	case Structs.LocalDeliveryOptimization:
		return "LocalDeliveryOptimization"
	default:
		return "Unknown"
	}
}


func listFeatures(lb *MiniLbLoader.MiniLb) {
	for _, feature := range kAllFeatures {
		if lb.HasFeature(feature) {
			log.Printf("feature: %v", tostring(feature))
		}
	}
}

func testLbCounters(lb *MiniLbLoader.MiniLb, testparam *MiniKatranParm.MiniKatranTestParam) {
	var vip Structs.VipKey
	var stats Structs.Lb_stats
	vip.Address = "10.200.1.1"
	vip.Port = MiniKatranParm.KVipPort
	vip.Proto = MiniKatranParm.KTcp

	log.Printf("Testing counter's sanity. Printing on errors only")

	for key := range testparam.PerVipCounters {
		vipstats := lb.GetStatsForVip(&vip)
		if vipstats.V1 != testparam.ExpectedTotalPktsForVip(key) || vipstats.V2 != testparam.ExpectedTotalBytesForVip(key) {
			log.Printf("pckts: %v, bytes: %v", vipstats.V1, vipstats.V2)
			log.Printf("per Vip counter is incorrect for vip: %v", vip.Address)
		}
	}

	stats = lb.GetLruStats()
	if stats.V1 != testparam.ExpectedTotalPkts() || stats.V2 != testparam.ExpectedTotalLruMisses() {
		log.Printf("Total pckts: %v, LRU misses: %v", stats.V1, stats.V2)
		log.Printf("LRU counter is incorrect")
	}

	stats = lb.GetLruMissStats()
	if stats.V1 != testparam.ExpectedTotalTcpSyns() || stats.V2 != testparam.ExpectedTotalTcpNonSynLruMisses() {
		log.Printf("TCP syns: %v TCP non-syns: %v", stats.V1, stats.V2)
		log.Printf("per pckt type LRU miss counter is incorrect")
	}

	stats = lb.GetLruFallbackStats()
	if stats.V1 != testparam.ExpectedTotalLruFallbackHits() {
		log.Printf("FallbackLRU hits: %v", stats.V1)
		log.Printf("LRU fallback counter is incorrect")
	}

	tprStats := lb.GetTcpServerIdRoutingStats()
	if tprStats.Sid_routed != testparam.ExpectedTcpServerIdRoutingCounts() || tprStats.Ch_routed != testparam.ExpectedTcpServerIdRoutingFallbackCounts() {
		log.Printf("Counters for TCP server-id routing with CH (v1): %v , with server-id (v2): %v ", tprStats.Ch_routed, tprStats.Sid_routed)
		log.Printf("Counters for TCP server-id based routing are wrong")
	}

	//缺少quic参数审查

	realStats := testparam.ExpectedRealStats()
	for i := 0; i < len(realStats); i++ {
		real := MiniKatranParm.KReals[i]
		ok, id := lb.GetIndexForReal(real)
		if !ok {
			log.Printf("Real %s not found", real)
			continue
		}

		stats = lb.GetRealsStats(id)
		expected_stats := realStats[i]

		if stats.V1 != expected_stats.V1 || stats.V2 != expected_stats.V2 {
			log.Printf("stats for real: %v  v1: %v  v2: %v",real, stats.V1, stats.V2)
			log.Printf("incorrect stats for real: %v", real)
			log.Printf("Expected to be incorrect w/ non default build flags")
		}
	}

	Lb_stats := lb.GetMiniKatranLbStats()
	if Lb_stats.BpfFailedCalls != testparam.ExpectedTotalFailedBpfCalls() {
		log.Printf("failed bpf calls: %v ", Lb_stats.BpfFailedCalls)
		log.Printf("incorrect stats about katran library internals: number of failed bpf syscalls is non zero")
	}

	if Lb_stats.AddrValidationFailed != testparam.ExpectedTotalAddressValidations() {
		log.Printf("failed ip address validations: %v", Lb_stats.AddrValidationFailed)
		log.Printf("incorrect stats about katran library internals: number of failed ip address validations is non zero")
	}

	log.Printf("Testing of counters is complete")
}

func runTestFromFixture(lb *MiniLbLoader.MiniLb, xdptester *XdpTester.XdpTester, testparam *MiniKatranParm.MiniKatranTestParam) {
	MiniKatranParm.PrepareLbData(lb)
	MiniKatranParm.PrepareVipUninitializedLbData(lb)

	xdptester.ResetTestFixtures(testparam.TestData)
	prog_fd := lb.GetMiniKatranProgFd()
	xdptester.SetBpfProgFd(prog_fd)

	xdptester.TestFromFixture(lb)
	//testLbCounters(lb, testparam)
	if *optional_tests {
		MiniKatranParm.PrepareOptionLbData(lb)

		if *gue {
			xdptester.ResetTestFixtures(Packageattributes.GueOptionalTestFixtures)
		} else {
			xdptester.ResetTestFixtures(Packageattributes.OptionalTestFixtures)
		}

		xdptester.TestFromFixture(lb)
	}

	//独自测试
	if *stable_rt {
		MiniKatranParm.PrepareLbDataStableRt(lb)
		xdptester.ResetTestFixtures(Packageattributes.UdpStableRtFixtures)
		xdptester.TestFromFixture(lb)
	}
}


func TestMain(t *testing.T) { 
	flag.Parse()

	var config Structs.MiniKatranConfig
	Structs.Get_ready_config(&config)
	var testconfig MiniKatranParm.TesterConfig
	testparam := getTestParam()
	testconfig.TestData = testparam.TestData

	xdptester := XdpTester.NewXdpTester(testconfig)

	//缺少base64打印，从pcap文件中读取数据包
	//缺少监控与存储

	config.MainInterface = MiniKatranParm.KMainInterface
	config.BalancerProgPath = *balancer_prog
	config.DefaultMac = MiniKatranParm.KDefaultMac
	config.Priority = MiniKatranParm.KDefaultPriority

	config.MiniKatranSrcV4 = "10.0.13.37"
	config.MiniKatranSrcV6 = "fc00:2307::1337"
	config.LocalMac = MiniKatranParm.KLocalMac
	config.MaxVips = 512 //


	lb := MiniLbLoader.NewMiniKatran(&config)

	if res := lb.LoadBpfProgs(); !res {
		log.Printf("Failed to load bpf program")
		os.Exit(1)
	}
	log.Printf("LoadBpfProgs success!")
	listFeatures(lb)
	balancer_prog_fd := lb.GetMiniKatranProgFd()
	xdptester.SetBpfProgFd(balancer_prog_fd)

	if *test_from_fixtures {
		runTestFromFixture(lb, xdptester, &testparam)
	}
}

