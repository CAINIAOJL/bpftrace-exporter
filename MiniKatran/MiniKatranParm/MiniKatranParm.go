package MiniKatranParm

import (
	"log"
  "fmt"
	MiniLb "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/MiniLB"
	Packageattributes "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/PackageAttributes"
	Structs "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/Structs"
)


type TesterConfig struct {
  TestData []Packageattributes.Packageattributes
  OutPutFileName string
  InPutFileName string
  BpfProgfd int
}



const (
	Default int = 0
	GUE     int = 1
	TPR     int = 2
)

const (
  DEFAULT_NO_COUNTER = 0
  TOTAL_PKTS = 1
  LRU_MISSES = 2
  TCP_SYNS = 3
  NON_SYN_LRU_MISSES = 4
  LRU_FALLBACK_HITS = 5
  QUIC_ROUTING_WITH_CH = 6
  QUIC_ROUTING_WITH_CID = 7
  QUIC_CID_V1 = 8
  QUIC_CID_V2 = 9
  QUIC_CID_DROPS_REAL_0 = 10
  QUIC_CID_DROPS_NO_REAL = 11
  TCP_SERVER_ID_ROUNTING = 12
  TCP_SERVER_ID_ROUTING_FALLBACK_CH = 13
  TOTAL_FAILED_BPF_CALLS = 14
  TOTAL_ADDRESS_VALIDATION_FAILED = 15
  // optional counters
  ICMP_V4_COUNTS = 16
  ICMP_V6_COUNTS = 17
  SRC_ROUTING_PKTS_LOCAL = 18
  SRC_ROUTING_PKTS_REMOTE = 19
  INLINE_DECAP_PKTS = 20
  // udp stable routing counters
  STABLE_RT_CH_ROUTING = 21
  STABLE_RT_CID_ROUTING = 22
  STABLE_RT_CID_INVALID_SERVER_ID = 23
  STABLE_RT_CID_UNKNOWN_REAL_DROPPED = 24
  STABLE_RT_INVALID_PACKET_TYPE = 25
);

const (
    KDefaultPriority uint32 = 2307
    KDefaultKatranPos uint32 = 8
    KMonitorLimit uint32 = 1024
    KNoHc bool = false
    K1Mbyte uint32 = 1024 * 1024

    KVipPort uint16 = 80
    KUdp uint8 = 17
    KTcp uint8 = 6
    KDefaultWeight uint32 = 1

    KLocalReal uint8 = 2

    kQuicVip uint32 = 4

    KDportHash uint32 = 8

    KSrcRouting uint32 = 16

    KLocalVip uint32 = 32

    KUdpStableRouting uint32 = 256

    KMainInterface string = "lo"
    KV4TunInterface string = "lo"
    KV6TunInterface string = "lo"
    KNoExternalMap string = ""
)

var (
    KDefaultMac = []uint8{0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xAF}
    KLocalMac   = []uint8{0x00, 0xFF, 0xDE, 0xAD, 0xBE, 0xAF}
    KReals      = []string{
        "10.0.0.1",
        "10.0.0.2",
        "10.0.0.3",
        "fc00::1",
        "fc00::2",
        "fc00::3",
    }
    
    KDefaultRealStats = []Structs.Lb_stats{
        {0, 0},
        {9, 422},
        {5, 291},
        {4, 206},
        {2, 76},
        {3, 156},
    }

    KTPRRealStats = []Structs.Lb_stats{
        {0, 0},
        {3, 181},
        {4, 244},
        {8, 356},
        {2, 134},
        {0, 0},
    }
)

var (
    KRealStats = map[int][]Structs.Lb_stats {
        Default: KDefaultRealStats,
        GUE: KDefaultRealStats,
        TPR: KTPRRealStats,
    }
)

type MiniKatranTestParam struct {
	Mode int 
	TestData []Packageattributes.Packageattributes
    PerVipCounters map[Structs.VipKey][]uint64
    ExpectedCounters map[int]uint64
}

func (p *MiniKatranTestParam) _lookup_counter(counter int) uint64 {
    counters, ok := p.ExpectedCounters[counter]
    if !ok {
        return 0
    }
    return counters
}

func (p *MiniKatranTestParam) ExpectedTotalPkts() uint64 {
  return p._lookup_counter(TOTAL_PKTS)
}
func (p *MiniKatranTestParam) ExpectedTotalLruMisses() uint64 {
  return p._lookup_counter(LRU_MISSES)
}
func (p *MiniKatranTestParam) ExpectedTotalTcpSyns() uint64 {
  return p._lookup_counter(TCP_SYNS)
}
func (p *MiniKatranTestParam) ExpectedTotalTcpNonSynLruMisses() uint64 {
  return p._lookup_counter(NON_SYN_LRU_MISSES);
}
func (p *MiniKatranTestParam) ExpectedTotalLruFallbackHits() uint64 {
  return p._lookup_counter(LRU_FALLBACK_HITS);
}
func (p *MiniKatranTestParam) ExpectedQuicRoutingWithCh() uint64 {
  return p._lookup_counter(QUIC_ROUTING_WITH_CH);
}
func (p *MiniKatranTestParam) ExpectedQuicRoutingWithCid() uint64 {
  return p._lookup_counter(QUIC_ROUTING_WITH_CID);
}
func (p *MiniKatranTestParam) ExpectedQuicCidV1Counts() uint64 {
  return p._lookup_counter(QUIC_CID_V1);
}
func (p *MiniKatranTestParam) ExpectedQuicCidV2Counts() uint64 {
  return p._lookup_counter(QUIC_CID_V2);
}
func (p *MiniKatranTestParam) ExpectedQuicCidDropsReal0Counts() uint64 {
  return p._lookup_counter(QUIC_CID_DROPS_REAL_0);
}
func (p *MiniKatranTestParam) ExpectedQuicCidDropsNoRealCounts() uint64 {
  return p._lookup_counter(QUIC_CID_DROPS_NO_REAL);
}
func (p *MiniKatranTestParam) ExpectedTcpServerIdRoutingCounts() uint64 {
  return p._lookup_counter(TCP_SERVER_ID_ROUNTING);
}
func (p *MiniKatranTestParam) ExpectedTcpServerIdRoutingFallbackCounts() uint64 {
  return p._lookup_counter(TCP_SERVER_ID_ROUTING_FALLBACK_CH);
}
func (p *MiniKatranTestParam) ExpectedUdpStableRoutingWithCh() uint64 {
  return p._lookup_counter(STABLE_RT_CH_ROUTING);
}
func (p *MiniKatranTestParam) ExpectedUdpStableRoutingWithCid() uint64 {
  return p._lookup_counter(STABLE_RT_CID_ROUTING);
}
func (p *MiniKatranTestParam) ExpectedUdpStableRoutingInvalidSid() uint64 {
  return p._lookup_counter(STABLE_RT_CID_INVALID_SERVER_ID);
}
func (p *MiniKatranTestParam) ExpectedUdpStableRoutingUnknownReals() uint64 {
  return p._lookup_counter(
      STABLE_RT_CID_UNKNOWN_REAL_DROPPED);
}
func (p *MiniKatranTestParam) ExpectedUdpStableRoutingInvalidPacketType() uint64 {
  return p._lookup_counter(STABLE_RT_INVALID_PACKET_TYPE);
}
func (p *MiniKatranTestParam) ExpectedTotalFailedBpfCalls() uint64 {
  return p._lookup_counter(TOTAL_FAILED_BPF_CALLS);
}
func (p *MiniKatranTestParam) ExpectedTotalAddressValidations() uint64 {
  return p._lookup_counter(TOTAL_ADDRESS_VALIDATION_FAILED);
}
func (p *MiniKatranTestParam) ExpectedIcmpV4Counts() uint64 {
  return p._lookup_counter(ICMP_V4_COUNTS);
}
func (p *MiniKatranTestParam) ExpectedIcmpV6Counts() uint64 {
  return p._lookup_counter(ICMP_V6_COUNTS);
}
func (p *MiniKatranTestParam) ExpectedSrcRoutingPktsLocal() uint64 {
  return p._lookup_counter(SRC_ROUTING_PKTS_LOCAL);
}
func (p *MiniKatranTestParam) ExpectedSrcRoutingPktsRemote() uint64 {
  return p._lookup_counter(SRC_ROUTING_PKTS_REMOTE);
}
func (p *MiniKatranTestParam) ExpectedInlineDecapPkts() uint64 {
  return p._lookup_counter(INLINE_DECAP_PKTS);
}

func (p *MiniKatranTestParam) ExpectedTotalPktsForVip(vip Structs.VipKey) uint64 {
    counters, ok := p.PerVipCounters[vip]
    if !ok {
        return 0
    }
    return counters[0]
}
func (p *MiniKatranTestParam) ExpectedTotalBytesForVip(vip Structs.VipKey) uint64 {
    counters, ok := p.PerVipCounters[vip]
    if !ok {
        return 0
    }
    return counters[1]
}

func (p *MiniKatranTestParam) ExpectedRealStats() []Structs.Lb_stats {
    realStats := KRealStats[p.Mode]
    if realStats == nil {
        return []Structs.Lb_stats{{0, 0}}
    }
    return realStats 
}

func addReals(Lb *MiniLb.MiniLb, vip *Structs.VipKey, reals *[]string) {
  var real Structs.NewReal
  real.Weight = KDefaultWeight
  for _, r := range *reals {
      real.Address = r
      Lb.AddRealForVip(&real, vip)
  }
}

func deleteReals(Lb *MiniLb.MiniLb, vip *Structs.VipKey, reals *[]string) {
  var real Structs.NewReal
  real.Weight = KDefaultWeight
  for _, r := range *reals {
    real.Address = r
    Lb.DelRealForVip(&real, vip)
  }
}

func addQuicMappings(lb *MiniLb.MiniLb) {
  var qreal Structs.QuicReal 
  var qreals []Structs.QuicReal
  action := Structs.ADD
  ids := []uint16{1022, 1023, 1025, 1024, 1026, 1027}
  for i := 0; i < len(KReals); i++ {
    qreal.Address = KReals[i]
    qreal.Id = uint32(ids[i])
    qreals = append(qreals, qreal)

    qreal.Address = KReals[i]
    twJobMask := 0x030000
    qreal.Id = uint32(twJobMask | int(ids[i]))
    qreals = append(qreals, qreal)

    log.Printf("Adding mapping for %v with id %v", qreal.Address, qreal.Id)

    fmt.Printf(
    "%02X%02X%02X%02X\n",
    (qreal.Id >> 24) & 0xFF,
    (qreal.Id >> 16) & 0xFF,
    (qreal.Id >> 8) & 0xFF,
    qreal.Id & 0xFF,)
  }
  lb.ModifyQuicRealsMapping(action, &qreals)
}


//缺少quic映射

func PrepareLbData(Lb *MiniLb.MiniLb) {
  //缺少监控

  var vip Structs.VipKey
  vip.Address = "10.200.1.1"
  vip.Port = KVipPort
  vip.Proto = KUdp
  Lb.AddVip(&vip, 0)

  reals := []string {"10.0.0.1", "10.0.0.2", "10.0.0.3"}
  reals6 := []string{"fc00::1", "fc00::2", "fc00::3"}


  //vip: kVipPort kUdp "10.200.1.1"
  addReals(Lb, &vip, &reals) //v4
  vip.Proto = KTcp
  //vip: kVipPort KTcp "10.200.1.1"
  Lb.AddVip(&vip, 0)
  addReals(Lb, &vip, &reals)  //v4

  vip.Address = "10.200.1.2"
  vip.Port = 0
  //vip: 0 KTcp "10.200.1.2"
  Lb.AddVip(&vip, 0)
  addReals(Lb, &vip, &reals)

  vip.Address = "10.200.1.4"
  //vip: 0 KTcp "10.200.1.4"
  Lb.AddVip(&vip, 0)
  addReals(Lb, &vip, &reals)
  Lb.ModifyVip(&vip, KDportHash, true)

  //vip: KVipPort Ktcp "10.200.1.3"
  vip.Address = "10.200.1.3"
  vip.Port = KVipPort
  Lb.AddVip(&vip, 0)
  addReals(Lb, &vip, &reals6)

  vip.Address = "fc00:1::1"
  Lb.AddVip(&vip, 0)
  addReals(Lb, &vip, &reals6)


  addQuicMappings(Lb)
  //quic v4 vip
  vip.Proto = KUdp
  vip.Port = 443
  vip.Address = "10.200.1.5"
  Lb.AddVip(&vip, 0)
  Lb.ModifyVip(&vip, kQuicVip, true)
  addReals(Lb, &vip, &reals)

  //quic v6 vip
  vip.Address = "fc00:1::2"
  Lb.AddVip(&vip, 0)
  Lb.ModifyVip(&vip, kQuicVip, true)
  addReals(Lb,&vip, &reals6)
  //缺少健康检查
}

func PrepareOptionLbData(Lb *MiniLb.MiniLb) {
  var vip Structs.VipKey
  vip.Address = "10.200.1.1"
  vip.Port = KVipPort
  vip.Proto = KUdp

  Lb.ModifyVip(&vip, KSrcRouting, true) //lpm

  vip.Address = "fc00:1::1"
  vip.Proto = KTcp

  Lb.ModifyVip(&vip, KSrcRouting, true) //lpm

  srcs1 := []string{"192.168.0.0/17"}
  srcs2 := []string{"192.168.100.0/24"}
  srcs3 := []string{"fc00:2307::/32"}
  srcs4 := []string{"fc00:2307::/64"}
  srcs5 := []string{"fc00:2::/64"}
  Lb.AddSrcRoutingRule(&srcs1, "fc00::2307:1")
  Lb.AddSrcRoutingRule(&srcs2, "fc00::2307:2")
  Lb.AddSrcRoutingRule(&srcs3, "fc00::2307:3")
  Lb.AddSrcRoutingRule(&srcs4, "fc00::2307:4")
  Lb.AddSrcRoutingRule(&srcs5, "fc00::2307:10")
  Lb.AddInlineDecapDst("fc00:1404::1")

  vip.Address = "10.200.1.6"
  vip.Port = KVipPort
  vip.Proto = KUdp
  Lb.AddVip(&vip, 0)
  Lb.ModifyVip(&vip, KLocalVip, true) //本地优化配送\
  reals :=[]string{"10.0.0.6"}
  addReals(Lb, &vip, &reals)
  Lb.ModifyReal("10.0.0.6", KLocalReal, true)
}

func PrepareLbDataStableRt(Lb *MiniLb.MiniLb) {
  //重启监控器

  var vip Structs.VipKey
  reals := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
  reals6 := []string{"fc00::1", "fc00::2", "fc00::3"}

  vip.Address = "fc00:1::9"
  vip.Proto = KUdp
  vip.Port = KVipPort
  Lb.AddVip(&vip, 0)
  addReals(Lb, &vip, &reals6)
  Lb.ModifyVip(&vip, KUdpStableRouting, true) //udp稳定链接

  vip.Address = "10.200.1.90"
  Lb.AddVip(&vip, 0)
  addReals(Lb, &vip, &reals)
  Lb.ModifyVip(&vip, KUdpStableRouting, true)


  vip.Address = "10.200.1.2"
  vip.Port = 0 //ignores dst_port
  Lb.AddVip(&vip, 0)
  addReals(Lb, &vip, &reals)

  vip.Address = "10.200.1.4"
  Lb.AddVip(&vip, 0)
  addReals(Lb, &vip, &reals)
  Lb.ModifyVip(&vip, KDportHash, true)

  vip.Address = "10.200.1.3"
  vip.Port = KVipPort
  Lb.AddVip(&vip, 0)
  addReals(Lb, &vip, &reals6)

  vip.Address = "fc00:1::1"
  Lb.AddVip(&vip, 0)
  addReals(Lb, &vip, &reals6)

  addQuicMappings(Lb)

  //quic v4 vip
  vip.Proto = KUdp
  vip.Port = 443
  vip.Address = "10.200.1.5"
  Lb.AddVip(&vip, 0)
  Lb.ModifyVip(&vip, kQuicVip, true)
  addReals(Lb, &vip, &reals)

  vip.Address = "fc00:1::2"
  Lb.AddVip(&vip, 0)
  Lb.ModifyVip(&vip, kQuicVip, true)
  addReals(Lb, &vip, &reals6)

  //缺少健康检查
}

func PrepareVipUninitializedLbData(Lb *MiniLb.MiniLb) {
  var vip Structs.VipKey
  vip.Address = "10.200.1.99"
  vip.Port = KVipPort
  vip.Proto = KTcp
  Lb.AddVip(&vip, 0)

  vip.Address = "fc00:1::11"
  vip.Proto = KUdp
  Lb.AddVip(&vip, 0)
}

//缺少perf测试

func CreateDefaultTestParam(testMode int) MiniKatranTestParam {
  var vip Structs.VipKey
  vip.Address = "10.200.1.1"
  vip.Port = KVipPort
  vip.Proto = KTcp
  testParm := MiniKatranTestParam{
    Mode: testMode,
  }
  testParm.ExpectedCounters = map[int]uint64{
    TOTAL_PKTS: 23,
    LRU_MISSES: 11,
    TCP_SYNS: 2,
    NON_SYN_LRU_MISSES: 6,
    LRU_FALLBACK_HITS: 19,
    QUIC_ROUTING_WITH_CH: 7,
    QUIC_ROUTING_WITH_CID: 4,
    QUIC_CID_V1: 4,
    QUIC_CID_V2: 2,
    QUIC_CID_DROPS_REAL_0: 0,
    QUIC_CID_DROPS_NO_REAL: 2,
    TOTAL_FAILED_BPF_CALLS: 0,
    TOTAL_ADDRESS_VALIDATION_FAILED: 0,

    //optional counters
    ICMP_V4_COUNTS: 1,
    ICMP_V6_COUNTS: 1,
    SRC_ROUTING_PKTS_LOCAL: 2,
    SRC_ROUTING_PKTS_REMOTE: 6,
    INLINE_DECAP_PKTS: 4,

    //unused
    TCP_SERVER_ID_ROUNTING: 0,
    TCP_SERVER_ID_ROUTING_FALLBACK_CH: 0,
  }

  testParm.PerVipCounters = map[Structs.VipKey][]uint64{
    vip: []uint64{
      4, 248,
    },
  }

  if testMode == GUE {
    testParm.TestData = Packageattributes.GueTestFixtures
  } else {
    testParm.TestData = Packageattributes.TestFixtures
  }
  return testParm
}

func CreateTPRTestParam() MiniKatranTestParam {
  var vip Structs.VipKey
  vip.Address = "10.200.1.1"
  vip.Port = KVipPort
  vip.Proto = KTcp
  testParm := MiniKatranTestParam{
    Mode: TPR,
  }

  testParm.TestData = Packageattributes.TprTestFixtures
  testParm.ExpectedCounters = map[int]uint64{
    TOTAL_PKTS: 17,
    LRU_MISSES: 3,
    TCP_SYNS: 1,
    NON_SYN_LRU_MISSES: 2,
    LRU_FALLBACK_HITS: 17,
    TCP_SERVER_ID_ROUNTING: 8,
    TCP_SERVER_ID_ROUTING_FALLBACK_CH: 8,
    TOTAL_FAILED_BPF_CALLS: 0,
    TOTAL_ADDRESS_VALIDATION_FAILED: 0,
  }
  testParm.PerVipCounters = map[Structs.VipKey][]uint64{
    vip: []uint64{
      4, 244,
    },
  }
  return testParm
}

func CreateUdpStableRtTestParam() MiniKatranTestParam { 
  var vip Structs.VipKey
  vip.Address = "fc00:1::9"
  vip.Port = KVipPort
  vip.Proto = KUdp
  testParm := MiniKatranTestParam{
    Mode: GUE,
  }
  testParm.TestData = Packageattributes.UdpStableRtFixtures
  testParm.ExpectedCounters = map[int]uint64{
    TOTAL_PKTS: 5,
    STABLE_RT_CH_ROUTING: 2,
    STABLE_RT_CID_ROUTING: 3,
    STABLE_RT_CID_INVALID_SERVER_ID: 0,
    STABLE_RT_CID_UNKNOWN_REAL_DROPPED: 0,
    STABLE_RT_INVALID_PACKET_TYPE: 0,
  }
  testParm.PerVipCounters = map[Structs.VipKey][]uint64{
    vip: []uint64{
      4, 244,
    },
  }
  return testParm
}




