package minilb_test

import (
	"fmt"
	"log"
	"testing"

	MiniLbLoader "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/MiniLB"
	Structs "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/Structs"
	"github.com/stretchr/testify/assert"
)

const (
	kMaxRealTest = 4096;
	// real index 0 is preserved. So the real capacity would be
	// sizeof(reals array)-1.
	kMaxNumOfReals = kMaxRealTest - 1;	
)

var miniKatranConfig Structs.MiniKatranConfig
var miniKatranLb *MiniLbLoader.MiniLb

var (
	v1 Structs.VipKey 
	v2 Structs.VipKey 
	r1 Structs.NewReal
	r2 Structs.NewReal;
	newReals1 []Structs.NewReal
	newReals2 []Structs.NewReal
	qReals1 []Structs.QuicReal
	qReals2 []Structs.QuicReal
)
//暂不实现quic


func SetUp() {
	Structs.Get_ready_config(&miniKatranConfig)
	miniKatranConfig.MainInterface = "ens33"
	//miniKatranConfig.V4TunInterface = "ipip0"
	//miniKatranConfig.V6TunInterface = "ipip6"
	miniKatranConfig.BalancerProgPath = "/lb.o"
	//缺少hc
	miniKatranConfig.DefaultMac = []uint8{0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E}
	miniKatranConfig.Priority = 1
	//缺少root
	miniKatranConfig.MaxVips = 512
	miniKatranConfig.MaxReals = kMaxRealTest
	miniKatranConfig.ChRingSize = 65537
	miniKatranConfig.Testing = true
	miniKatranConfig.LruSize = 1
	miniKatranConfig.ForwardingCores = []uint32{}
	miniKatranConfig.NumaNodes = []uint32{}
	miniKatranConfig.MaxLpmSrcSize = 10
	miniKatranConfig.MaxDecapDst = 4
	miniKatranConfig.XdpAttachFlags = 0

	miniKatranLb = MiniLbLoader.NewMiniKatran(&miniKatranConfig)

	v1.Address = "fc01::1"
	v1.Port = 443
	v1.Proto = 6
	v2.Address = "fc01::2"
	v2.Port = 443
	v2.Proto = 6
	r1.Address = "192.168.1.1"
	r1.Weight = 10
	r2.Address = "fc00::1"
	r2.Weight = 12

	var real1 Structs.NewReal
	var real2 Structs.NewReal
	var qreal1 Structs.QuicReal
	var qreal2 Structs.QuicReal
	real1.Weight = 1
	real2.Weight = 1

	for i := 0; i < 16; i++ {
		for j := 0; j < 256; j++ {
			k := (i * 256 + j)
			if k < kMaxNumOfReals {
				real1.Address = fmt.Sprintf("10.0.%v.%v", i, j)
				newReals1 = append(newReals1, real1)
				qreal1.Address = real1.Address
				qreal1.Id = uint32(k)
				qReals1 = append(qReals1, qreal1)
				real2.Address = fmt.Sprintf("10.1.%v.%v", i, j)
				newReals2 = append(newReals2, real2)
				qreal2.Address = real2.Address
				qreal2.Id = uint32(k)
				qReals2 = append(qReals2, qreal2)
			}
		}
	}
}

func TestChageMac(t *testing.T) {
	SetUp()
	mac := []uint8{0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0F}
	assert.Equal(t, true, miniKatranLb.ChangeMac(mac))
	defult_mac := miniKatranLb.GetMac()
	assert.Equal(t, 6, len(defult_mac))
}

func TestIfindex(t *testing.T) {
	SetUp()
	inidices := miniKatranLb.GetIndexOfNetworkInterfaces()
	assert.Equal(t, 1, len(inidices))

	//缺少hc
}

func TestVipHelpers(t *testing.T) {
	SetUp()
	var v Structs.VipKey
	v.Address = "fc00::3"
	v.Proto = 6
	v.Port = 0
	assert.Equal(t, false, miniKatranLb.DelVip(&v1))
	assert.Equal(t, true, miniKatranLb.AddVip(&v2, 0))
	assert.Equal(t, true, miniKatranLb.DelVip(&v2))

	for i := 0; i < 512; i++ {
		v.Port = uint16(i)
		assert.Equal(t, true, miniKatranLb.AddVip(&v, 0))
	}
	v.Port = uint16(1000)
	//超出max_vip的大小
	assert.Equal(t, false, miniKatranLb.AddVip(&v, 0))
}


func TestAddingInvalidVip(t *testing.T) {
	SetUp()
	var v Structs.VipKey
	v.Address = "fc00::/64" //network
	v.Proto = 6
	v.Port = 80
	assert.Equal(t, false, miniKatranLb.AddVip(&v, 0))
}

func TestRealHelpers(t *testing.T) {
	SetUp()
	miniKatranLb.AddVip(&v1, 0)

	assert.Equal(t, true, miniKatranLb.DelRealForVip(&r1, &v1))
	//没有v2
	assert.Equal(t, false, miniKatranLb.AddRealForVip(&r1, &v2))
	assert.Equal(t, true, miniKatranLb.AddRealForVip(&r1, &v1))
}

func TestRealFlags(t *testing.T) {
	SetUp()
	miniKatranLb.AddVip(&v1, 0)
	miniKatranLb.AddRealForVip(&r1, &v1)

	assert.Equal(t, true, miniKatranLb.ModifyReal(r1.Address, uint8(0xf0), true), "trying to modify existent real")
	assert.Equal(t, false, miniKatranLb.ModifyReal("1.2.3.4", uint8(0xff), true), "trying to modify non-existent real")
	miniKatranLb.ModifyReal(r1.Address, uint8(0xff), true)
	reals := miniKatranLb.GetRealsForVip(&v1)
	if reals != nil {
		assert.Equal(t, uint8(0xfe), reals[0].Flags, "set and get flags (ipv4/ipv6 specific flag should not be changed)")
	}

	miniKatranLb.ModifyReal(r1.Address, uint8(0x10), false)
	reals = miniKatranLb.GetRealsForVip(&v1)
	if reals != nil {
		assert.Equal(t, uint8(0xee), reals[0].Flags, "unset 0x10 flag")
	}
}

func TestVipStatsHelper(t *testing.T) {
	SetUp()
	miniKatranLb.AddVip(&v1, 0)
	stats := miniKatranLb.GetStatsForVip(&v1)

	assert.Equal(t, uint64(0), stats.V1, "No ebpf prog load and attach, so no stats")
	assert.Equal(t, uint64(0), stats.V2, "No ebpf prog load and attach, so no stats")
}

func TestLruStatsHelper(t *testing.T) {
	SetUp()
	stats := miniKatranLb.GetLruStats()
	assert.Equal(t, uint64(0), stats.V1, "No ebpf prog load and attach, so no stats")
	assert.Equal(t, uint64(0), stats.V2, "No ebpf prog load and attach, so no stats")
}

func TestLruMissStatsHelper(t *testing.T) {
	SetUp()
	stats := miniKatranLb.GetLruMissStats()
	assert.Equal(t, uint64(0), stats.V1, "No ebpf prog load and attach, so no stats")
	assert.Equal(t, uint64(0), stats.V2, "No ebpf prog load and attach, so no stats")
}

//缺少hc检查

func TestVipFlags(t *testing.T) { 
	SetUp()
	//给虚拟ip设置标志
	miniKatranLb.AddVip(&v1, uint32(2307))
	flags, err := miniKatranLb.GetVipFlags(&v1)
	if err == 0 {
		assert.Equal(t, uint32(2307), flags, "check the GetVipFlags, its must be 2307(uint32)")
	}
}

func TestGetAllVips(t *testing.T) {
	SetUp()
	miniKatranLb.AddVip(&v1, 0)
	miniKatranLb.AddVip(&v2, 0)
	assert.Equal(t, 2, len(miniKatranLb.GetAllVips()), "GetAllVips() should return 2 vips")
}

func TestUpdateRealsHelper(t *testing.T) {
	SetUp()
	miniKatranLb.AddVip(&v1, 0)
	miniKatranLb.AddVip(&v2, 0)
	
	action := Structs.ADD
	assert.Equal(t, true, miniKatranLb.ModifyRealsForVip(action, &newReals1, &v1))
	assert.Equal(t, true, miniKatranLb.ModifyRealsForVip(action, &newReals2, &v2))
	assert.Equal(t, kMaxNumOfReals, len(miniKatranLb.GetRealsForVip(&v1)))
	assert.Equal(t, 0, len(miniKatranLb.GetRealsForVip(&v2)))

	//向v2注册与v1相同的real，只是计数器的变化，此刻v2可以读出数据
	assert.Equal(t, true, miniKatranLb.ModifyRealsForVip(action, &newReals1, &v2))
	assert.Equal(t, kMaxNumOfReals, len(miniKatranLb.GetRealsForVip(&v2)), "v2's reals are same with v1, so only reals's recounts changes, now v2 has reals like v1")

	action = Structs.DEL
	assert.Equal(t, true, miniKatranLb.ModifyRealsForVip(action, &newReals1, &v1))
	assert.Equal(t, true, miniKatranLb.ModifyRealsForVip(action, &newReals1, &v1))

	action = Structs.ADD
	assert.Equal(t, true, miniKatranLb.ModifyRealsForVip(action, &newReals2, &v2))
	assert.Equal(t, kMaxNumOfReals, len(miniKatranLb.GetRealsForVip(&v2)))
	assert.Equal(t, kMaxNumOfReals, len(miniKatranLb.GetNumToRealsMap()))
}

func TestUpdateQuicRealHelper(t *testing.T) {
	SetUp()
	miniKatranLb.AddVip(&v1, 0)
	miniKatranLb.AddVip(&v2, 0)
	action := Structs.ADD
	miniKatranLb.ModifyQuicRealsMapping(action, &qReals2)
	assert.Equal(t, true, miniKatranLb.ModifyRealsForVip(action, &newReals1, &v1))
	assert.Equal(t, true, miniKatranLb.ModifyRealsForVip(action, &newReals2, &v2))

	assert.Equal(t, 0, len(miniKatranLb.GetRealsForVip(&v1)))
	assert.Equal(t, kMaxNumOfReals, len(miniKatranLb.GetRealsForVip(&v2)))
	assert.Equal(t, kMaxNumOfReals, len(miniKatranLb.GetQuicRealsMapping()))

	action = Structs.DEL
	assert.Equal(t, true, miniKatranLb.ModifyRealsForVip(action, &newReals2, &v2))
	miniKatranLb.ModifyQuicRealsMapping(action, &qReals2)
	assert.Equal(t, 0, len(miniKatranLb.GetQuicRealsMapping()))

	action = Structs.ADD
	assert.Equal(t, true, miniKatranLb.ModifyRealsForVip(action, &newReals1, &v1))
	assert.Equal(t, kMaxNumOfReals, len(miniKatranLb.GetRealsForVip(&v1)))
}

func TestUpdateQuicReal(t *testing.T) {
	SetUp()
	var real Structs.QuicReal
	var reals []Structs.QuicReal
	action := Structs.ADD
	real.Address = "10.0.0.1"
	real.Id = 1
	reals = append(reals, real)

	miniKatranLb.ModifyQuicRealsMapping(action, &reals)
	assert.Equal(t, 1, len(miniKatranLb.GetQuicRealsMapping()))

	miniKatranLb.ModifyQuicRealsMapping(action, &reals)
	assert.Equal(t, 1, len(miniKatranLb.GetQuicRealsMapping()))

	reals[0].Address = "2.0.0.1"
	miniKatranLb.ModifyQuicRealsMapping(action, &reals)
	resMap := miniKatranLb.GetQuicRealsMapping()
	assert.Equal(t, 1, len(resMap))
	assert.Equal(t, "2.0.0.1", resMap[0].Address)

	reals[0].Id = 2
	miniKatranLb.ModifyQuicRealsMapping(action, &reals)
	resMap = miniKatranLb.GetQuicRealsMapping()
	assert.Equal(t, 2, len(resMap))
	assert.Equal(t, "2.0.0.1", resMap[0].Address)
	assert.Equal(t, "2.0.0.1", resMap[1].Address)

	action = Structs.DEL

	//删除不存在id
	reals[0].Id = 100
	miniKatranLb.ModifyQuicRealsMapping(action, &reals)
	assert.Equal(t, 2, len(miniKatranLb.GetQuicRealsMapping()))

	//删除id为1的但是ip地址不对应
	reals[0].Id = 1
	reals[0].Address = "9.9.9.9"
	miniKatranLb.ModifyQuicRealsMapping(action, &reals)
	assert.Equal(t, 2, len(miniKatranLb.GetQuicRealsMapping()))


	reals[0].Id = 1
	reals[0].Address = "2.0.0.1"
	var real2 Structs.QuicReal
	real2.Id = 2
	real2.Address = "2.0.0.1"
	reals = append(reals, real2)
	miniKatranLb.ModifyQuicRealsMapping(action, &reals)
	assert.Equal(t, 0, len(miniKatranLb.GetQuicRealsMapping())) 
}


func TestGetRealsForVip(t *testing.T) {
	SetUp()
	miniKatranLb.AddVip(&v1, 0)
	miniKatranLb.AddRealForVip(&r1, &v1)
	miniKatranLb.AddRealForVip(&r2, &v1)
	assert.Equal(t, 2, len(miniKatranLb.GetRealsForVip(&v1)))
}


//缺少健康检查


func TestInvalidAddressHading(t *testing.T) {
	SetUp()
	var v Structs.VipKey
	v.Address = "aaa"
	v.Port = 0
	v.Proto = uint8(6)
	var r Structs.NewReal
	r.Address = "bbb"
	r.Weight = 1

	res := miniKatranLb.AddVip(&v, 0)
	assert.Equal(t, false, res, "invalid ip for lb's addvip")

	res = miniKatranLb.AddVip(&v1, 0)
	assert.Equal(t, true, res, "valid ip for lb's addvip")

	res = miniKatranLb.AddRealForVip(&r, &v1)
	rnum := miniKatranLb.GetRealsForVip(&v1)
	assert.Equal(t, 0, len(rnum), "invalid ip for lb's addvip. so no reals in v1")

	//缺少健康检查

	stats := miniKatranLb.GetMiniKatranLbStats()
	assert.Equal(t, uint64(2), stats.AddrValidationFailed)
}

func TestAddInvalidSrcRoutingRuleV4(t *testing.T) {
	SetUp()
	srcsv4 := []string{"10.0.0.0/24", "10.0.1.0/24"}
	res := miniKatranLb.AddSrcRoutingRule(&srcsv4, "fc00::1")
	assert.Equal(t, 0, res)
}

func TestAddInvalidSrcRoutingRuleV6(t *testing.T) {
	SetUp()
	srcsv6 := []string{"fc00:1::/64", "fc00:2::/64"}
	res := miniKatranLb.AddSrcRoutingRule(&srcsv6, "fc00::1")
	assert.Equal(t, 0, res)
}

func TestAddMaxSrcRules(t *testing.T) {
	SetUp()
	var srcs []string
	for i := 0; i < 20; i++ {
		prefix := fmt.Sprintf("10.0.%v.0/24", i)
		srcs = append(srcs, prefix)
	}

	res := miniKatranLb.AddSrcRoutingRule(&srcs, "fc00::1")
	assert.Equal(t, res, 10) 

	src_rules := miniKatranLb.GetSrcRoutingRule()
	assert.Equal(t, 10, len(src_rules))
	assert.Equal(t, 10, len(miniKatranLb.GetSrcRoutingRuleCidr()))
	assert.Equal(t, 10, len(miniKatranLb.LpmSrcMapping_))
	assert.Equal(t, 1, len(miniKatranLb.NumToReals_))

	src_, ok := src_rules["10.0.0.0/24"] //或者其他
	assert.Equal(t, true, ok)
	assert.Equal(t, src_, "fc00::1")
}

func TestDelSrcRules(t *testing.T) {
	SetUp()
	var srcs []string
	for i := 0; i < 10; i++ {
		prefix := fmt.Sprintf("10.0.%v.0/24", i)
		srcs = append(srcs, prefix)
	}

	assert.Equal(t, 0, miniKatranLb.AddSrcRoutingRule(&srcs, "fc00::1"))
	assert.Equal(t, 10, len(miniKatranLb.LpmSrcMapping_))
	log.Printf("len lpmSrcMapping is %v",len(miniKatranLb.LpmSrcMapping_))
	assert.Equal(t, true, miniKatranLb.DelSrcRoutingRule(&srcs))
	assert.Equal(t, 0, len(miniKatranLb.LpmSrcMapping_))
}

func TestClearSrcRules(t *testing.T) {
	SetUp()
	var srcs []string
	for i := 0; i < 10; i++ {
		prefix := fmt.Sprintf("10.0.%v.0/24", i)
		srcs = append(srcs, prefix)
	}

	assert.Equal(t, 0, miniKatranLb.AddSrcRoutingRule(&srcs, "fc00::1"))
	assert.Equal(t, 10, len(miniKatranLb.LpmSrcMapping_))
	assert.Equal(t, true, miniKatranLb.ClearAllSrcRoutingRules())
	assert.Equal(t, 0, len(miniKatranLb.LpmSrcMapping_))
}

func TestAddFewInvalidNets(t *testing.T) {
	SetUp()
	var srcs []string
	for i := 0; i < 7; i++ {
		prefix := fmt.Sprintf("10.0.%v.0/24", i)
		srcs = append(srcs, prefix)
	}
	srcs = append(srcs, "aaa")
	srcs = append(srcs, "bbb")
	res := miniKatranLb.AddSrcRoutingRule(&srcs, "fc00::1")
	assert.Equal(t, 2, res)
	assert.Equal(t, 7, len(miniKatranLb.LpmSrcMapping_))
}

func TestAddInvalidDecapDst(t *testing.T) {
	SetUp()

	assert.Equal(t, false, miniKatranLb.AddInlineDecapDst("asd"))

	assert.Equal(t, false, miniKatranLb.AddInlineDecapDst("fc00::/64"))
}

func TestAddValidDecapDst(t *testing.T) {
	SetUp()

	assert.Equal(t, true, miniKatranLb.AddInlineDecapDst("fc00::1"))
	assert.Equal(t, true, miniKatranLb.DelInlineDecapDst("fc00::1"))
	assert.Equal(t, false, miniKatranLb.DelInlineDecapDst("fc00::2"))
}

func TestAddMaxDecapDst(t *testing.T) {
	SetUp()

	assert.Equal(t, true, miniKatranLb.AddInlineDecapDst("fc00::1"))
	assert.Equal(t, true, miniKatranLb.AddInlineDecapDst("fc00::2"))
	assert.Equal(t, true, miniKatranLb.AddInlineDecapDst("fc00::3"))
	assert.Equal(t, true, miniKatranLb.AddInlineDecapDst("fc00::4"))
	assert.Equal(t, false, miniKatranLb.AddInlineDecapDst("fc00::5"))

	assert.Equal(t, 4, len(miniKatranLb.DecapDsts_))
}