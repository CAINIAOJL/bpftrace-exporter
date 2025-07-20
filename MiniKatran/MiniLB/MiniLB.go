package minilb

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"log"
	"net"
	"sort"
	"strconv"
	"unsafe"

	iphelper "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/IpHelper"
	MiniBpfAdapter "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/MiniBpfAdapter"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	//Packageattributes "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/PackageAttributes"
	Structs "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/Structs"
	Vip "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/Vip"
)

var (
	INVALID int = 1
  	HOST    int = 2
  	NETWORK int = 3
)

const (
	kMacAddrPos int 			= 0
	kIpv4TunPos int 			= 1
	kIpv6TunPos int 			= 2
	kMainIntfPos int 			= 3
	kHcIntfPos int 				= 4
	kIntrospectionGkPos int 	= 5

	kLruCntrOffset uint32 		= 0
	kLruMissOffset uint32 		= 1
	kLruFallbackOffset uint32 	= 3
	kIcmpTooBigOffset uint32 	= 4
	kLpmSrcOffset uint32 		= 5
	kInlineDecapOffset uint32 	= 6
	kGlobalLruOffset uint32 	= 8
	kChDropOffset uint32 		= 9
	kDecapCounterOffset uint32 	= 10
	kQuicIcmpOffset uint32 		= 11
	kIcmpPtbV6Offset uint32 	= 12
	kIcmpPtbV4Offset uint32 	= 13

	kFallbackLruSize int		= 1024
	kMapNoFlags int				= 0
	kNoNuma int 				= -1 

	V6DADDR uint8 				= 1
	kDeleteXdpProg int 			= -1
	kMacBytes int 				= 6
	kCtlMapSize int 			= 16
	kLruPrototypePos int 		= 0
	kMaxForwardingCores int 	= 128
	kFirstElem int 				= 0
	kError int 					= -1
	kMaxQuicIdV2 uint32 		= 0x00fffffe // 2^24-2
	kDefaultStatsIndex uint32 	= 0
	kEmptyString string 		= ""
	kSrcV4Pos uint32 			= 0
	kSrcV6Pos uint32 			= 1
	kRecirculationIndex uint32 	= 0
	kHcSrcMacPos uint32 		= 0
	kHcDstMacPos uint32 		= 1

	MiniBalancerProgName        = "balancer_prog"
)

const (
	ch_rings 		= "ch_rings"
	ctl_array 		= "ctl_array"
	decap_dst 		= "decap_dst"
	//event_pipe = "event_pipe"
	fallback_cache	= "fallback_cache"
	fallback_glru 	= "fallback_glru"
	//flow_debug_lru = "flow_debug_lru"
	//flow_debug_maps = "flow_debug_maps"
	global_lru 		= "global_lru"
	global_lru_maps = "global_lru_maps"
	//hc_ctrl_map = "hc_ctrl_map"
	//hc_key_map = "hc_key_map"
	//hc_pckt_macs = "hc_pckt_macs"
	//hc_pckt_srcs_map = "hc_pckt_srcs_map"
	//hc_reals_map = "hc_reals_map"
	//hc_stats_map = "hc_stats_map"
	minikatran_lru 	= "Minikatran_lru"
	lpm_src_4 		= "lpm_src_v4"
	lpm_src_6 		= "lpm_src_v6"
	lru_mapping 	= "lru_mapping"
	lru_miss_stats 	= "lru_miss_stats"
	pckt_srcs 		= "pckt_srcs"
	//per_hckey_stats = "per_hckey_stats"
	reals 			= "reals"
	server_id_map 	= "server_id_map"
	stats 			= "stats"
	reals_stats     = "reals_stats"
	vip_map 		= "vip_map"
	vip_miss_stats 	= "vip_miss_stats"
)

type MiniLb struct {

		MiniBpfAdapter *MiniBpfAdapter.MiniBpfAdapter
//-------------------------------------------------------------
		MiniKatranConfig Structs.MiniKatranConfig
//-------------------------------------------------------------
		MiniKatranLbStats Structs.MiniKatranLbStats

        // 特征结构体
        MinikatranFeatrues Structs.MiniKatranFeatures

        //ip地址------------------>RealMeta
        Reals_      map[string]Structs.RealMeta

        //num(序号)----------------> ip地址
        NumToReals_ map[uint32]string

        //RealsIdCallback_ *RealsIdCallback
//-------------------------------------------------------------
        vipNums_    []uint32

        RealNums_   []uint32

        //hcKeysNums_ []uint32
//-------------------------------------------------------------
        /**
         * 若果是持久化模式下，会有一个root map
         */
        //RootMapFd_					int
        /**
         * 是不是持久化模式
         */
        Standalone_                 bool

        /**
         * 是否已经加载了 BPF 程序
         */
        ProgsAttached_              bool

        /**
         * 是否已经加载了 BPF 程序
         */
        ProgsLoaded_                bool

        /**
         * 是否加载了监控器
         */
        //IntrospectionStarted_       bool

        /**
         * 全局lru的fallback map
         */
        GlobalLruFallbackFd_      	int

        /**
         * 是否已经加载了bpf程序
         */
        ProgsReloaded_      		bool
//-------------------------------------------------------------
        /**
         * 存储mac地址，ifindex信息的向量
         */
        CtlValues_mac 			 []Structs.Ctl_value_mac

		CtlValues_ifindex        []Structs.Ctl_value_ifindex

        /**
         * * 转发 CPU 的向量（负责 NIC 的 CPU/内核, IRQ 处理）
         */
        ForwardingCores_ 	 []uint32

        /**
         * * 可选向量，其中包含将核心转发到 NUMA NUMA 的映射此向量的长度必须为零（在本例中我们不使用它）或等于 forwardingCores_ 的长度
         */
        NumaNodes_ 			 []uint32
        /**
         * LRU maps 的文件描述符的向量
         */
        LruMapsFd_			 []int

        /**
         * 调试流数据的maps的文件描述符的向量
         */
        //FlowDebugMapsFd_     []int

        /**
         * 全局 LRU maps 的文件描述符的向量
         */
        globalLruMapsFd_     []int

//-------------------------------------------------------------
		vips_ map[Structs.VipKey]*Vip.Vip
    
		QuciMapping_ map[uint32]string
    
    	//HcReals_ map[uint32]net.IP
    
		LpmSrcMapping_ map[Structs.IpNet]uint32

		DecapDsts_ map[string]bool
    
		InvalidServerIds_ map[uint64]int

		Balancer_link *link.Link
}

func NewMiniKatran(config *Structs.MiniKatranConfig) (*MiniLb) {
	lb := &MiniLb{
		MiniKatranConfig: *config,
		CtlValues_mac: make([]Structs.Ctl_value_mac, kCtlMapSize),
		CtlValues_ifindex: make([]Structs.Ctl_value_ifindex, kCtlMapSize),
		Standalone_: true,
		ForwardingCores_: config.ForwardingCores,
		NumaNodes_: config.NumaNodes,
		LruMapsFd_: make([]int, kMaxForwardingCores),
		globalLruMapsFd_: make([]int, kMaxForwardingCores),
		Reals_: map[string]Structs.RealMeta{},
		NumToReals_: map[uint32]string{},
		vips_: map[Structs.VipKey]*Vip.Vip{},
		LpmSrcMapping_: map[Structs.IpNet]uint32{},
		DecapDsts_: map[string]bool{},
		InvalidServerIds_: map[uint64]int{},
		QuciMapping_: make(map[uint32]string),
		MiniBpfAdapter: MiniBpfAdapter.NewMiniBpfAdapter(true, true),
		MinikatranFeatrues: Structs.MiniKatranFeatures{
			SrcRouting: true,
			InlineDecap: true,
			GueEncapd: true,
			LocalDeliveryOptimization: true,
		},
	}

	for i := 0; i < int(config.MaxVips); i++ {
		lb.vipNums_ = append(lb.vipNums_, uint32(i))
		//缺少hc
	}

	//从1开始, 0不做序号！
	for i := 1; i < int(config.MaxReals); i++ {
		lb.RealNums_ = append(lb.RealNums_, uint32(i))
	}

	//缺少rootmap

	//缺少hc

	if(!config.Testing) {
		var ctl_m Structs.Ctl_value_mac
		var ctl_i Structs.Ctl_value_ifindex
		var res uint32

		if len(config.DefaultMac) != 6 {
			log.Fatalf("Invalid default mac address")
		}
		for i := 0; i < 6; i++ {
			ctl_m.Mac[i] = config.DefaultMac[i]
		}
		//ctl.Ifindex = 0
		//ctl.Value = 0
		lb.CtlValues_mac[kMacAddrPos] = ctl_m

		//缺少hc


		res = config.MainInterfaceIndex
		if res == 0 {
			index, err := net.InterfaceByName(config.MainInterface)
			if err != nil {
				log.Fatalf("Can't find interface %s", config.MainInterface)
			}
			if index.Index == 0 {
				log.Fatalf("Can't find interface %s", config.MainInterface)
			}
			res = uint32(index.Index)
		}
		ctl_i = Structs.Ctl_value_ifindex{
			Ifindex: res,
		}
		lb.CtlValues_ifindex[kMainIntfPos] = ctl_i
	}
	return lb
}	

func (lb *MiniLb) GetMiniKatranLbStats() Structs.MiniKatranLbStats {
	return lb.MiniKatranLbStats
}


func (lb *MiniLb) ChangeMac(newMac []uint8) bool {
	key := kMacAddrPos

	if len(newMac) != kMacBytes {
		return false
	}

	for i := 0; i < kMacBytes; i++ {
		lb.CtlValues_mac[key].Mac[i] = newMac[i]
	}

	if !lb.MiniKatranConfig.Testing {
		log.Printf("a")
		res := lb.MiniBpfAdapter.BpfUpdateMap(
									lb.MiniBpfAdapter.GetMapByName(ctl_array),
									key,
									lb.CtlValues_mac[key].Mac,
									0)
		if res != 0 {
			lb.MiniKatranLbStats.BpfFailedCalls++
			return false
		}

		//缺少健康检查
	}
	return true
}

func (lb *MiniLb) GetMac() [6]uint8 {
	return lb.CtlValues_mac[kMacAddrPos].Mac
}

func (lb *MiniLb) GetIndexOfNetworkInterfaces() map[int]uint32 {
	res := map[int]uint32{}
	res[kMainIntfPos] = lb.CtlValues_ifindex[kMainIntfPos].Ifindex
	
	//缺少hc
	return res
}

func (lb *MiniLb) vipKeyToVipDefinition(vipKey *Structs.VipKey) Structs.Vip_definition {
	Iphelper := iphelper.IPHelpers{}
	vip_addr, err := Iphelper.ParseAddrToBe(vipKey.Address, true)
 
	if err != nil {
		log.Printf("ParseAddrToBe error: %v", err.Error())
	}
	vip_def := Structs.Vip_definition{}
	if (vip_addr.Flags & V6DADDR) != 0 {
		//
		copy(vip_def.Vip6[:], vip_addr.Dstv6[:])
	} else {
		vip_def.Vip = vip_addr.Dst
	}
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, vipKey.Port)

	vip_def.Port = binary.BigEndian.Uint16(buf)
	
	vip_def.Proto = vipKey.Proto
	
	log.Printf("vip_def is %v", vip_def);
	return vip_def
}

func (lb *MiniLb) updateVipMap(op int, vip *Structs.VipKey, vipmeta *Structs.Vipmeta) bool {
	vip_def := lb.vipKeyToVipDefinition(vip)
	log.Printf("vipmeta's num: %v", vipmeta.Vip_num)
	log.Printf("vipmeta's flags: %v", vipmeta.Flags)
	if op == Structs.ADD {
		res := lb.MiniBpfAdapter.BpfUpdateMap(lb.MiniBpfAdapter.GetMapByName(vip_map), vip_def, *vipmeta, 0)
		if res != 0 {
			log.Printf("can't add new element into vip_map! ")
			lb.MiniKatranLbStats.BpfFailedCalls++
			return false
		}
	} else {
		res := lb.MiniBpfAdapter.BpfMapDeleteElement(lb.MiniBpfAdapter.GetMapByName(vip_map), vip_def)
		if res != 0 {
			log.Printf("can't delete element from vip_map! ")
			lb.MiniKatranLbStats.BpfFailedCalls++
			return false
		}
	}
	return true
}

func (lb *MiniLb) AddVip(vip *Structs.VipKey, flags uint32) bool {
	if lb.validateAddress(vip.Address, false) == INVALID {
		log.Printf("Invalid Vip address: %v", vip.Address)
		return false
	}
	log.Printf("adding new vip: %v:%v:%v", vip.Address, vip.Port, vip.Proto)

	if len(lb.vipNums_) == 0 {
		log.Printf("exhausted vip's space")
		return false
	}

	if _, ok := lb.vips_[*vip]; ok {
		log.Printf("trying to add already existing vip")
		return false
	}

	vip_num := lb.vipNums_[0]
	removeUint32(&lb.vipNums_, 0)
	lb.vips_[*vip] = Vip.NewVip(vip_num, flags, lb.MiniKatranConfig.ChRingSize, 2)
	if !lb.MiniKatranConfig.Testing {
		var vipmeta Structs.Vipmeta
		vipmeta.Vip_num = vip_num
		vipmeta.Flags = flags
		lb.updateVipMap(Structs.ADD, vip, &vipmeta) 
	}
	return true
}


//删除虚拟ip，删除这个虚拟ip对应所有reals
func (lb *MiniLb) DelVip(vip *Structs.VipKey) bool {
	log.Printf("deleting vip: %v:%v:%v", vip.Address, vip.Port, vip.Proto)

	vip_, ok := lb.vips_[*vip]
	if !ok {
		log.Printf("trying to delete non-existing vip")
		return false
	}

	vip_reals := vip_.GetReals()
	for _, vip_real := range vip_reals {
		real_num := lb.NumToReals_[vip_real]
		lb.decreaseRefCountForReal(real_num)
	}

	//每个vip都有一个序号
	lb.vipNums_ = append(lb.vipNums_, vip_.GetVipNum())
	if !lb.MiniKatranConfig.Testing {
		lb.updateVipMap(Structs.DEL, vip, nil)
	}
	delete(lb.vips_, *vip)
	return true
}

func HashIPToUint32FNV(ip *net.IP) uint64 {
	h := fnv.New64a()
	h.Write(*ip)
	return h.Sum64()
}

func (lb *MiniLb) validateAddress(addr string, allowNetAddr bool) int {
	ip := net.ParseIP(addr)
	if ip != nil {
		return HOST
	}

	if allowNetAddr && (lb.MinikatranFeatrues.SrcRouting || lb.MiniKatranConfig.Testing) {
		_, _, err := net.ParseCIDR(addr)
		if err == nil {
			return NETWORK
		}
	}

	lb.MiniKatranLbStats.AddrValidationFailed++
	log.Printf("Invalid address: %v", addr)
	return INVALID
}

func (lb *MiniLb) AddRealForVip(real *Structs.NewReal, vipkey *Structs.VipKey) bool {
	var reals []Structs.NewReal
	reals = append(reals, *real)
	return lb.ModifyRealsForVip(Structs.ADD, &reals, vipkey)
}

func (lb *MiniLb) DelRealForVip(real *Structs.NewReal, vipkey *Structs.VipKey) bool {
	var reals []Structs.NewReal
	reals = append(reals, *real)
	return lb.ModifyRealsForVip(Structs.DEL, &reals, vipkey)
}

//修改
func (lb *MiniLb) updateRealsMap(real string, num uint32, flags uint8) bool {
	Iphelper := iphelper.IPHelpers{}
	//解析ip地址
	real_addr, err := Iphelper.ParseAddrToBe(real, true)
	if err != nil {
		log.Printf("ParseAddrToBe error: %v", err.Error())
		return false
	}
	
	flags &= ^V6DADDR //先把V6标志擦除
	real_addr.Flags |= flags //这边添加标志，V6标志会在解析ip时自动添加

	res := lb.MiniBpfAdapter.BpfUpdateMap(lb.MiniBpfAdapter.GetMapByName(reals), num, real_addr, 0)
    if res != 0 {
		log.Printf("can't add new real!")
		lb.MiniKatranLbStats.BpfFailedCalls++
		return false
	}
	return true
}


func containsSorted(slice *[]uint32, value uint32) bool {
    length := len(*slice)
    idx := sort.Search(length, func(i int) bool {
        return (*slice)[i] >= value
    })
    return idx < length && (*slice)[idx] == value
}

func removeUint32(slice *[]uint32, i int) bool {
    s := *slice
    if i < 0 || i >= len(s) {
        return false
    }
    *slice = append(s[:i], s[i+1:]...)
    return true
}


func (lb *MiniLb) decreaseRefCountForReal(real string) {
	real_, ok := lb.Reals_[real]
	if !ok {
		return
	}
	real_.RefCount--
	if real_.RefCount == 0 {
		num := real_.Num
		lb.RealNums_ = append(lb.RealNums_, num)
		delete(lb.Reals_, real)
		delete(lb.NumToReals_, num)

		//回调记录删除信息
	} else {
		//real_.Refcount > 0
		//放回映射中
		lb.Reals_[real] = real_
	}
}

func (lb *MiniLb) increaseRefCountForReal(real string, flags uint8) uint32 {
	real_, ok := lb.Reals_[real]
	log.Printf("real is %v", real)
	flags &= ^V6DADDR
	if ok {
		real_.RefCount++
		lb.Reals_[real] = real_ //记住，要将value值放入map映射中，否则value映射不更新
		//log.Printf("第二次")
		return real_.Num
	} else {
		//log.Printf("第一次")
		if len(lb.RealNums_) == 0 {
			//没有备用的num
			return lb.MiniKatranConfig.MaxReals
		}
		//新建
		var rmeta Structs.RealMeta
		rnum := lb.RealNums_[0]
		removeUint32(&lb.RealNums_, 0)
		lb.NumToReals_[rnum] = real
		rmeta.RefCount = 1
		rmeta.Flags = flags
		rmeta.Num = rnum
		lb.Reals_[real] = rmeta
		//log.Printf("添加")
		//log.Printf("net.ip is %v", real)
		if !lb.MiniKatranConfig.Testing {
			lb.updateRealsMap(real, rnum, flags)
		}

		//回调记录新建信息

		return rnum
	}
}

func (lb *MiniLb) programHashRing(chposition []Structs.RealPos, vipnum uint32) {
	if len(chposition) == 0 {
		return //没有变化
	}

	if !lb.MiniKatranConfig.Testing {
		updateSize := len(chposition)
		keys := make([]uint32, updateSize)
		values:= make([]uint32, updateSize)

		ch_fd := lb.MiniBpfAdapter.GetMapByName(ch_rings)
	
		for i := 0; i < updateSize; i++ {
			keys[i] = vipnum * lb.MiniKatranConfig.ChRingSize + chposition[i].Pos
			values[i] = chposition[i].Real
		}

		res := lb.MiniBpfAdapter.BpfUpdateMapBatch(ch_fd, keys, values, uint32(updateSize))
		if res != 0 {
			lb.MiniKatranLbStats.BpfFailedCalls++
			log.Printf("can't update ch ring!")
		}
	}	
}

func (lb *MiniLb) ModifyRealsForVip(op int, reals *[]Structs.NewReal, vipkey *Structs.VipKey) bool {
	var ureal Structs.UpdateReal
	var ureals []Structs.UpdateReal
	ureal.Op = op

	vip_, ok := lb.vips_[*vipkey]
	if !ok {
		log.Printf("trying to modify reals for non existing vip: %v", *vipkey)
		return false
	}

	cur_reals := vip_.GetReals()
	for _, r := range *reals {
		ip_type := lb.validateAddress(r.Address, false)
		if ip_type == INVALID {
			log.Printf("Invalid real's address: %v", r.Address)
			continue
		}
		IpKey := net.ParseIP(r.Address)
		if err := IpKey.To4(); err == nil {
			if err = IpKey.To16(); err == nil {
				log.Printf("Invalid real's address: %v", r.Address)
				return false
			}
		}
		if op == Structs.DEL {
			real_, ok:= lb.Reals_[r.Address]
			if !ok {
				log.Printf("trying to delete non-existing real")
				continue
			}
			if !containsSorted(&cur_reals, real_.Num) {
				log.Printf("trying to delete non-existing real")
				continue
			}
			ureal.UpdateReal.Num = real_.Num
			lb.decreaseRefCountForReal(r.Address)
		} else {
			real_, ok:= lb.Reals_[r.Address]
			if ok {
				if containsSorted(&cur_reals, real_.Num) {
					lb.increaseRefCountForReal(r.Address, r.Flags)
					cur_reals = append(cur_reals, real_.Num)
				}
				ureal.UpdateReal.Num = real_.Num
			} else {
				log.Printf("ip is %v", IpKey.String())
				rnum := lb.increaseRefCountForReal(r.Address, r.Flags)
				if rnum == lb.MiniKatranConfig.MaxReals {
					log.Printf("exhausted real's space")
					continue
				}
				ureal.UpdateReal.Num = rnum
			}
			ureal.UpdateReal.Weight = r.Weight
			ureal.UpdateReal.Hash = HashIPToUint32FNV(&IpKey) //
		}
		ureals = append(ureals, ureal)
	}

	//更新，获得差异数组
	ch_positions := vip_.BatchRealsUpdate(ureals)
	vip_num := vip_.GetVipNum() //获得这个vip的num
	lb.programHashRing(ch_positions, vip_num)
	return true
}

func (lb *MiniLb) ModifyReal(real string, flags uint8, set bool) bool {
	if lb.validateAddress(real, false) == INVALID {
		log.Printf("invalid real's address: %v", real)
		return false
	}

	log.Printf("modifying real: %v", real)

	real_, ok := lb.Reals_[real]
	if !ok {
		log.Printf("trying to modify non-existing real: %v", real)
		return false
	}

	flags &= ^V6DADDR
	if set {
		real_.Flags |= flags
		log.Println(real_.Flags)
	} else {
		real_.Flags &= ^flags
		log.Println(real_.Flags)
	}
	lb.Reals_[real] = real_

	if !lb.MiniKatranConfig.Testing {
		lb.updateRealsMap(real, real_.Num, real_.Flags)
	}
	return true
}

func (lb *MiniLb) GetRealsForVip(vip *Structs.VipKey) []Structs.NewReal {
	vip_, ok := lb.vips_[*vip]
	if !ok {
		log.Printf("trying to get real from non-existing vip: %v", vip)
		return nil
	}

	vip_reals_ids := vip_.GetRealsAndWeight()
	if len(vip_reals_ids) == 0 {
		log.Printf("vip %v has no reals", vip)
		return nil
	}
	
	//这边初始化后数组长度之后（默认有长度，即有空的实体），不能用append添加，否则会在原有的上面添加，个数会变
	reals := make([]Structs.NewReal, len(vip_reals_ids))
	newReal := Structs.NewReal{}
	i := 0
	for _, r := range vip_reals_ids {
		newReal.Weight = r.Weight
		newReal.Address = lb.NumToReals_[r.Num]
		newReal.Flags = lb.Reals_[lb.NumToReals_[r.Num]].Flags
		reals[i] = newReal
		i++
	}
	return reals
}

func (lb *MiniLb) GetStatsForVip(vip *Structs.VipKey) Structs.Lb_stats {
	vip_, ok := lb.vips_[*vip]
	if !ok {
		log.Printf("trying to get stats for non-existing vip %v", vip)
		return Structs.Lb_stats{}
	}

	num := vip_.GetVipNum()
	return lb.getLbStats(num, stats)
}

func (lb *MiniLb) GetChDropStats() Structs.Lb_stats {
  return lb.getLbStats(lb.MiniKatranConfig.MaxVips + kChDropOffset, stats);
}

func (lb *MiniLb) GetSrcRoutingStats() Structs.Lb_stats{
  return lb.getLbStats(lb.MiniKatranConfig.MaxVips + kLpmSrcOffset, stats);
}

func (lb *MiniLb) GetInlineDecapStats() Structs.Lb_stats{
  return lb.getLbStats(lb.MiniKatranConfig.MaxVips + kInlineDecapOffset, stats);
}

func (lb *MiniLb) GetGlobalLruStats() Structs.Lb_stats{
  return lb.getLbStats(lb.MiniKatranConfig.MaxVips + kGlobalLruOffset, stats);
}

func (lb *MiniLb) GetDecapStats() Structs.Lb_stats{
  return lb.getLbStats(lb.MiniKatranConfig.MaxVips + kDecapCounterOffset, stats);
}

func (lb *MiniLb) GetQuicIcmpStats() Structs.Lb_stats{
  return lb.getLbStats(lb.MiniKatranConfig.MaxVips + kQuicIcmpOffset, stats);
}

func (lb *MiniLb) GetIcmpPtbV6Stats() Structs.Lb_stats{
  return lb.getLbStats(lb.MiniKatranConfig.MaxVips + kIcmpPtbV6Offset, stats);
}

func (lb *MiniLb) GetIcmpPtbV4Stats() Structs.Lb_stats{
  return lb.getLbStats(lb.MiniKatranConfig.MaxVips + kIcmpPtbV4Offset, stats);
}

func (lb *MiniLb) GetRealsStats(num uint32) Structs.Lb_stats {
	return lb.getLbStats(num, reals_stats)
}

func (lb *MiniLb) GetLruStats() Structs.Lb_stats{
  return lb.getLbStats(lb.MiniKatranConfig.MaxVips + kLruCntrOffset, stats);
}

func (lb *MiniLb) GetLruMissStats() Structs.Lb_stats{
  return lb.getLbStats(lb.MiniKatranConfig.MaxVips + kLruMissOffset, stats);
}

func (lb *MiniLb) GetLruFallbackStats() Structs.Lb_stats{
  return lb.getLbStats(lb.MiniKatranConfig.MaxVips + kLruFallbackOffset, stats);
}

func (lb *MiniLb) GetIcmpTooBigStats() Structs.Lb_stats{
  return lb.getLbStats(lb.MiniKatranConfig.MaxVips + kIcmpTooBigOffset, stats);
}

func (lb *MiniLb) GetTcpServerIdRoutingStats() Structs.Lb_tpr_packets_stats {
	nr_cpus, err := ebpf.PossibleCPU()
	if err != nil {
		log.Printf("Error while getting number of possible cpus, err: %v", err)
		return Structs.Lb_tpr_packets_stats{}
	}

	stats := make([]Structs.Lb_tpr_packets_stats, nr_cpus)
	sum_stat := Structs.Lb_tpr_packets_stats{}

	if !lb.MiniKatranConfig.Testing {
		position := 0
		if res := lb.MiniBpfAdapter.BpfMapLookupElement(lb.MiniBpfAdapter.GetMapByName("tpr_stats_map"), position, &stats, 0); res == 0{
			for _, s := range stats {
				sum_stat.Ch_routed += s.Ch_routed
				sum_stat.Dst_missmatch_in_lru += s.Dst_missmatch_in_lru
				sum_stat.Sid_routed += s.Sid_routed
				sum_stat.Tcp_syn += s.Tcp_syn
			}
		} else {
			lb.MiniKatranLbStats.BpfFailedCalls++
		}
	}
	return sum_stat
}

func (lb *MiniLb) GetUdpStableRoutingStats() Structs.Lb_stable_rt_packets_stats {
	nr_cpus, err := ebpf.PossibleCPU()
	if err != nil {
		log.Printf("Error while getting number of possible cpus, err: %v", err)
		return Structs.Lb_stable_rt_packets_stats{}
	}

	stats := make([]Structs.Lb_stable_rt_packets_stats, nr_cpus)
	sum_stat := Structs.Lb_stable_rt_packets_stats{}

	if !lb.MiniKatranConfig.Testing {
		position := 0

		if res := lb.MiniBpfAdapter.BpfMapLookupElement(lb.MiniBpfAdapter.GetMapByName("stable_rt_stats"), position, &stats, 0); res == 0{
			for _, s := range stats {
				sum_stat.Ch_routed += s.Ch_routed
				sum_stat.Cid_routed += s.Cid_routed
				sum_stat.Cid_invalid_server_id += s.Cid_invalid_server_id
				sum_stat.Cid_unknown_real_dropped += s.Cid_unknown_real_dropped
			}
		} else {
			lb.MiniKatranLbStats.BpfFailedCalls++
		}
	}
	return sum_stat

}

func (lb *MiniLb) getLbStats(num uint32, MapName string) Structs.Lb_stats {
	//获取当前的cpu数量
	nr_cpu, err := ebpf.PossibleCPU()
	if err != nil {
		log.Printf("Error while getting number of possible cpus, err: %v", err)
		return Structs.Lb_stats{}
	}

	//传递指针！
	stats := make([]Structs.Lb_stats, nr_cpu)
	sum_stat := Structs.Lb_stats{}

	if !lb.MiniKatranConfig.Testing {
		res := lb.MiniBpfAdapter.BpfMapLookupElement(lb.MiniBpfAdapter.GetMapByName(MapName), num, &stats, 0)
		if res == 0 {
			for _, s := range stats {
				sum_stat.V1 += s.V1
				sum_stat.V2 += s.V2
			}
		} else {
			lb.MiniKatranLbStats.BpfFailedCalls++
		}
	}
	return sum_stat
}

func (lb *MiniLb) GetVipFlags(vip *Structs.VipKey) (uint32, int) {
	vip_, ok := lb.vips_[*vip]
	if !ok {
		log.Printf("trying to get flags from non-existing vip: %v", vip)
		return 0, -1 //特殊检查
	}
	return vip_.GetVipFlags(), 0
}

func (lb *MiniLb) GetAllVips() []Structs.VipKey {
	var result []Structs.VipKey
	for v := range lb.vips_ {
		result = append(result, v)
	}
	return result
}

func (lb *MiniLb) GetNumToRealsMap() map[uint32]string {
	result := map[uint32]string{}

	for num, real := range lb.NumToReals_ {
		result[num] = real
	}
	return result
}

func (lb *MiniLb) GetIndexForReal(real string) (bool, uint32) {
	if lb.validateAddress(real, false) == INVALID {
		log.Printf("Invalid real address: %v", real)
		return false, 0
	}
	real_, ok := lb.Reals_[real]
	if ok {
		return true, real_.Num
	}
	return false, 0
}

func (lb *MiniLb) AddSrcRoutingRule(srcs *[]string, dst string) int {
	num_error := 0

	if !lb.MinikatranFeatrues.SrcRouting && !lb.MiniKatranConfig.Testing {
		log.Printf(" 1 Source based routing is not enabled in forwarding plane")
		return kError
	}

	if lb.validateAddress(dst, true) == INVALID {
		log.Printf("Invalid dst address for src routing: %v", dst)
		return kError
	}

	var src_networks []*net.IPNet

	for _, src := range *srcs {
		if lb.validateAddress(src, true) == INVALID {
			log.Printf("trying to add incorrect addr for src routing %v ", src)
			num_error++
			continue
		}

		if (len(lb.LpmSrcMapping_) + len(src_networks) + 1) > int(lb.MiniKatranConfig.MaxLpmSrcSize) {
			log.Printf("source mappings map size is exhausted")
			num_error += (len(*srcs) - len(src_networks))
			break
		}
		_, netmask, _ := net.ParseCIDR(src)
		src_networks = append(src_networks, netmask)
	}


	ral := lb.addSrcRoutingRule(&src_networks, dst)
	if ral == kError {
		num_error = ral
	}

	return num_error
}

func (lb *MiniLb) addSrcRoutingRule(srcs *[]*net.IPNet, dst string) int {
	if !lb.MinikatranFeatrues.SrcRouting && !lb.MiniKatranConfig.Testing {
		log.Printf("2 Source based routing is not enabled in forwarding plane")
		return kError
	}

	if lb.validateAddress(dst, true) == INVALID {
		log.Printf("Invalid dst address for src routing: %v", dst)
		return kError
	}

	for _, src := range *srcs {
		if len(lb.LpmSrcMapping_) + 1 > int(lb.MiniKatranConfig.MaxLpmSrcSize) {
			log.Printf("source mappings map size is exhausted")
			return kError
		}

		rnum := lb.increaseRefCountForReal(dst, 0)
		log.Printf("rnum is %v", rnum);
		if rnum == lb.MiniKatranConfig.MaxReals {
			log.Printf("exhausted real's space")
			return kError
		}
		mask, _ := src.Mask.Size()
		key := Structs.IpNet{
			Ip: src.IP.String(),
			Mask: mask,
		}

		lb.LpmSrcMapping_[key] = rnum
		if !lb.MiniKatranConfig.Testing {
			lb.modifyLpmSrcRule(Structs.ADD, src, &rnum)
		}
	}
	return 0
}

func (lb *MiniLb) modifyLpmSrcRule(action int, src *net.IPNet, rnum *uint32) bool {
	return lb.modifyLpmMap("lpm_src", action, src, rnum)
}

func (lb *MiniLb) modifyLpmMap(map_name string, action int, src *net.IPNet, rnum *uint32) bool {
	IpHelper := iphelper.IPHelpers{}

	lpm_addr, _ := IpHelper.ParseAddrToBe(src.IP.String(), true)

	if (lpm_addr.Flags & V6DADDR) == 0 {
		var key_v4 Structs.Lpm_key_v4
		src4 := src.IP.To4()
		key_v4.Addr = *(*uint32)(unsafe.Pointer(&src4[0]))
		mask, _ := src.Mask.Size()
		//估计会有问题
		key_v4.Prefixlen = uint32(mask)
		map_name = map_name + "_v4"
		if action == Structs.ADD {
			
			res := lb.MiniBpfAdapter.BpfUpdateMap(lb.MiniBpfAdapter.GetMapByName(map_name), key_v4, *rnum, 0)
			if res != 0 {
				log.Printf("can't add new element into %v ", map_name)
				lb.MiniKatranLbStats.BpfFailedCalls++
				return false
			}
		} else {
			res := lb.MiniBpfAdapter.BpfMapDeleteElement(lb.MiniBpfAdapter.GetMapByName(map_name), key_v4)
			if res != 0 {
				log.Printf("can't delete element from %v", map_name)
				lb.MiniKatranLbStats.BpfFailedCalls++
				return false
			}
		}
	} else {
		var key_v6 Structs.Lpm_key_v6
		src6 := src.IP.To16()
		copy(key_v6.Addr[:], src6)
		map_name = map_name + "_v6"
		mask, _ := src.Mask.Size()
		key_v6.Prefixlen = uint32(mask)
		if action == Structs.ADD {
			
			res := lb.MiniBpfAdapter.BpfUpdateMap(lb.MiniBpfAdapter.GetMapByName(map_name), key_v6, *rnum, 0)
			if res != 0 {
				log.Printf("can't add new element into %v", map_name)
				lb.MiniKatranLbStats.BpfFailedCalls++
				return false
			}
		} else {
			res := lb.MiniBpfAdapter.BpfMapDeleteElement(lb.MiniBpfAdapter.GetMapByName(map_name), key_v6)
			if res != 0 {
				log.Printf("can't delete element from %v", map_name)
				lb.MiniKatranLbStats.BpfFailedCalls++
				return false
			}
		}
	}
	return true
}

func (lb *MiniLb) GetSrcRoutingRule() map[string]string {
	var res map[string]string
	res = make(map[string]string)
	if !lb.MinikatranFeatrues.SrcRouting && !lb.MiniKatranConfig.Testing {
		log.Printf("3 Source based routing is not enabled in forwarding plane")
		return res
	} 

	for cidr, num := range lb.LpmSrcMapping_ {
		real := lb.NumToReals_[num]
		src_networks := fmt.Sprintf("%v/%v", cidr.Ip, cidr.Mask)
		res[src_networks] = real
	}
	return res
}

func (lb *MiniLb) GetSrcRoutingRuleCidr() map[Structs.IpNet]string {
	var res map[Structs.IpNet]string
	res = make(map[Structs.IpNet]string)
	if !lb.MinikatranFeatrues.SrcRouting && !lb.MiniKatranConfig.Testing {
		log.Printf("4 Source based routing is not enabled in forwarding plane")
		return res
	} 

	for cidr, num := range lb.LpmSrcMapping_ {
		real := lb.NumToReals_[num]
		res[cidr] = real
	}
	return res
}

func (lb *MiniLb) DelSrcRoutingRule(srcs *[]string) bool {
	if !lb.MinikatranFeatrues.SrcRouting && !lb.MiniKatranConfig.Testing {
		log.Printf("5 Source based routing is not enabled in forwarding plane")
		return  false
	}

	var src_net []*net.IPNet
	for _, src := range *srcs {
		_, ipnet, _ := net.ParseCIDR(src)
		src_net = append(src_net, ipnet)
	}
	return lb.delSrcRoutingRule(&src_net)
}

func (lb *MiniLb) delSrcRoutingRule(src_net *[]*net.IPNet) bool {
	if !lb.MinikatranFeatrues.SrcRouting && !lb.MiniKatranConfig.Testing {
		log.Printf("6 Source based routing is not enabled in forwarding plane")
		return  false
	}

	for _, src := range *src_net {
		mask, _ := src.Mask.Size()
		key := Structs.IpNet{
			Ip: src.IP.String(),
			Mask: mask,
		}
		src_, ok := lb.LpmSrcMapping_[key]
		if !ok {
			log.Printf("trying to delete non existing src mapping %v/%v", src.IP, src.Mask)
			continue
		}

		dst := lb.NumToReals_[src_]
		lb.decreaseRefCountForReal(dst)
		if !lb.MiniKatranConfig.Testing {
			lb.modifyLpmSrcRule(Structs.DEL, src, &src_)
		}
		delete(lb.LpmSrcMapping_, key)
	}
	return true
}

func (lb *MiniLb) ClearAllSrcRoutingRules() bool {
	if !lb.MinikatranFeatrues.SrcRouting && !lb.MiniKatranConfig.Testing {
		log.Printf("7 Source based routing is not enabled in forwarding plane")
		return  false
	}

	for ipnet, rnum := range lb.LpmSrcMapping_ {
		dst_, ok := lb.NumToReals_[rnum]
		if !ok {
			log.Printf("Real %s not found for src routing rule %s", dst_, ipnet.Ip)
			return false
		}
		lb.decreaseRefCountForReal(dst_)
		mask := net.CIDRMask(ipnet.Mask, 32)
		cidr := net.IPNet {
			IP: net.IP(ipnet.Ip),
			Mask: mask,
		} 
		if !lb.MiniKatranConfig.Testing {
			lb.modifyLpmSrcRule(Structs.DEL, &cidr, &rnum)
		}
	}

	clear(lb.LpmSrcMapping_)
	return true
}

func (lb *MiniLb) AddInlineDecapDst(dst string) bool {
	if !lb.MinikatranFeatrues.InlineDecap && !lb.MiniKatranConfig.Testing {
		log.Printf("8 source based routing is not enabled in forwarding plane")
		return false
	}

	if lb.validateAddress(dst, false) == INVALID {
		log.Printf("invalid decap destination address: %v", dst)
		return false
	}

	_, ok := lb.DecapDsts_[dst]
	if ok {
		log.Printf("trying to add already existing decap dst")
		return false
	}

	if len(lb.DecapDsts_) + 1 > int(lb.MiniKatranConfig.MaxDecapDst) {
		log.Printf("size of decap destinations map is exhausted")
		return false
	}

	log.Printf("adding decap dst %v", dst)
	lb.DecapDsts_[dst] = true
	if !lb.MiniKatranConfig.Testing {
		lb.modifyDecapDst(Structs.ADD, dst, 0)
	}
	return true
}

func (lb *MiniLb) DelInlineDecapDst(dst string) bool {
	if !lb.MinikatranFeatrues.InlineDecap && !lb.MiniKatranConfig.Testing {
		log.Printf("9 source based routing is not enabled in forwarding plane")
		return false
	}

	if lb.validateAddress(dst, false) == INVALID {
		log.Printf("invalid decap destination address: %v", dst)
		return false
	}

	_, ok := lb.DecapDsts_[dst]
	if !ok {
		log.Printf("trying to delete non-existing decap dst %v", dst)
		return false
	}

	log.Printf("deleting decap dst %v", dst)
	delete(lb.DecapDsts_, dst)

	if !lb.MiniKatranConfig.Testing {
		lb.modifyDecapDst(Structs.DEL, dst, 0)
	}
	return true
}


func (lb *MiniLb) modifyDecapDst(option int, dst string, flags uint32) bool {
	Iphelper := iphelper.IPHelpers{}
	baddr, _:= Iphelper.ParseAddrToBe(dst, true)

	if (baddr.Flags & V6DADDR) == 0 {
		//v4
		addr := Structs.Address{
			Addr: baddr.Dst,
		}
		if option == Structs.ADD {
			res := lb.MiniBpfAdapter.BpfUpdateMap(lb.MiniBpfAdapter.GetMapByName(decap_dst), addr, flags, 0)
			if res != 0 {
				log.Printf("error while adding dst for inline decap %v", dst)
				lb.MiniKatranLbStats.BpfFailedCalls++
				return false
			}
		} else {
			res := lb.MiniBpfAdapter.BpfMapDeleteElement(lb.MiniBpfAdapter.GetMapByName(decap_dst), addr)
			if res != 0 {
				log.Printf("error while deleting dst for inline decap %v", dst)
				lb.MiniKatranLbStats.BpfFailedCalls++
				return false
			}
		}
	} else {
		//v6
		addr := Structs.Address{
		}
		copy(addr.Addrv6[:], baddr.Dstv6[:])
		if option == Structs.ADD {
			res := lb.MiniBpfAdapter.BpfUpdateMap(lb.MiniBpfAdapter.GetMapByName(decap_dst), addr, flags, 0)
			if res != 0 {
				log.Printf("error while adding dst for inline decap %v", dst)
				lb.MiniKatranLbStats.BpfFailedCalls++
				return false
			}
		} else {
			res := lb.MiniBpfAdapter.BpfMapDeleteElement(lb.MiniBpfAdapter.GetMapByName(decap_dst), addr)
			if res != 0 {
				log.Printf("error while deleting dst for inline decap %v", dst)
				lb.MiniKatranLbStats.BpfFailedCalls++
				return false
			}
		}
	}
	return true
}

func (lb *MiniLb) ModifyVip(vip *Structs.VipKey, flag uint32, set bool) bool {
	log.Printf("modifying vip: %v flag: %v", vip, flag)

	vip_, ok := lb.vips_[*vip]
	if !ok {
		log.Printf("trying to modify non-existing vip: %v", vip)
		return  false
	}

	if set {
		vip_.SetVipFlags(flag)
	} else {
		vip_.UnsetVipFlags(flag)
	}

	//再加入map中
	lb.vips_[*vip] = vip_

	if !lb.MiniKatranConfig.Testing {
		var meta Structs.Vipmeta
		meta.Vip_num = vip_.VipNum_
		meta.Flags = vip_.VipFlags_
		return lb.updateVipMap(Structs.ADD, vip, &meta)
	}
	return true
}

func (lb *MiniLb) createLruMap(size int, flags int, numanode int, cpu int) int {
	var flowKeyInstance Structs.FlowKey
    var realPosLRUInstance Structs.RealPosLRU
	return lb.MiniBpfAdapter.CreateNameBpfMap(
				minikatran_lru + strconv.Itoa(cpu), 
				int(ebpf.LRUHash), int(unsafe.Sizeof(flowKeyInstance)), int(unsafe.Sizeof(realPosLRUInstance)), size, flags, numanode)
}

func (lb *MiniLb) initLrus() bool {
	//缺少检查flow流与健康检查

	forwarding_cores_specified := false
	numa_mapping_specified := false

	if len(lb.ForwardingCores_) != 0 {
		if len(lb.NumaNodes_) != 0 {
			if len(lb.ForwardingCores_) != len(lb.NumaNodes_) {
				fmt.Println("Error: number of forwarding cores and number of numa nodes do not match")
				return false
			}
			numa_mapping_specified = true //numa与转发节点匹配
		}

		per_core_lru_size := int(lb.MiniKatranConfig.LruSize) / len(lb.ForwardingCores_)
		log.Printf("per cpu lru size: %d", per_core_lru_size)

		for i := 0; i < len(lb.ForwardingCores_); i++ {
			core := lb.ForwardingCores_[i]
			if core > uint32(kMaxForwardingCores) || core < 0 {
				log.Printf("got core# %v which is not in supported range: [0 : %v]", core, kMaxForwardingCores)
				return false
			}

			numa_node := kNoNuma
			lru_map_flags := 0

			if numa_mapping_specified {
				numa_node = int(lb.NumaNodes_[i])
				lru_map_flags |= 1 << 2 //BPF_F_NUMA_NODE标志
			}

			lru_fd := lb.createLruMap(per_core_lru_size, lru_map_flags, numa_node, int(core))
			if lru_fd < 0 {
				log.Printf("can't creat lru for core: %v", core)
				log.Printf("can't create LRU for forwarding core")
				return false
			}
			lb.LruMapsFd_[core] = lru_fd

			//缺少flow与globalLru的初始化

		}
		forwarding_cores_specified = true
	}

	lru_proto_fd := 0
	if forwarding_cores_specified {
		lru_proto_fd = lb.LruMapsFd_[lb.ForwardingCores_[kFirstElem]]
	} else {
		lru_proto_fd = lb.createLruMap(kFallbackLruSize, kMapNoFlags, kNoNuma, 0)
		
		if lru_proto_fd < 0 {
			log.Printf("can't create prototype map for test lru")
			return false
		}
	}

	res := lb.MiniBpfAdapter.SetInnerMapPrototype(lru_mapping, lru_proto_fd)
	if res < 0 {
		log.Printf("can't update inner_maps_fds w/ prototype for main lru")
		return false
	}
	return true
}	

func (lb *MiniLb) initGlobalLruProtoTypeMap() bool {
	log.Printf("initGlobalLruProtoTypeMap ")

	prog_fd := -1

	if len(lb.ForwardingCores_) != 0 {
		prog_fd = lb.globalLruMapsFd_[lb.ForwardingCores_[kFirstElem]]
	} else {
		log.Printf("Creating generic flow debug lru")
		var flowKeyInstance Structs.FlowKey
		var u32 uint32
		prog_fd = lb.MiniBpfAdapter.CreateNameBpfMap(
			global_lru,
			int(ebpf.LRUHash),
			int(unsafe.Sizeof(flowKeyInstance)),
			int(unsafe.Sizeof(u32)),
			kFallbackLruSize,
			kMapNoFlags,
			kNoNuma,
		)
	}

	if prog_fd < 0 {
		log.Printf("can't create global LRU prototype! ")
		return false
	}

	res := lb.MiniBpfAdapter.SetInnerMapPrototype(global_lru_maps, prog_fd)
	if res < 0 {
		log.Printf("can't update inner_maps_fds w/ prototype for global lru")
		return  false
	}
	log.Printf("Created global_lru map proto")
	return true
}

func (lb *MiniLb) initialSanityChecking() bool {
	var res int

	maps := []string{
		ctl_array,
		vip_map,
		ch_rings,
		reals,
		stats,
		lru_mapping,
		server_id_map,
		lru_miss_stats,
		vip_miss_stats,
		global_lru_maps,
	}

	res = lb.MiniBpfAdapter.GetProgFdByName()

	if res < 0 {
		log.Printf("can't get fd for prog: %v", Structs.KBalancerProgName)
		return false
	}

	//缺少hc健康检查

	for _, m := range maps {
		ok := lb.MiniBpfAdapter.GetMapByName(m)
		if ok == nil {
			log.Printf("missing map: %v not found! ", m)
			return false
		}
	}
	return true
}

func (lb *MiniLb) featureDiscovering() {
	if lb.MiniBpfAdapter.IsMapInProg(Structs.KBalancerProgName, lpm_src_4) {
		log.Printf("source based routing is supported ")
		lb.MinikatranFeatrues.SrcRouting = true
	} else {
		lb.MinikatranFeatrues.SrcRouting = false
	}

	if lb.MiniBpfAdapter.IsMapInProg(Structs.KBalancerProgName, decap_dst) {
		log.Printf("inline decapsulation is supported ")
		lb.MinikatranFeatrues.InlineDecap = true
	} else {
		lb.MinikatranFeatrues.InlineDecap = false
	}

	//缺少event_pipe选项

	if lb.MiniBpfAdapter.IsMapInProg(Structs.KBalancerProgName, pckt_srcs) {
		log.Printf("GUE encapsulation is supported ")
		lb.MinikatranFeatrues.GueEncapd = true
	} else {
		lb.MinikatranFeatrues.GueEncapd = false
	}

	//缺少hc和flow debug
}

func (lb *MiniLb) setUpGueEnvironment() bool {
	if len(lb.MiniKatranConfig.MiniKatranSrcV4) == 0 && len(lb.MiniKatranConfig.MiniKatranSrcV6) == 0 {
		log.Printf("No source address provided to use as source GUE encapsulation")
	}
	log.Printf("MiniKatranSrcV4 : %v", lb.MiniKatranConfig.MiniKatranSrcV4)
	log.Printf("MiniKatranSrcV4 : %v", lb.MiniKatranConfig.MiniKatranSrcV6)
	Iphelper := iphelper.IPHelpers{}
	if len(lb.MiniKatranConfig.MiniKatranSrcV4) != 0 {

		src4, _ := Iphelper.ParseAddrToBe(lb.MiniKatranConfig.MiniKatranSrcV4, true)
		key := kSrcV4Pos

		log.Printf("src4 is %v", src4);
		res := lb.MiniBpfAdapter.BpfUpdateMap(lb.MiniBpfAdapter.GetMapByName(pckt_srcs), key, src4, 0)
		if res < 0 {
			log.Printf("can not update src v4 address for GUE packet")
			return false
		} else {
			log.Printf("update src v4 address %v for GUE packet", lb.MiniKatranConfig.MiniKatranSrcV4)
		}
	} else {
		log.Printf("Empty IPV4 address provided to use as source in GUE encap")
	}

	if len(lb.MiniKatranConfig.MiniKatranSrcV6) != 0 {
		
		src6, _ := Iphelper.ParseAddrToBe(lb.MiniKatranConfig.MiniKatranSrcV6, true)
		key := kSrcV6Pos

		log.Printf("src6 is %v", src6);
		res := lb.MiniBpfAdapter.BpfUpdateMap(lb.MiniBpfAdapter.GetMapByName(pckt_srcs), key, src6, 0)
		if res < 0 {
			log.Printf("can not update src v6 address for GUE packet")
			return false
		} else {
			log.Printf("update src v6 address %v for GUE packet", lb.MiniKatranConfig.MiniKatranSrcV6)
		}
	} else {
		log.Printf("Empty IPV6 address provided to use as source in GUE encap")
	}
	return true
}

func (lb *MiniLb) enableRecirculation() bool {
	key := kRecirculationIndex
	balancer_fd := lb.MiniBpfAdapter.GetProgFdByName()

	res := lb.MiniBpfAdapter.BpfUpdateMap(lb.MiniBpfAdapter.GetMapByName("subprograms"), key, uint32(balancer_fd), 0)

	if res < 0 {
		log.Printf("can not update subprograms for recirculation")
		return false
	}
	return true
}

func (lb *MiniLb) attachGlobalLru(core int) bool {
	log.Printf("attachGlobalLru ")
	key := core
	map_fd := lb.globalLruMapsFd_[core]

	if map_fd < 0 {
		log.Printf("Invalid FD found for core: %v map fd: %v", core, map_fd)
		return false
	}
	log.Printf("x")
	if res := lb.MiniBpfAdapter.BpfUpdateMap(lb.MiniBpfAdapter.GetMapByName(global_lru_maps), key, map_fd, 0); res < 0 {
		log.Printf("can't attach global lru to forwarding core %v", core)
		return false
	}
	log.Printf("Set cpu core %v global_lru map id to %v", core, map_fd)
	return true
}

func (lb *MiniLb) attachLrus() bool {
	if !lb.ProgsLoaded_ {
		log.Printf("can't attach lru when bpf progs are not loaded")
		return false
	}

	map_fd, res, key := 0, 0, 0

	for _, core := range lb.ForwardingCores_ {
		key = int(core)
		map_fd = lb.LruMapsFd_[core]

		if res = lb.MiniBpfAdapter.BpfUpdateMap(lb.MiniBpfAdapter.GetMapByName(lru_mapping), key, map_fd, 0); res < 0 {
			log.Printf("can't attach lru to forwarding core! ")
			return false
		}
		
		//缺少flow debug

		if ok := lb.attachGlobalLru(int(core)); !ok {
			return false
		}
	}

	lb.GlobalLruFallbackFd_ = lb.MiniBpfAdapter.GetMapByName(fallback_glru).FD()
	
	if lb.GlobalLruFallbackFd_ < 0 {
		log.Printf("can't find fallback_glru map' fd! ")
		return false
	}
	return true
}


func (lb *MiniLb) LoadBpfProgs() bool {
	//缺少检查flow流与健康检查

	if ok := lb.initLrus(); !ok {
		log.Print("init lrus failed")
		return false
	}

	if ok := lb.initGlobalLruProtoTypeMap(); !ok {
		log.Print("init global lru proto type map failed")
		return false
	}

	if res := lb.MiniBpfAdapter.LoadBpfProg(lb.MiniKatranConfig.BalancerProgPath); res != 0 {
		log.Print("load balancer prog failed")
		return false
	}

	//缺少hc健康检查

	if ok := lb.initialSanityChecking(); !ok {
		log.Print("initial sanity checking failed")
		return false
	}

	lb.featureDiscovering()

	if lb.MinikatranFeatrues.GueEncapd {
		lb.setUpGueEnvironment()
	}

	if lb.MinikatranFeatrues.InlineDecap {
		lb.enableRecirculation()
	}

	balancer_ctl_keys := []uint32{uint32(kMacAddrPos)}

	for _, ctl_key := range balancer_ctl_keys {

		if res := lb.MiniBpfAdapter.BpfUpdateMap(lb.MiniBpfAdapter.GetMapByName(ctl_array), ctl_key, lb.CtlValues_mac[ctl_key], 0); res != 0 {
			log.Printf("can't update ctl array for main program")
			return false
		}
	}

	//缺少hc健康检查

	lb.ProgsLoaded_ = true

	//缺少监控

	if ok := lb.attachLrus(); !ok {
		return false
	}

	var vip_def Structs.Vip_definition
	key := 0

	if res := lb.MiniBpfAdapter.BpfUpdateMap(lb.MiniBpfAdapter.GetMapByName(vip_miss_stats), uint32(key), vip_def, 0); res != 0 {
		log.Printf("can't update lru miss stat vip")
		return false
	}

	return true
}

func (lb *MiniLb) AttachBpfProgs(prog string) bool {
	if !lb.ProgsLoaded_ {
		log.Printf("failed to attach bpf prog: prog not loaded")
		return false
	}
	ifindex, err := net.InterfaceByName(lb.MiniKatranConfig.MainInterface)
	if err != nil {
		log.Printf("can not find interface %s", lb.MiniKatranConfig.MainInterface)
		return false
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Program: lb.MiniBpfAdapter.Loader.BpfObj[prog].Programs["balancer_prog"],
		Interface: ifindex.Index,
	}) 
	
	if err != nil {
		log.Printf("failed to attach bpf prog: %v", err.Error())
		return false
	}

	lb.Balancer_link = &link
	//缺少健康检查
	log.Printf("attach xdp program to interface %v", lb.MiniKatranConfig.MainInterface)
	return true
}

func (lb *MiniLb) HasFeature(feature int) bool {
	log.Printf("has feature %v", feature);
	switch feature {
	case Structs.LocalDeliveryOptimization:
		return lb.MinikatranFeatrues.LocalDeliveryOptimization
	case Structs.GueEncapd:
		return lb.MinikatranFeatrues.GueEncapd
	case Structs.InlineDecap:
		return lb.MinikatranFeatrues.InlineDecap
	case Structs.SrcRouting:
		return lb.MinikatranFeatrues.SrcRouting
	}
	return true
}

func (lb *MiniLb) GetMiniKatranProgFd() int {
	return lb.MiniBpfAdapter.GetMiniKatranProgFd(MiniBalancerProgName)
}

func (lb *MiniLb) ModifyQuicRealsMapping(action int, reals *[]Structs.QuicReal) bool {
	to_update := make(map[uint32]uint32)
	for _, real := range *reals {
		if lb.validateAddress(real.Address, false) == INVALID {
			log.Printf("Invalid quic real's address: %v", real.Address)
			continue
		}

		if(!lb.MiniKatranConfig.EnableCidV3 && (real.Id > kMaxQuicIdV2)) {
			log.Printf("trying to add mapping for id out of assigned space")
			continue
		}

		log.Printf("modifying quic's real %v . action: %v", real, action)

		real_, ok := lb.QuciMapping_[real.Id]
		if(action == Structs.DEL) {
			if !ok {
				log.Printf("trying to delete nonexisting mapping for id %v address %v", real.Id, real.Address)
				continue
			}
			if real_ != real.Address {
				log.Printf("deleted id %v pointed to diffrent address %v than given %v", real.Id, real_, real.Address)
				continue
			}

			lb.decreaseRefCountForReal(real.Address)
			delete(lb.QuciMapping_, real.Id)
		} else {
			if ok {
				if real_ == real.Address {
					continue
				}
				log.Printf("overriding address %v for existing mapping id %v address %v", real_, real.Id, real.Address)
				lb.decreaseRefCountForReal(real_)
			}
			rnum := lb.increaseRefCountForReal(real.Address, 0)
			if rnum == lb.MiniKatranConfig.MaxReals {
				log.Printf("exhausted real's space")
				continue
			}
			to_update[real.Id] = rnum
			lb.QuciMapping_[real.Id] = real.Address
		}	
	}

	if(!lb.MiniKatranConfig.Testing) {
		server_id_map := lb.MiniBpfAdapter.GetMapByName(server_id_map)
		res := 0
		for id, rnum := range to_update {
			log.Printf("id: %v rnum: %v", id, rnum)
			res = lb.MiniBpfAdapter.BpfUpdateMap(server_id_map, id, rnum, 0)
			if res != 0 {
				log.Printf("can't update quic mapping! ")
				lb.MiniKatranLbStats.BpfFailedCalls++
				return false
			}
		}
	}
	return true
}

func (lb *MiniLb) GetQuicRealsMapping() []Structs.QuicReal {
	reals := []Structs.QuicReal{}
	var real Structs.QuicReal
	for id, address := range lb.QuciMapping_ {
		real.Id = id
		real.Address = address
		reals = append(reals, real)
	}
	return reals
}
