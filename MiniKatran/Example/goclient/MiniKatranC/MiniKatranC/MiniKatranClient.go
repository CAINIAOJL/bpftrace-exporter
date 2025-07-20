package goclient

import (
	"context"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"
	"fmt"
	lb_MiniKatran "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/Example/goclient/MiniKatranC/lb_MiniKatran"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const(
	ADD_VIP = iota //添加vip
	DEL_VIP        //删除vip
	MODIFY_VIP     //修改vip
)

const(
	IPPROTO_TCP = 6
	IPPROTO_UDP = 17
	NO_SPORT    = 1
	NO_LRU      = 2
	QUIC_VIP    = 4
	DPORT_HASH  = 8
	LOCAL_VIP   = 32

	LOCAL_REAL = 2
)

var (
	vipFlagTranslationTable = map[string]int64{
		"NO_SPORT":   NO_SPORT,
		"NO_LRU":     NO_LRU,
		"QUIC_VIP":   QUIC_VIP,
		"DPORT_HASH": DPORT_HASH,
		"LOCAL_VIP":  LOCAL_VIP,
	}
	realFlagTranslationTable = map[string]int32{
		"LOCAL_REAL": LOCAL_REAL,
	}
)

func checkError(err error) {
	if err != nil {
		log.Fatalf("Error: %v\n", err)
	}
}

type MiniKatranClient struct {
	client lb_MiniKatran.MiniKatranServiceClient //服务的客户端
}

func (Mc *MiniKatranClient) Init_client(serverAddr string) {
	var opts []grpc.DialOption
	//源码修改更新
	opts = append(opts, grpc.WithTransportCredentials((insecure.NewCredentials())))
	conn, err := grpc.NewClient(serverAddr, opts...)
	if err != nil {
		log.Fatalf("can not connect to local czkatran server! err is %v\n", err)
	}
	
	Mc.client = lb_MiniKatran.NewMiniKatranServiceClient(conn)
}

func (Mc *MiniKatranClient) ChangeMac(mac string) {
	newmac := lb_MiniKatran.Mac{
		Mac: mac,
	}

	res, err := Mc.client.ChangeMac(context.Background(), &newmac)
	checkError(err)
	if res.Success == true {
		log.Print("Mac address changed success !")
	} else {
		log.Print("Mac address changed failed !")
	}
}

func (Mc *MiniKatranClient) GetMac() {
	mac, err := Mc.client.GetMac(context.Background(), &lb_MiniKatran.Empty{})
	checkError(err)
	log.Printf("Mac address is %v\n", mac.GetMac())
}

func parseToVip(addr string, proto int) lb_MiniKatran.Vip {
		var vip lb_MiniKatran.Vip
	vip.Protocol = int32(proto)
	if strings.Index(addr, "[") >= 0 {
		// v6 address. format [<addr>]:<port>
		v6re := regexp.MustCompile(`\[(.*?)\]:(.*)`)
		addr_port := v6re.FindStringSubmatch(addr)
		if addr_port == nil {
			log.Fatalf("invalid v6 address %v\n", addr)
		}
		vip.Address = addr_port[1]
		port, err := strconv.ParseInt(addr_port[2], 10, 32)
		vip.Port = int32(port)
		checkError(err)
	} else {
		// v4 address. format <addr>:<port>
		addr_port := strings.Split(addr, ":")
		if len(addr_port) != 2 {
			log.Fatalf("incorrect v4 address: %v\n", addr)
		}
		vip.Address = addr_port[0]
		port, err := strconv.ParseInt(addr_port[1], 10, 32)
		vip.Port = int32(port)
		checkError(err)
	}
	return vip
}

func parseToReal(addr string, weight int64, flags int32) lb_MiniKatran.Real {
	var real lb_MiniKatran.Real
	real.Address = addr
	real.Weight = int32(weight)
	real.Flags = flags
	return real
}

func parseToQuicReal(mapping string) lb_MiniKatran.QuicReal {
	addr_id := strings.Split(mapping, "=")
	if len(addr_id) != 2 {
		panic("quic mapping must be in <addr>=<id> format")
	}
	id, err := strconv.ParseInt(addr_id[1], 10, 64)
	checkError(err)
	var qr lb_MiniKatran.QuicReal
	qr.Address = addr_id[0]
	qr.Id = int32(id)
	return qr
}

func (Mc *MiniKatranClient) UpdateService(
	vip lb_MiniKatran.Vip, flags int64, action int, setFlags bool) {
	var vMeta lb_MiniKatran.VipMeta
	var ok *lb_MiniKatran.Bool
	var err error
	vMeta.Vip = &vip
	vMeta.Flags = flags
	vMeta.SetFlag = setFlags
	switch action {
	case MODIFY_VIP:
		ok, err = Mc.client.ModifyVip(context.Background(), &vMeta)
		break
	case ADD_VIP:
		ok, err = Mc.client.AddVip(context.Background(), &vMeta)
		break
	case DEL_VIP:
		ok, err = Mc.client.DelVip(context.Background(), &vip)
		break
	default:
		break
	}
	checkError(err)
	if ok.Success {
		log.Printf("Vip modified\n")
	}
}

func (Mc *MiniKatranClient) AddOrModifyService(addr string, flagsString string, proto int, modify bool, setFlags bool) {
	log.Printf("Adding service: %v %v\n", addr, proto)
	vip := parseToVip(addr, proto)
	var flags int64
	var exists bool
	if flagsString != "" {
		if flags, exists = vipFlagTranslationTable[flagsString]; !exists {
			log.Printf("unrecognized flag: %v\n", flagsString)
			return
		}
	}
	if modify {
		Mc.UpdateService(vip, flags, MODIFY_VIP, setFlags)
	} else {
		Mc.UpdateService(vip, flags, ADD_VIP, setFlags)
	}
}

func (Mc *MiniKatranClient) DelService(addr string, proto int) {
	log.Printf("Deleting service: %v %v\n", addr, proto)
	vip := parseToVip(addr, proto)
	Mc.UpdateService(vip, 0, DEL_VIP, false)
}

func (Mc *MiniKatranClient) ModifyRealsForVip(
	vip *lb_MiniKatran.Vip, reals *lb_MiniKatran.Reals, action lb_MiniKatran.Action) {
	var mReals lb_MiniKatran.ModifiedRealsForVip
	mReals.Vip = vip
	mReals.Real = reals
	mReals.Action = action
	ok, err := Mc.client.ModifyRealsForVip(context.Background(), &mReals)
	checkError(err)
	if ok.Success {
		log.Printf("Reals modified\n")
	}
}

func (Mc *MiniKatranClient) UpdateServerForVip(
	vipAddr string, proto int, realAddr string, weight int64, realFlags string, delete bool) {
	vip := parseToVip(vipAddr, proto)
	var flags int32
	var exists bool
	if realFlags != "" {
		if flags, exists = realFlagTranslationTable[realFlags]; !exists {
			log.Printf("unrecognized flag: %v\n", realFlags)
			return
		}
	}
	real := parseToReal(realAddr, weight, flags)
	var action lb_MiniKatran.Action
	if delete {
		action = lb_MiniKatran.Action_DEL
	} else {
		action = lb_MiniKatran.Action_ADD
	}
	var reals lb_MiniKatran.Reals
	reals.Reals = append(reals.Reals, &real)
	Mc.ModifyRealsForVip(&vip, &reals, action)
}

func (Mc *MiniKatranClient) ModifyQuicMappings(mapping string, delete bool) {
	var action lb_MiniKatran.Action
	if delete {
		action = lb_MiniKatran.Action_DEL
	} else {
		action = lb_MiniKatran.Action_ADD
	}
	qr := parseToQuicReal(mapping)
	var qrs lb_MiniKatran.QuicReals
	qrs.Qreals = append(qrs.Qreals, &qr)
	var mqr lb_MiniKatran.ModifiedQuicReals
	mqr.Reals = &qrs
	mqr.Action = action
	ok, err := Mc.client.ModifyQuicRealsMapping(
		context.Background(), &mqr)
	checkError(err)
	if ok.Success {
		log.Printf("Quic mapping modified\n")
	}
}

func (Mc *MiniKatranClient) GetAllVips() lb_MiniKatran.Vips {
	vips, err := Mc.client.GetAllVips(context.Background(), &lb_MiniKatran.Empty{})
	checkError(err)
	return *vips
}

/*func (Mc *MiniKatranClient) GetAllHcs() lb_MiniKatran.HcMap {
	hcs, err := kc.client.GetHealthcheckersDst(
		context.Background(), &lb_MiniKatran.Empty{})
	checkError(err)
	return *hcs
}*/

func (Mc *MiniKatranClient) GetRealsForVip(vip *lb_MiniKatran.Vip) lb_MiniKatran.Reals {
	reals, err := Mc.client.GetRealsForVip(context.Background(), vip)
	checkError(err)
	return *reals
}

func (Mc *MiniKatranClient) GetVipFlags(vip *lb_MiniKatran.Vip) uint64 {
	flags, err := Mc.client.GetVipFlags(context.Background(), vip)
	checkError(err)
	return flags.Flags
}

func parseVipFlags(flags uint64) string {
	flags_str := ""
	if flags&uint64(NO_SPORT) > 0 {
		flags_str += " NO_SPORT "
	}
	if flags&uint64(NO_LRU) > 0 {
		flags_str += " NO_LRU "
	}
	if flags&uint64(QUIC_VIP) > 0 {
		flags_str += " QUIC_VIP "
	}
	if flags&uint64(DPORT_HASH) > 0 {
		flags_str += " DPORT_HASH "
	}
	if flags&uint64(LOCAL_VIP) > 0 {
		flags_str += " LOCAL_VIP "
	}
	return flags_str
}

func parseRealFlags(flags int32) string {
	if flags < 0 {
		log.Fatalf("invalid real flags passed: %v\n", flags)
	}
	flags_str := ""
	if flags&LOCAL_REAL > 0 {
		flags_str += " LOCAL_REAL "
	}
	return flags_str
}

func (Mc *MiniKatranClient) ListVipAndReals(vip *lb_MiniKatran.Vip) {
	reals := Mc.GetRealsForVip(vip)
	proto := ""
	if vip.Protocol == IPPROTO_TCP {
		proto = "tcp"
	} else {
		proto = "udp"
	}
	fmt.Printf("VIP: %20v Port: %6v Protocol: %v\n",
		vip.Address,
		vip.Port,
		proto)
	flags := Mc.GetVipFlags(vip)
	fmt.Printf("Vip's flags: %v\n", parseVipFlags(flags))
	for _, real := range reals.Reals {
		fmt.Printf("%-20v weight: %v flags: %v\n",
			" ->"+real.Address,
			real.Weight, parseRealFlags(real.Flags))
	}
}

func (Mc *MiniKatranClient) List(addr string, proto int) {
	vips := Mc.GetAllVips()
	log.Printf("vips len %v", len(vips.Vips))
	for _, vip := range vips.Vips {
		Mc.ListVipAndReals(vip)
	}
}

func (Mc *MiniKatranClient) ClearAll() {
	fmt.Println("Deleting Vips")
	vips := Mc.GetAllVips()
	for _, vip := range vips.Vips {
		ok, err := Mc.client.DelVip(context.Background(), vip)
		if err != nil || !ok.Success {
			fmt.Printf("error while deleting vip: %v", vip.Address)
		}
	}
	/*fmt.Println("Deleting Healthchecks")
	hcs := Mc.GetAllHcs()
	var Somark lb_MiniKatran.Somark
	for somark := range hcs.Healthchecks {
		Somark.Somark = uint32(somark)
		ok, err := Mc.client.DelHealthcheckerDst(context.Background(), &Somark)
		if err != nil || !ok.Success {
			fmt.Printf("error while deleting hc w/ somark: %v", somark)
		}
	}*/
}

func (Mc *MiniKatranClient) ListQm() {
	fmt.Printf("printing address to quic's connection id mapping\n")
	qreals, err := Mc.client.GetQuicRealsMapping(
		context.Background(), &lb_MiniKatran.Empty{})
	checkError(err)
	for _, qr := range qreals.Qreals {
		fmt.Printf("real: %20v = connection id: %6v\n",
			qr.Address,
			qr.Id)
	}
}

/*func (Mc *MiniKatranClient) AddHc(addr string, somark uint64) {
	var hc lb_MiniKatran.Healthcheck
	hc.Somark = uint32(somark)
	hc.Address = addr
	ok, err := Mc.client.AddHealthcheckerDst(context.Background(), &hc)
	checkError(err)
	if !ok.Success {
		fmt.Printf("error while add hc w/ somark: %v and addr %v", somark, addr)
	}
}

func (Mc *MiniKatranClient) DelHc(somark uint64) {
	var sm lb_MiniKatran.Somark
	sm.Somark = uint32(somark)
	ok, err := Mc.client.DelHealthcheckerDst(context.Background(), &sm)
	checkError(err)
	if !ok.Success {
		fmt.Printf("error while deleting hc w/ somark: %v", somark)
	}
}

func (Mc *MiniKatranClient) ListHc() {
	hcs := Mc.GetAllHcs()
	for somark, addr := range hcs.Healthchecks {
		fmt.Printf("somark: %10v addr: %10v\n",
			somark,
			addr)
	}
}*/

func (Mc *MiniKatranClient) ShowSumStats() {
	oldPkts := uint64(0)
	oldBytes := uint64(0)
	vips := Mc.GetAllVips()
	for true {
		pkts := uint64(0)
		bytes := uint64(0)
		for _, vip := range vips.Vips {
			stats, err := Mc.client.GetStatsForVip(context.Background(), vip)
			if err != nil {
				continue
			}
			pkts += stats.V1
			bytes += stats.V2
		}
		diffPkts := pkts - oldPkts
		diffBytes := bytes - oldBytes
		fmt.Printf("summary: %v pkts/sec %v bytes/sec\n", diffPkts, diffBytes)
		oldPkts = pkts
		oldBytes = bytes
		time.Sleep(1 * time.Second)
	}
}

func (Mc *MiniKatranClient) ShowLruStats() {
	oldTotalPkts := uint64(0)
	oldMiss := uint64(0)
	oldTcpMiss := uint64(0)
	oldTcpNonSynMiss := uint64(0)
	oldFallbackLru := uint64(0)
	for true {
		lruMiss := float64(0)
		tcpMiss := float64(0)
		tcpNonSynMiss := float64(0)
		udpMiss := float64(0)
		lruHit := float64(0)
		stats, err := Mc.client.GetLruStats(
			context.Background(), &lb_MiniKatran.Empty{})
		if err != nil {
			continue
		}
		missStats, err := Mc.client.GetLruMissStats(
			context.Background(), &lb_MiniKatran.Empty{})
		if err != nil {
			continue
		}
		fallbackStats, err := Mc.client.GetLruFallbackStats(
			context.Background(), &lb_MiniKatran.Empty{})
		if err != nil {
			continue
		}
		diffTotal := stats.V1 - oldTotalPkts
		diffMiss := stats.V2 - oldMiss
		diffTcpMiss := missStats.V1 - oldTcpMiss
		diffTcpNonSynMiss := missStats.V2 - oldTcpNonSynMiss
		diffFallbackLru := fallbackStats.V1 - oldFallbackLru
		if diffTotal != 0 {
			lruMiss = float64(diffMiss) / float64(diffTotal)
			tcpMiss = float64(diffTcpMiss) / float64(diffTotal)
			tcpNonSynMiss = float64(diffTcpNonSynMiss) / float64(diffTotal)
			udpMiss = 1 - (tcpMiss + tcpNonSynMiss)
			lruHit = 1 - lruMiss
		}
		fmt.Printf("summary: %d pkts/sec. lru hit: %.2f%% lru miss: %.2f%% ",
			diffTotal, lruHit*100, lruMiss*100)
		fmt.Printf("(tcp syn: %.2f%% tcp non-syn: %.2f%% udp: %.2f%%)", tcpMiss,
			tcpNonSynMiss, udpMiss)
		fmt.Printf(" fallback lru hit: %d pkts/sec\n", diffFallbackLru)
		oldTotalPkts = stats.V1
		oldMiss = stats.V2
		oldTcpMiss = missStats.V1
		oldTcpNonSynMiss = missStats.V2
		oldFallbackLru = fallbackStats.V1
		time.Sleep(1 * time.Second)
	}
}

func (Mc *MiniKatranClient) ShowPerVipStats() {
	vips := Mc.GetAllVips()
	statsMap := make(map[string]uint64)
	for _, vip := range vips.Vips {
		key := strings.Join([]string{
			vip.Address, strconv.Itoa(int(vip.Port)),
			strconv.Itoa(int(vip.Protocol))}, ":")
		statsMap[key+":pkts"] = 0
		statsMap[key+":bytes"] = 0
	}
	for true {
		for _, vip := range vips.Vips {
			key := strings.Join([]string{
				vip.Address, strconv.Itoa(int(vip.Port)),
				strconv.Itoa(int(vip.Protocol))}, ":")
			stats, err := Mc.client.GetStatsForVip(context.Background(), vip)
			if err != nil {
				continue
			}
			diffPkts := stats.V1 - statsMap[key+":pkts"]
			diffBytes := stats.V2 - statsMap[key+":bytes"]
			fmt.Printf("vip: %16s : %8d pkts/sec %8d bytes/sec\n",
				key, diffPkts, diffBytes)
			statsMap[key+":pkts"] = stats.V1
			statsMap[key+":bytes"] = stats.V2
		}
		time.Sleep(1 * time.Second)
	}
}

func (Mc *MiniKatranClient) ShowIcmpStats() {
	oldIcmpV4 := uint64(0)
	oldIcmpV6 := uint64(0)
	for true {
		icmps, err := Mc.client.GetIcmpTooBigStats(
			context.Background(), &lb_MiniKatran.Empty{})
		checkError(err)
		diffIcmpV4 := icmps.V1 - oldIcmpV4
		diffIcmpV6 := icmps.V2 - oldIcmpV6
		fmt.Printf(
			"ICMP \"packet too big\": v4 %v pkts/sec v6: %v pkts/sec\n",
			diffIcmpV4, diffIcmpV6)
		oldIcmpV4 = icmps.V1
		oldIcmpV6 = icmps.V2
		time.Sleep(1 * time.Second)
	}
}
