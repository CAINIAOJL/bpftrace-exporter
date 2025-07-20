package main

import(
	"flag"
	"fmt"
	MiniKatranClient "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/Example/goclient/MiniKatranC/MiniKatranC"

)

const (
	IPPROTO_TCP = 6
	IPPROTO_UDP = 17
)

var (
	addService  = flag.Bool("A", false, "Add new virtual service")
	editService = flag.Bool("E", false, "Edit existing virtual service")
	delService  = flag.Bool("D", false, "Delete existing virtual service")

	addServer   = flag.Bool("a", false, "Add real server")
	editServer  = flag.Bool("e", false, "Edit real server")
	delServer   = flag.Bool("d", false, "Delete real server")

	tcpService  = flag.String("t", "",
		"Tcp service address. must be in format: <addr>:<port>")
	udpService = flag.String("u", "",
		"Udp service addr. must be in format: <addr>:<port>")

	realServer     = flag.String("r", "", "Address of the real server")
	realWeight     = flag.Int64("w", 1, "Weight (capacity) of real server")

	showStats      = flag.Bool("s", false, "Show stats/counters")
	showSumStats   = flag.Bool("sum", false, "Show summary stats")
	showLruStats   = flag.Bool("lru", false, "Show LRU related stats")
	showIcmpStats  = flag.Bool("icmp", false, "Show ICMP 'packet too big' related stats")

	listServices   = flag.Bool("l", false, "List configured services")

	vipChangeFlags = flag.String("vf", "",
		"change vip flags. Possible values: NO_SPORT, NO_LRU, QUIC_VIP, DPORT_HASH, LOCAL_VIP")
	realChangeFlags = flag.String("rf", "",
		"change real flags. Possible values: LOCAL_REAL")
	unsetFlags = flag.Bool("unset", false, "Unset specified flags")

	//健康检查
	//newHc      = flag.String("new_hc", "", "Address of new backend to healtcheck")
	//somark     = flag.Uint64("somark", 0, "Socket mark to specified backend")
	//delHc      = flag.Bool("del_hc", false, "Delete backend w/ specified somark")
	//listHc     = flag.Bool("list_hc", false, "List configured healthchecks")

	listMac    = flag.Bool("list_mac", false,
		"List configured mac address of default router")
	changeMac = flag.String("change_mac", "",
		"Change configured mac address of default router")

	clearAll    = flag.Bool("C", false, "Clear all configs")

	//quic服务
	quicMapping = flag.String("quic_mapping", "",
		"mapping of real to connectionId. must be in <addr>=<id> format")
	listQuicMapping = flag.Bool("list_qm", false, "List current quic's mappings")
	delQuicMapping  = flag.Bool("del_qm", false,
		"Delete instead of adding specified quic mapping")

	//服务器地址
	MinikatranServer = flag.String("server", "127.0.0.1:50051",
		"Katran server listen address")
)

func main() {
	flag.Parse()
	var service string
	var proto int
	if *tcpService != "" {
		service = *tcpService
		proto = IPPROTO_TCP
	} else if *udpService != "" {
		service = *udpService
		proto = IPPROTO_UDP
	}
	var Mc MiniKatranClient.MiniKatranClient
	Mc.Init_client(*MinikatranServer)
	if *changeMac != "" {
		Mc.ChangeMac(*changeMac)
	} else if *listMac {
		Mc.GetMac()
	} else if *addService {
		Mc.AddOrModifyService(service, *vipChangeFlags, proto, false, true)
	} else if *listServices {
		// TODO(tehnerd): print only specified tcp/udp service
		Mc.List("", 0)
	} else if *delService {
		Mc.DelService(service, proto)
	} else if *editService {
		Mc.AddOrModifyService(service, *vipChangeFlags, proto, true, !*unsetFlags)
	} else if *addServer || *editServer {
		Mc.UpdateServerForVip(service, proto, *realServer, *realWeight, *realChangeFlags, false)
	} else if *delServer {
		Mc.UpdateServerForVip(service, proto, *realServer, *realWeight, *realChangeFlags, true)
	} else if *delQuicMapping {
		Mc.ModifyQuicMappings(*quicMapping, true)
	} else if *quicMapping != "" {
		Mc.ModifyQuicMappings(*quicMapping, false)
	} else if *listQuicMapping {
		Mc.ListQm()
	} else if *clearAll {
		Mc.ClearAll()
	} else if *showStats {
		if *showSumStats {
			Mc.ShowSumStats()
		} else if *showLruStats {
			Mc.ShowLruStats()
		} else if *showIcmpStats {
			Mc.ShowIcmpStats()
		} else {
			Mc.ShowPerVipStats()
		}
	} /*else if *newHc != "" {
		kc.AddHc(*newHc, *somark)
	} else if *delHc {
		kc.DelHc(*somark)
	} else if *listHc {
		kc.ListHc()*/
	/*}*/
	fmt.Printf("MiniKatranClient finished")
}
