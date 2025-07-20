package structs


const (
	KBalancerProgName = "balancer_prog"
	KBalancerProgPath = "/home/cainiao/bpftrace-exporter/MiniKatran/build/balancer.bpf.o"
)

const (
	KDefaultChRingSize = 65537
)

//后端节点的描述
type Endpoint struct {
	Num uint32
	Weight uint32
	Hash uint64
} 

type RealPos struct {
	Real  uint32
	Pos   uint32
}

const (
	ADD = iota
	DEL
)

type UpdateReal struct {
	Op int
	UpdateReal Endpoint //需要更新的后端节点
}

type NewReal struct{
  	Address string
  	Weight  uint32
  	Flags   uint8
};

type VipRealMeta struct { 
	Weight uint32
	Hash   uint64
}

type RealMeta struct {
	Num    		uint32
    RefCount 	uint32
  	Flags       uint8
}

type Lb_stats struct {
  	V1 uint64
  	V2 uint64
};

type Lb_tpr_packets_stats struct {
	Ch_routed 				uint64
	Dst_missmatch_in_lru 	uint64
	Sid_routed 				uint64
	Tcp_syn                 uint64
}

type Lb_stable_rt_packets_stats struct {
	Ch_routed               	uint64
	Cid_routed              	uint64
	Cid_invalid_server_id		uint64
	Cid_unknown_real_dropped 	uint64
	Invalid_packet_type         uint64
}

type QuicReal struct{
  	Address 	string
  	Id 			uint32
};

const (
	KDefaultPriority uint32 = 2307
	kDefaultKatranPos uint32 = 2; //共存prog下的位置
	kDefaultMaxVips uint32 = 512; //最大支持的vip数量
	kDefaultMaxReals uint32 = 4096;	//最大支持的backend数量
	kLbDefaultChRingSize uint32 = 65537; //默认的hash环大小
	kDefaultMaxLpmSrcSize uint32 = 3000000; //最大支持的lpm源ip数量
	kDefaultMaxDecapDstSize uint32 = 6; //最大支持的decap目的ip数量
	kDefaultNumOfPages uint32 = 2; //默认的bpf map page数量
	//kDefaultMonitorQueueSize uint32 = 4096; //默认的monitor队列大小
	//kDefaultMonitorPcktLimit uint32 = 0;  //默认的monitor队列大小
	//kDefaultMonitorSnapLen uint32 = 128; //默认的monitor队列大小
	kDefaultLruSize uint32 = 8000000; //默认的lru大小
	kDefaultGlobalLruSize uint32 = 100000; //默认的全局lru大小
	kNoFlags uint32 = 0; //默认的flag
	kUnspecifiedInterfaceIndex uint32 = 0; //默认的interface index
	kNoExternalMap string = "" //默认的external map
	kDefaultHcInterface string = "" //默认的hc interface
	kAddressNotSpecified string = "" //默认的address
)

type MiniKatranMonitorConfig struct {
	//NCpus uint32
	//Pages []uint32
	//Mapfd int
	//QueueSize []uint32
	//PcktLimit []uint32
	//SnapLen []uint32
	//events set[uint32]
	//Path string
	//Storage uint32
	//BufferSize uint32
}


type MiniKatranConfig struct{
  	MainInterface string
	V4TunInterface string
  	V6TunInterface string 
  	BalancerProgPath string
  	//healthcheckingProgPath string
  	DefaultMac []uint8
  	Priority uint32
  	//rootMapPath string
  	//rootMapPos uint32
  	//enableHc bool
  	//tunnelBasedHCEncap bool
  	MaxVips uint32
  	MaxReals uint32
  	ChRingSize uint32
  	Testing bool
  	LruSize uint64
  	ForwardingCores []uint32
  	NumaNodes []uint32
  	MaxLpmSrcSize uint32
  	MaxDecapDst uint32
  	//hcInterface string
  	XdpAttachFlags uint32
  	//KatranMonitorConfig MiniKatranMonitorConfig
  	//memlockUnlimited bool
  	MiniKatranSrcV4 string
  	MiniKatranSrcV6 string
  	LocalMac []uint8
  	MaglevOp int 
  	//flowDebug bool
  	GlobalLruSize uint32
  	//useRootMap bool
  	//enableCidV3 bool
  	MainInterfaceIndex uint32
  	//hcInterfaceIndex uint32
  	//cleanupOnShutdown bool
	EnableCidV3 bool
};


type MiniKatranFeatures struct {
	SrcRouting bool
  	InlineDecap bool
  	//Introspection bool
	GueEncapd bool
	//DirectHealthchecking bool
	LocalDeliveryOptimization bool
	//FlowDebug bool
};

const (
	SrcRouting = 1
	InlineDecap = 2
	//Introspection = 1 << 2,
	GueEncapd = 3
	//DirectHealthchecking = 4
	LocalDeliveryOptimization = 4
	//FlowDebug = 1 << 6
)

type VipKey struct {
	Address 	string
	Port 		uint16
  	Proto 		uint8
}

/* c.
struct vip_meta {
    __u32 flags;
    __u32 vip_num; //虚拟ip所对应的服务器序号
};
*/

type Vipmeta struct{
  	Flags 		uint32
	Vip_num 	uint32
};

/* c. 24字节
struct vip_definition {
    __be32 vip;
    __be32 vip6[4];
    __u16 port;
    __u8 proto;
};
*/

//24个字节
type Vip_definition struct{
	Vip         uint32
	Vip6 		[4]uint32
  	Port 		uint16
  	Proto 		uint8
	Padding     [1]byte
};


/*
struct address
{
    __be32 addr;
    __be32 addrv6[4];
};
*/

type Address struct {
	Addr     uint32
	Addrv6   [4]uint32
}

type IpNet struct {
	Ip     	string
	Mask   	int
}

/*
struct lpm_key4 {
    __u32 prefixlen;
    __be32 addr;
};
*/

type Lpm_key_v4 struct {
	Prefixlen uint32
	Addr      uint32
}

/*
struct lpm_key6 {
    __u32 prefixlen;
    __be32 addr[4];
};
*/

type Lpm_key_v6 struct {
	Prefixlen uint32
	Addr      [16]uint8
}

/* c.
struct ctl_value {
    //__u64 value;
    //__u32 ifindex;
    __u8 mac[6];
};
*/
type Ctl_value_mac struct {
    //Value		uint32
    //Ifindex 	uint32
   	Mac 		[6]uint8
};

type Ctl_value_ifindex struct {
	Ifindex     uint32
}

type MiniKatranLbStats struct {
  BpfFailedCalls 			uint64
  AddrValidationFailed 		uint64
};

/*
struct flow_key {
    __be32 src;
     __be32 srcv6[4];

    __be32 dst;
    __be32 dstv6[4];

    __u32 ports;
    __u32 port16[2];

    __u8 proto;
};
*/

type FlowKey struct {
    Src   		uint32
    Srcv6 		[4]uint32
	Dst   		uint32
	Dstv6       [4]uint32

    Port 		uint32
    Ports 		[2]uint16
	Proto       uint8
    pad  		[3]byte
}

type RealPosLRU struct {
    Pos   uint32
    Atime uint64
	_     [4]byte
}


func Get_ready_config(config *MiniKatranConfig) {
	//config.V4TunInterface = kDefaultHcInterface
	//config.V6TunInterface = kDefaultHcInterface
	config.Priority = KDefaultPriority
	config.MaxVips = kDefaultMaxVips
	config.MaxReals = kDefaultMaxReals
	config.ChRingSize = kLbDefaultChRingSize
	config.LruSize = uint64(kDefaultLruSize)
	config.MaxLpmSrcSize = kDefaultMaxLpmSrcSize
	config.MaxDecapDst = kDefaultMaxDecapDstSize
	config.XdpAttachFlags = kNoFlags
	config.MiniKatranSrcV4 = kAddressNotSpecified
	config.MiniKatranSrcV6 = kAddressNotSpecified
	config.MaglevOp = 2
	config.GlobalLruSize = kDefaultGlobalLruSize
	config.MainInterfaceIndex = kUnspecifiedInterfaceIndex
	config.EnableCidV3 = false
}