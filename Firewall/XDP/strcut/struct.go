package XDP
import(
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

var (
	Obj *ebpf.Collection
)

var (
	AttachedLinks map[int]link.Link
	Iface2Index map[string]int

	Pre_Xdp_Config Xdp_Config

	Now_Xdp_Config Xdp_Config
)

var(
	InterfaceRuleDel 		map[string]int  
	InterfaceRuleTotalOld 	map[string]int

	InterfaceLimitDel       map[string]int    
	InterfaceLimitTotalOld  map[string]int	
)

type MapOperation struct {
	Action   			int    				
	MapType  			string 			
	IfName   			string 		
	RuleType 			string 			
	IPType   			string 			
	IP       			string 			
	FromPort            uint16
	ToPort              uint16
	FromPortLists   	[]uint16 		
	ToPortList 			[]uint16		
	FullMode   		    bool 				
	IsCidr     		    bool   
}

type LimitOperation struct {
	Action              int								
	IfName              string              			
	MapType  			string               		
	Proto               string 							
	TRB                 map[string][]int64 			
}


type Xdp_Config struct {
	Interfaces map[string]Interface 		`yaml:"Interfaces"`
}

type Interface struct {
	Rules map[string]Rule 					`yaml:"Rules"` 
	Limit map[string]TokenBucket 			`yaml:"Limit"`
}

type Rule struct {
	Ip4s map[string][]uint16 				`yaml:"ip4s"`
	Ip6s map[string][]uint16 				`yaml:"ip6s"`
}

type TokenBucket struct {
	Burst    int64    						`yaml:"Burst"`
	Rate     int64    						`yaml:"Rate"`
	Tokens   int64    						`yaml:"Tokens"`
}

/*
struct Package_Count {
    u64 Allowed;
    u64 Passed;
    struct Package_Dropped Dropped;
};
*/
type Package_Count struct {
	Allowed         uint64
    Passed          uint64
    Dropped         Package_Dropped 
}

/*
struct Package_Dropped {
    u64 Active_Dropped; //根据规则丢弃的数据包数
    u64 Passive_Dropped; //数据包有错误的数据包数 ？？？？
};
*/
type Package_Dropped struct {
    Active_Dropped      uint64
    Passive_Dropped     uint64
}

var (
	MAX_IFACES_IPS     int64 = 1000
	MAX_IFACES_PORTS   int64 = 1000
	MAX_IFACES         int32 = 10 
)

type IPv6Key [16]byte // 16字节（128位）IPv6地址键

//可以继续加规则
var (
	Map_Package_Count      				= "Package_Count"
	Map_Rule         					= "Rule"
	Map_Rule6        					= "Rule6"
	Map_RingBuf 		   				= "map_RingBuf"
	Map_Lpm_Rule           				= "Lpm_Rule4"
	Map_Lpm_Rule6          				= "Lpm_Rule6"
	
	Map_Token_Bucket_global       		= "TB_global"
	Map_Tb_Burst_Rate_global		   	= "Tb_BR_global"

	Map_Tb_Rate_Burst_Pre_Ip			= "Tb_RB_Pre_Ip"
	Map_Tb_Rate_Burst_Pre_Ip6			= "Tb_RB_Pre_Ip6"
	Map_Token_Bucket_Ip					= "TB_Ip"
	Map_Token_Bucket_Ip6				= "TB_Ip6"
)

var (
	XDP_PROGRAM_NAME string = "xdp_main"
)

//go会自动补充padding，满足字段对齐要求
type Debug_Log struct {
    Ip       uint32    `struc:"uint32"`  // IPv4地址 0 1 2 3 
    Ip6      [16]byte  `struc:"[16]byte"`// IPv6地址 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19
    Port     uint16    `struc:"uint16"`  // 端口 20 21
    Protocol uint8     `struc:"uint8"`   // 协议类型 22
    Mode     uint8     `struc:"uint8"`   // 模式 23
    Version  uint8     `struc:"uint8"`   // IP版本 24
	Pad      [3]byte    // 手动补齐到 28 字节
}

var Protocol_Map = map[uint8]string{
	6:   "TCP",
	17:  "UDP",
	1:   "ICMP",
	58:  "ICMPv6",
}

var Mode_Map = map[uint8]string {
	1: "Black", //XDP_DROP
	2: "White", //XDP_PASS
}

var (
	XDP_DROP = 1
	XDP_PASS = 2
)

/*
struct Ip_ifindex {
    u32 ip; 
    u32 ifindex;
};
*/
type IpIfindex struct {
	Ip 			 uint32
	Ifindex      uint32
}

/*
struct Ip6_ifindex {
    u32 ifindex;
    u8 ip[16];
};
*/
type Ip6Ifindex struct {
	Ifindex      uint32
    IP           [16]byte
}

/*
struct Lpm_trie_key4 {
    u32 prefixlen;
    u64 data;
};
*/
type Lpm_key4 struct {
	Prefixlen    uint32
	Ip           uint32
}

/*
struct Lpm_trie_key6 {
    u32 prefixlen; //四字节
    u8 data[20];
};
*/

//和c形式字节对齐
type Lpm_key6 struct {
	Prefixlen     uint32    //四个字节
	Ip            [16]byte //八个字节
}

/*
struct token_bucket {
    u64 last_update_time; //ns
    u64 tokens;
};
*/
//Token_Bucket
type Token_Bucket_Value struct {
    Last_update_time 	uint64; //ns
    Tokens				uint64;
}

/*
struct token_bucket_key {
    u32 ifindex;
    u8 category;
};
*/
//Go 语言要求整个结构体的大小必须是其最大字段类型大小的整数倍
type Token_Bucket_key struct {
	Ifindex      uint32
	Category     uint8
	_            [3]byte // 填充：确保总大小为8字节
}

/*
struct tokens_rate_burst_key {
    u32 ifindex;
    u32 ip;
    u8 ip6[16];
};
*/
type Tokens_Rate_Burst_Key struct {
	Ifindex      uint32
	Ip4          uint32
	Ip6          [16]byte
}

/*
struct rate_burst {
    u64 rate;
    u64 burst;
};
*/
type Tokens_Rate_Burst_value struct {
	Rate          uint64
	Burst         uint64
}

var (
	Global_index = 0
	Tcp_index = 1
	Udp_index = 2
)

var (
	OPT_ACTION_ADD = 0
	OPT_ACTION_DEL = 1
	OPT_ACTION_UPD = 2
)