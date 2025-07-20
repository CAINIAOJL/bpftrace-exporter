package main

import (
	"flag"
	"strconv"
	"strings"
	"log"
	"os"
	"net"
	"time"
	"context"
	"syscall"
	"os/signal"
	"google.golang.org/grpc"
	MacHelper "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/MacHelpers"
	pb "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/Example/goclient/MiniKatranC/lb_MiniKatran"
	MiniKatranGrpcService "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/Example/goclient/MiniKatranS/MiniKatranGrpcService"
	Structs "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/Structs"
)

var (
	server          	= flag.String("server", "0.0.0.0:50051", "Service server:port")
	intf            	= flag.String("intf", "ens33", "main interface")
	hcIntf          	= flag.String("hc_intf", "", "interface for healthchecking")
	ipipIntf        	= flag.String("ipip_intf", "ipip0", "ipip (v4) encap interface")
	ipip6Intf       	= flag.String("ipip6_intf", "ipip60", "ip(6)ip6 (v6) encap interface")
	balancerProg    	= flag.String("balancer_prog", "/home/cainiao/bpftrace-exporter/MiniKatran/build/balancer.bpf.o", "path to balancer bpf prog")
	healthcheckerProg 	= flag.String("healthchecker_prog", "", "path to healthchecking bpf prog")
	defaultMac      	= flag.String("default_mac", "00:50:56:f8:0b:40", "mac address of default router. must be in format: xx:xx:xx:xx:xx:xx")
	priority        	= flag.Int("priority", 2307, "tc's priority for bpf progs")
	mapPath         	= flag.String("map_path", "", "path to pinned map from root xdp prog. default path forces to work in standalone mode")
	progPos         	= flag.Int("prog_pos", 2, "katran's position inside root xdp array")
	hcForwarding    	= flag.Bool("hc_forwarding", true, "turn on forwarding path for healthchecks")
	shutdownDelay   	= flag.Int("shutdown_delay", 10000, "shutdown delay in milliseconds")
	lruSize         	= flag.Int64("lru_size", 8000000, "size of LRU table")
	forwardingCores 	= flag.String("forwarding_cores", "", "comma separated list of forwarding cores")
	numaNodes       	= flag.String("numa_nodes", "", "comma separated list of numa nodes to forwarding cores mapping")
)

func ParseCoreOrNumaLine(line string) []uint32 {
	nums := []uint32{}
	if len(line) != 0 {
		splitedLine := strings.Split(line, ",")
		for _, num := range splitedLine {
			code, err := strconv.Atoi(num)
			if err != nil {
				log.Fatalf("Can't parse %s to int", num)
			}
			nums = append(nums, uint32(code))
		}
	}
	return nums
}

func RunServer(config *Structs.MiniKatranConfig, delay int) {
	server_address := *server
	rpcService := MiniKatranGrpcService.NewKatranGrpcService(config)

	server := grpc.NewServer()
	pb.RegisterMiniKatranServiceServer(server, rpcService)

	lis, err := net.Listen("tcp", server_address)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", server_address, err)
	}

	log.Printf("Server listening on %s", server_address)

	// 在独立goroutine中处理关闭信号
	go handleShutdown(server, delay)
	
	if err := server.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}

func handleShutdown(server *grpc.Server, delay int) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	
	// 等待信号
	<-sigCh
	
	log.Printf("Received shutdown signal, waiting %d ms before stopping...", delay)
	time.Sleep(time.Duration(delay) * time.Millisecond)
	
	// 优雅关闭服务器
	_, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	server.GracefulStop()
	log.Println("Server stopped gracefully")
}


func main() {
	flag.Parse()

	forwardingCores := ParseCoreOrNumaLine(*forwardingCores)
	log.Printf("Forwarding cores: %v", forwardingCores)
	numaNodes := ParseCoreOrNumaLine(*numaNodes)
	log.Printf("Numa nodes: %v", numaNodes)

	machelper := MacHelper.MacHelper{}

	config := Structs.MiniKatranConfig{
		MainInterface: *intf,
		//作为健康检查网口
		V4TunInterface: *ipipIntf, //ipip
		V6TunInterface: *ipip6Intf, //ipip6
		BalancerProgPath: *balancerProg,
		//没有健康检查程序
		Priority: uint32(*priority),
		DefaultMac: machelper.ConvertMacToUint(*defaultMac),
	}
	config.LruSize = uint64(*lruSize)
	config.ForwardingCores = forwardingCores
	config.NumaNodes = numaNodes
	//缺少健康检查
	Structs.Get_ready_config(&config) //配置初始化

	RunServer(&config, *shutdownDelay)
}