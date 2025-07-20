package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	bpftrace_client_service "github.com/CAINIAOJL/bpftrace-exporter/Bpftrace-exporter/Grpc/proto"
	exporter "github.com/CAINIAOJL/bpftrace-exporter/Bpftrace-exporter/exporter"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
)

func checkError(err error) {
	if err != nil {
		log.Fatalf("Error: %v\n", err)
	}
}

type BpftraceServer struct {
	bpftrace_client_service.UnimplementedBpftraceServiceServer
	//List            map[string]bool
	mu              		sync.RWMutex
	ScriptToCollector 		map[string]*exporter.Exporter
}

var customRegistry = prometheus.NewRegistry()
//var ScriptToCollector = make(map[string]*exporter.Exporter)
//var Collectors = make([]*exporter.Exporter, 50) //预备50个脚本收集

func (bs *BpftraceServer) RunScript(ctx context.Context, in *bpftrace_client_service.BpftraceFlags) (*bpftrace_client_service.ResponseStatus, error) {
	log.Printf("收到启动脚本请求 - BPFtrace二进制文件: %s, 脚本路径: %s, 变量: %s", in.PathBin, in.PathScript, in.Vars)

	// 创建新的exporter
	bpftraceExporter, err := exporter.NewExporter(in.PathBin, in.PathScript, in.Vars)
	if err != nil {
		checkError(err)
		return &bpftrace_client_service.ResponseStatus{Success: false, Message: fmt.Sprintf("can not create exporter for bpftrace script, error is %s", err.Error())}, err
	}
	
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if ok := bs.ScriptToCollector[in.PathScript]; ok != nil {
		//log.Println("脚本已经存在")
		return &bpftrace_client_service.ResponseStatus{Success: false, Message: "脚本已经存在"}, nil
	} else {
		customRegistry.Register(bpftraceExporter)
		bs.ScriptToCollector[in.PathScript] = bpftraceExporter //收集起来
		//Collectors = append(Collectors, bpftraceExporter)
		//bs.List[in.PathScript] = true
		return &bpftrace_client_service.ResponseStatus{Success: true}, nil
	}
	//customRegistry.Register(bpftraceExporter)
	//return &bpftrace_client_service.ResponseStatus{Success: false}, nil
	//return &bpftrace_client_service.ResponseStatus{Success: true}, nil
}

func (bs *BpftraceServer) DeleteScript(ctx context.Context, in *bpftrace_client_service.BpftraceDeleteScript) (*bpftrace_client_service.ResponseStatus, error) {
	log.Printf("收到删除请求 - 脚本路径: %s",in.Script)
	
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if ok := bs.ScriptToCollector[in.Script]; ok != nil {
		//delete(ScriptToCollector, in.Script)
		//temExporter := ScriptToCollector[in.Script]
		customRegistry.Unregister(bs.ScriptToCollector[in.Script]) //取消收集
		delete(bs.ScriptToCollector, in.Script)
		//delete(ScriptToCollector, in.Script) //删除映射
		//Collectors = append(Collectors, bpftraceExporter)
		//return &bpftrace_client_service.ResponseStatus{Success: true}, nil
	} else {
		return &bpftrace_client_service.ResponseStatus{Success: true, Message: "Script not found"}, nil
	}
	return &bpftrace_client_service.ResponseStatus{Success: true}, nil
}

func (bs *BpftraceServer) GetScriptList(ctx context.Context, in *emptypb.Empty) (*bpftrace_client_service.BpftraceGetScriptList, error) {	
	log.Print("收到展示所有脚本文件请求 -")
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	var result bpftrace_client_service.BpftraceGetScriptList
	for script, _ := range bs.ScriptToCollector {
		if script != "" {
			temp := &bpftrace_client_service.BpftraceDeleteScript{Script: script}
			result.List = append(result.List, temp)
		}
	} 
	return &result, nil
}

func init_w() {
	http.Handle("/metrics", promhttp.HandlerFor(customRegistry, promhttp.HandlerOpts{
		EnableOpenMetrics:  true,
		Timeout: 5 * time.Second,
	}))
        
    log.Printf("Bpftrace 导出器服务器已启动，监听端口: %s", *address)
    if err := http.ListenAndServe(*address, nil); err != nil {
        log.Fatalf("Failed to start Bpftrace server: %v", err)
    }
}

var (
	address = flag.String("address", ":9928", "Address to listen on for HTTP requests")
	serverport = flag.String("port", ":50051", "Address to listen on for gRPC requests")
)

func main() {
    lis, err := net.Listen("tcp", *serverport)
    if err != nil {
        log.Fatalf("监听失败: %v", err)
    }

    // 创建gRPC服务器实例（使用不安全连接）
    s := grpc.NewServer(
        grpc.Creds(insecure.NewCredentials()),
    )
	server := &BpftraceServer{
		ScriptToCollector: make(map[string]*exporter.Exporter),
	}
    // 注册服务
    bpftrace_client_service.RegisterBpftraceServiceServer(s, server)

    log.Printf("rpc服务器已启动，监听端口: %s", *serverport)

    // 启动HTTP服务器
	//开启一个goroutine，init_w函数会阻塞协程
    go init_w()

    // 启动gRPC服务
    if err := s.Serve(lis); err != nil {
        log.Fatalf("服务启动失败: %v", err)
    }	
}