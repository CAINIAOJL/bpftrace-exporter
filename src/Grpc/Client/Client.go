package main

import (
	"log"
	"flag"
	"fmt"
	bpftrace_client_service "github.com/CAINIAOJL/bpftrace-exporter/src/Grpc/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
)

type BpftraceClient struct {
	client       bpftrace_client_service.BpftraceServiceClient  //客户端
}

func checkError(err error) {
	if err != nil {
		log.Fatalf("Error: %v\n", err)
	}
}

func (bc *BpftraceClient) Init(serverAddr string) {
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	conn, err := grpc.NewClient(serverAddr, opts...)
	if err != nil {
		log.Fatalf("Can't connect to local bfptrace server! err is %v\n", err)
	}
	bc.client = bpftrace_client_service.NewBpftraceServiceClient(conn)
}

func (bc *BpftraceClient) RunScript(BpftraceBin string, BpftraceScript string, vars string) {
	var Flags  bpftrace_client_service.BpftraceFlags
	Flags.PathScript = BpftraceScript
	Flags.PathBin = BpftraceBin
	Flags.Vars = vars
	status, err := bc.client.RunScript(context.Background(), &Flags)
	checkError(err)
	if !status.Success {
		log.Printf("run script failed, error is %s", status.Message)
	} else {
		log.Printf("run script: %s success!", BpftraceScript)
	}
}

func (bc *BpftraceClient) DeleteScript(deletescript string) {
	var DeleteScript bpftrace_client_service.BpftraceDeleteScript
	DeleteScript.Script = deletescript
	status, err := bc.client.DeleteScript(context.Background(), &DeleteScript)
	checkError(err)
	if !status.Success {
		log.Printf("Delete script: %s failed, error is %s", deletescript, status.Message)
	} else {
		log.Printf("Delete script: %s success!", deletescript)
	}
}

func (bc *BpftraceClient) GetScriptList() {
	BpftraceGetScriptList, err := bc.client.GetScriptList(context.Background(), &emptypb.Empty{})
	checkError(err)
	for _, script := range BpftraceGetScriptList.List {
		log.Printf("Script: %s", script.Script)
	}
}

var (
	//add
	//scriptPath = flag.String("scrpt", "/home/cainiao/bpftrace-exporter/src/runqlat.bt", "bpftrace script path")
	runscript = flag.Bool("r", false, "run script")
	scriptPath = flag.String("runscript", "/home/cainiao/bpftrace-exporter/src/example.bt", "bpftrace script path")
	vars = flag.String("vars", "usecs:hist", "bpftrace script variables")
	bpftraceBin = flag.String("bpftracebin", "/usr/bin/bpftrace", "bpftrace binary path")

	//delete
	delete = flag.Bool("d", false, "delete script")
	deleteScript = flag.String("deletescript", "/home/cainiao/bpftrace-exporter/src/runqlat.bt", "delete script name")

	//get script list
	List = flag.Bool("list", false, "get script list")

	bpftraceServer = flag.String("server", "127.0.0.1:50051", "server address")

)

func main() {
	flag.Parse()

	var bc BpftraceClient
	bc.Init(*bpftraceServer)
	if *scriptPath != "" && *vars != "" && *runscript {
		bc.RunScript(*bpftraceBin, *scriptPath, *vars)
	}
	if *deleteScript != "" && *delete {
		bc.DeleteScript(*deleteScript)
	} 
	if *List {
		bc.GetScriptList()
	}
	fmt.Printf("exiting\n")
}