package bpftrace

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

type Process struct {
	Cmd	                *exec.Cmd        //执行bpftrace命令
	Stdoutscanner       *bufio.Scanner   // 扫描命令输出
	NumberPorbe         int 		     // 匹配的probe数量
}

// NewProcess creates a new Process instance to run bpftrace
func NewProcess(bpftracePath string, scriptPath string) (*Process, error) {
	// Create a new command to run bpftrace
	//(root)bpftrace -f json xxxxxx.bt
	cmd := exec.Command(bpftracePath, "-f", "json", scriptPath) 
	cmd.Stderr = os.Stderr
	//返回一个管道，连接着stdout
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	//从stdout中读取数据，这里生成扫描器
	stdoutScanner := bufio.NewScanner(stdout)

	return &Process{
		Cmd: cmd,
		Stdoutscanner: stdoutScanner,
	}, nil
}

func (p *Process) Start() error {
	log.Printf("Starting `%s %s`...", p.Cmd.Path, strings.Join(p.Cmd.Args[1:], " "))
	err := p.Cmd.Start() //开启命令
	if err != nil {
		return err
	}

	//开启一个goroutine
	go func() {
		err := p.Cmd.Wait()
		if err != nil {
			log.Fatalf("bpftrace process exited with error: %v", err)
		}
		log.Printf("bpftrace process exited")
	}()

	var out Output
Loop:
	for p.Stdoutscanner.Scan() {
		line := p.Stdoutscanner.Text()
		err := json.Unmarshal([]byte(line), &out)
		if err != nil {
			log.Printf("Failed to unmarshal JSON: %v", err)
			continue
		}

		switch out.Type {
		case "attached_probes": //假设类型的是attached_probes，说明有probe被attach
			var probesData AttachProbes
			err := json.Unmarshal(out.Data, &probesData) //解析json数据
			if err != nil {
				log.Printf("Failed to unmarshal attached_probes JSON: %v", err)
				return err
			}
			p.NumberPorbe = probesData.Probes
			break Loop //跳出循环
		default:
			log.Printf("Unknown output type: %s", out.Type)
		}
	}

	if p.NumberPorbe > 0 {
		log.Printf("bpftrace started success, Attached %d probes", p.NumberPorbe) //显示输出attach probe 的数量
	}
	return nil
}

func (p *Process) SendSigusr1() error {
	return p.Cmd.Process.Signal(syscall.SIGUSR1)
}

func (p *Process) SendSigInt() error {
	return p.Cmd.Process.Signal(syscall.SIGINT)
}