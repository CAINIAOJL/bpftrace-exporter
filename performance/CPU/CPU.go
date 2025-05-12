package CPU

import (
	"bufio"
	"encoding/json"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
	"fmt"
	"os"
	"github.com/prometheus/client_golang/prometheus"
)

// 原数据结构保持不变
type Mpstat_CPU_Load struct {
	CPU    string  `json:"cpu"`
	Usr    float64 `json:"usr"`
	Nice   float64 `json:"nice"`
	Sys    float64 `json:"sys"`
	Iowait float64 `json:"iowait"`
	Irq    float64 `json:"irq"`
	Soft   float64 `json:"soft"`
	Steal  float64 `json:"steal"`
	Guest  float64 `json:"guest"`
	Gnice  float64 `json:"gnice"`
	Idle   float64 `json:"idle"`
}

type Mpstat_statistics struct {
	Timestamp string           `json:"timestamp"`
	CPU_Load  []Mpstat_CPU_Load `json:"cpu-load"`
}

type Mpstat_Host struct {
	Nodename   string              `json:"nodename"`
	Sysname    string              `json:"sysname"`
	Release    string              `json:"release"`
	Machine    string              `json:"machine"`
	NumCPUs    int                 `json:"number-of-cpus"`
	Date       string              `json:"date"`
	Statistics []Mpstat_statistics `json:"statistics"`
}

type Mpstat_SysStat struct {
	Hosts []Mpstat_Host `json:"hosts"`
}

type Mpstat_SysStat_Line struct {
	Sysstat Mpstat_SysStat `json:"sysstat"`
}

type U_Mpstat_Exporter struct {
	mu         		sync.RWMutex
	cpuUsage   		*prometheus.GaugeVec
	mpstatPath 		string
}

type US_Uptime_Exporter struct {
	mu         		sync.RWMutex
	uptime     		*prometheus.GaugeVec
}

type U_Vmstat_Exporter struct {
	mu          	sync.RWMutex
	cpuUsage      	*prometheus.GaugeVec
	vmstatpath  	string
}

//psi 压力失速信息，可能需要较新的Linux内核支持
type Psi_Exporter struct {
	mu               sync.RWMutex
	psiUsage         *prometheus.GaugeVec
	psipath          string
}

type S_Sar_Exporter struct {
	mu               sync.RWMutex
	sarUsage         *prometheus.GaugeVec
	sarpath          string
}

type Schedstat_Exporter struct {
	mu               sync.RWMutex
	schedstatUsage   *prometheus.GaugeVec
	comm             string
	pid              int64
}

func PidToComm (pid int64) (string, error) {
	cmd := exec.Command("cat", "/proc/" + strconv.Itoa(int(pid)) + "/comm")
	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}()
	
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("error when find comm for pid = %d", pid)
		return "", err
	}

	return strings.TrimSpace(string(out)), nil
}

func Schedstat_NewExporter(pid int64) *Schedstat_Exporter {
	comm, err := PidToComm(pid)
	if err != nil || comm == "" {
		return nil
	}

	exporter := &Schedstat_Exporter{
		comm: comm,
		pid: pid,
		schedstatUsage: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "cainiao_schedstat_usage_"+comm,
				Help: "schedstat usage percentage of %s" + comm,
			},
			[]string{"pid","mode"},
		),
	}

	go exporter.startCollector()
	return exporter
}

func (e *Schedstat_Exporter) startCollector() {
	ticker := time.NewTicker(1 * time.Second) //定时器
	defer ticker.Stop()

	for range ticker.C{
		e.collectMetrics()
	}
}

func (e *Schedstat_Exporter) collectMetrics() {
	taskDir := fmt.Sprintf("/proc/%d/task", e.pid)
    entries, err := os.ReadDir(taskDir)
    if err != nil {
		log.Printf("error when read task directory %s: %v", taskDir, err)
        return
    }

	//dir := strings.Fields(string(output))

	for _, dirname := range entries {
		cmd := exec.Command("cat", "/proc/"+strconv.Itoa(int(e.pid))+"/task/"+dirname.Name()+"/schedstat")
		defer func() {
			if cmd.Process != nil {
				cmd.Process.Kill()
			}
		}()

		out, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("error when get %s: %v",out, err)
			return
		}

		lines := strings.Fields(string(out))

		var mp = map[int]string {
			0: "cpu_on_cpu",
			1: "run_queue",
			2: "run_on_cpu",
		}
		e.mu.Lock()
		for i, line := range lines {
			if line != "" {
				value, err := strconv.ParseInt(line, 10, 64)
				if err != nil {
					log.Printf("error when parsing value: %v", err)
					return
				}
				e.schedstatUsage.WithLabelValues(dirname.Name(), mp[i]).Set(float64(value))
			}
		}
		e.mu.Unlock()
	}
}	

func (e * Schedstat_Exporter) Describe(ch chan<- *prometheus.Desc) {
	e.schedstatUsage.Describe(ch)
}

func (e * Schedstat_Exporter) Collect(ch chan<- prometheus.Metric) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.schedstatUsage.Collect(ch)
}

func Sar_NewExporter(sarpath string) *S_Sar_Exporter {
	exporter := &S_Sar_Exporter {
		sarUsage: prometheus.NewGaugeVec(
			prometheus.GaugeOpts {
				Name: "cainiao_sar_cpu_Saturation",
				Help: "sar cpu queue size, plist size, and blocked processes",
			},
			[]string{"mode"},
		),
		sarpath: sarpath,
	}

	go exporter.startCollector()
	return exporter
}

func (e *S_Sar_Exporter) startCollector() {
	ticker := time.NewTicker(1 * time.Second) //定时器
	defer ticker.Stop()

	for range ticker.C{
		e.collectMetrics()
	}
}

func (e *S_Sar_Exporter) collectMetrics() {
	cmd := exec.Command(e.sarpath, "-q", "1", "1")
	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}()
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("error when executing 'sar -q 1 1: %v", err)
		return
	}

	line := string(out)

	var result []int64

	lines := strings.Split(line, "\n")

	lines = lines[len(lines) - 3:] //只要最后一行
	lines_trim := strings.Fields(lines[0]) //分割成数组

	for i, line := range lines_trim {
		if i == 2 || i == 3 || i == 7 {
			value, err := strconv.ParseInt(line, 10, 64)
			if err != nil {
				log.Printf("error when parsing load average value: %v", err)
				return //有一个不对，重来
			}
			result = append(result, value)
		}
	}

	if len(result) < 3 {
		log.Printf("error when parsing load average value: %v", result)
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.sarUsage.Reset()

	e.sarUsage.WithLabelValues("runq-sz").Set(float64(result[0]))
	e.sarUsage.WithLabelValues("plist-sz").Set(float64(result[1]))
	e.sarUsage.WithLabelValues("blocked").Set(float64(result[2]))
}

func (e *S_Sar_Exporter) Describe(ch chan<- *prometheus.Desc) {
	e.sarUsage.Describe(ch)
}

func (e *S_Sar_Exporter) Collect(ch chan<- prometheus.Metric) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sarUsage.Collect(ch)
}

func PSI_NewExporter(psipath string) *Psi_Exporter {
	exporter := &Psi_Exporter {
		psiUsage: prometheus.NewGaugeVec(
			prometheus.GaugeOpts {
				Name: "cainiao_psi_cpu",
				Help: "(cpu)PSI usage percentage by mode",
			},
			[]string{"situation","mode"}, //situation: some, full
		),
		psipath: psipath,
	}

	go exporter.startCollector()
	return exporter
}

func (e *Psi_Exporter) startCollector() {
	ticker := time.NewTicker(1 * time.Second) //定时器
	defer ticker.Stop()

	for range ticker.C{
		e.collectMetrics()
	}
}

func (e *Psi_Exporter) collectMetrics() {
	cmd := exec.Command("cat", e.psipath)
	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}()
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("error when read /proc/pressure/cpu: %v", err)
		return
	}

	line := string(out)
	var some []float64
	var full []float64

	lines := strings.Split(line, "\n")
	if len(lines) < 2 {
		log.Printf("error when read /proc/pressure/cpu: %v", err)
		return
	}

	some_line := strings.Fields(lines[0])
	full_line := strings.Fields(lines[1])

	for i, line := range some_line {
		if i == 0 {
			continue
		}
		vIndex := strings.Index(line, "=")
		if vIndex == -1 {
			log.Printf("error when read /proc/pressure/cpu: %v", err)
			return //有一个不对，重来
		}

		new_line := line[vIndex + 1:]
		value, err := strconv.ParseFloat(new_line, 64)
		if err != nil {
			log.Printf("error when read /proc/pressure/cpu: %v", err)
			return
		}
		some = append(some, value)
	}
	if len(some) < 4 {
		log.Printf("error when read /proc/pressure/cpu: %v", err)
		return
	}

	for i, line := range full_line {
		if i == 0 {
			continue
		}
		vIndex := strings.Index(line, "=")
		if vIndex == -1 {
			log.Printf("error when read /proc/pressure/cpu: %v", err)
			return //有一个不对，重来
		}

		new_line := line[vIndex + 1:]
		value, err := strconv.ParseFloat(new_line, 64)
		if err != nil {
			log.Printf("error when read /proc/pressure/cpu: %v", err)
			return
		}
		full = append(full, value)
	}
	if len(full) < 4 {
		log.Printf("error when read /proc/pressure/cpu: %v", err)
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// 重置指标（避免旧数据残留）
	e.psiUsage.Reset()

	e.psiUsage.WithLabelValues("some", "10s").Set(some[0])
	e.psiUsage.WithLabelValues("some", "60s").Set(some[1])
	e.psiUsage.WithLabelValues("some", "300s").Set(some[2])
	e.psiUsage.WithLabelValues("some", "total").Set(some[3])


	e.psiUsage.WithLabelValues("full", "10s").Set(full[0])
	e.psiUsage.WithLabelValues("full", "60s").Set(full[1])
	e.psiUsage.WithLabelValues("full", "300s").Set(full[2])
	e.psiUsage.WithLabelValues("full", "total").Set(full[3])
}

func (e *Psi_Exporter) Describe(ch chan<- *prometheus.Desc) {
	e.psiUsage.Describe(ch)
}

func (e *Psi_Exporter) Collect(ch chan<- prometheus.Metric) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.psiUsage.Collect(ch)
}

func Vmstat_NewExporter(vmstatpath string) *U_Vmstat_Exporter {
	exporter := &U_Vmstat_Exporter{
		vmstatpath: vmstatpath,
		cpuUsage: prometheus.NewGaugeVec(
			prometheus.GaugeOpts {
				Name: "vm_cainiao_cpu_usage_percent",
				Help: "CPU usage percentage by mode(vmstat): us, sy",
			},
			[]string{"mode"},
		),
	}

	go exporter.startCollector()
	return exporter
}

func (e *U_Vmstat_Exporter) startCollector() {
	e.collectMetrics()
}

func (e *U_Vmstat_Exporter) collectMetrics() {
	cmd := exec.Command(e.vmstatpath, "1")
	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}()
	out, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("error when creating StdoutPipe for Cmd: %v", err)
		return
	}

	if err := cmd.Start(); err != nil {
		log.Printf("error when starting Cmd: %v", err)
		return
	}

	scanner := bufio.NewScanner(out)

	var FieldsIndex = map[string]int {
		"us": 12,
		"sy": 13,
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		if line == "" {
			continue
		}

		//跳过第一行和第二行
		if strings.Contains(line, "procs") || strings.Contains(line, "us") {
			continue
		} 
		
		lines := strings.Fields(line) //分割成数组
		
		if len(lines) < 17 {
			log.Printf("error when parse output: %v", err)
			continue
		}

		e.mu.Lock()
		for metric, index := range FieldsIndex {
			if index >= len(lines) {
				log.Printf("Index %d out of range for metric %s", index, metric)
				continue
			}

			value, err := strconv.ParseFloat(lines[index], 64)
			if err != nil {
				log.Printf("error when parse output: %v", err)
				continue
			}

			e.cpuUsage.WithLabelValues(metric).Set(value)
		}
		e.mu.Unlock()
	}
	if err := scanner.Err(); err != nil {
		log.Fatal("Error reading output:", err)
	}
}

func (e *U_Vmstat_Exporter) Describe(ch chan<- *prometheus.Desc) {
	e.cpuUsage.Describe(ch)
}

func (e *U_Vmstat_Exporter) Collect(ch chan<- prometheus.Metric) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cpuUsage.Collect(ch)
}

func Uptime_NewExporter() *US_Uptime_Exporter {
	exporter := &US_Uptime_Exporter{
		uptime: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "cainiao_uptime",
				Help: "Uptime of the system",
			},
			[]string{"time"},
		),
	}

	go exporter.startCollector()
	return exporter
}

func (e *US_Uptime_Exporter) startCollector() {
	ticker := time.NewTicker(1 * time.Second) //定时器
	defer ticker.Stop()

	for range ticker.C {
		e.collectMetrics()
	}
}

func (e *US_Uptime_Exporter) collectMetrics() {
	cmd := exec.Command("uptime")
	out, err := cmd.CombinedOutput()
	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}()
	if err != nil {
		log.Printf("error when 'uptime' execution failed: %v", err)
		return
	}

	line := string(out)
	var result []float64
	
	loadAverageIndex := strings.Index(line, "load average:")

	if loadAverageIndex == -1 {
		log.Printf("error when Load average not found in output: %s", line)
		return
	}

	// 提取负载平均值
	loadAverage := line[loadAverageIndex + len("Load average:"):]

	loadAverages := strings.Split(loadAverage, ",")

	for _, part := range loadAverages {
		part = strings.TrimSpace(part) //去除空格,左边加上右边
		if part != "" {
			value, err := strconv.ParseFloat(part, 64)
			if err != nil {
				log.Printf("error when parsing load average value: %v", err)
				return //有一个不对，重来
			}
			result = append(result, value)
		}
	}

	if len(result) < 3 {
		log.Printf("error when parsing load average value: %v", result)
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	// 重置指标（避免旧数据残留）
	e.uptime.MetricVec.Reset()
	e.uptime.WithLabelValues("1").Set(result[0])
	e.uptime.WithLabelValues("5").Set(result[1])
	e.uptime.WithLabelValues("15").Set(result[2])
}

func (e *US_Uptime_Exporter) Describe(ch chan<- *prometheus.Desc) {
	e.uptime.Describe(ch)
}

func (e *US_Uptime_Exporter) Collect(ch chan<- prometheus.Metric) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.uptime.Collect(ch)
}
func Mpstat_NewExporter(mpstatPath string) *U_Mpstat_Exporter {
	exporter := &U_Mpstat_Exporter{
		cpuUsage: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "mp_cainiao_cpu_usage_percent",
				Help: "CPU usage percentage by mode(mpstat)",
			},
			[]string{"cpu", "mode"},
		),
		mpstatPath: mpstatPath,
	}

	go exporter.startCollector()
	return exporter
}

func (e *U_Mpstat_Exporter) startCollector() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		e.collectMetrics()
	}
}

func (e *U_Mpstat_Exporter) collectMetrics() {
	cmd := exec.Command(e.mpstatPath, "-P", "ALL", "-o", "JSON", "1", "1")
	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}()
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("error when run command 'sar -P ALL -o JSON 1 1': %v", err)
		return
	}

	var data Mpstat_SysStat_Line
	if err := json.Unmarshal(output, &data); err != nil {
		log.Printf("error when unmarshal json data %v", err)
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// 重置指标（避免旧数据残留）
	e.cpuUsage.Reset()

	for _, host := range data.Sysstat.Hosts {
		for _, stat := range host.Statistics {
			for _, cpu := range stat.CPU_Load {
				// 添加所有CPU指标
				modes := map[string]float64{
					"usr":    cpu.Usr,
					"nice":   cpu.Nice,
					"sys":    cpu.Sys,
					"iowait": cpu.Iowait,
					"irq":    cpu.Irq,
					"soft":   cpu.Soft,
					"steal":  cpu.Steal,
					"guest":  cpu.Guest,
					"gnice":  cpu.Gnice,
					"idle":   cpu.Idle,
				}

				for mode, value := range modes {
					e.cpuUsage.WithLabelValues(cpu.CPU, mode).Set(value)
				}
			}
		}
	}
}

func (e *U_Mpstat_Exporter) Describe(ch chan<- *prometheus.Desc) {
	e.cpuUsage.Describe(ch)
}

func (e *U_Mpstat_Exporter) Collect(ch chan<- prometheus.Metric) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cpuUsage.Collect(ch)
}