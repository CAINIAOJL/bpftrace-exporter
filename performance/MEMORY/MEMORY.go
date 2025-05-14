package memory

import (
	//"encoding/json"
	"bufio"
	//"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)


type Sar_Exporter struct {
	mu             			sync.RWMutex
	sarUsage                *prometheus.GaugeVec
	sarpath        			string
}

type Psi_Exporter struct {
	mu               sync.RWMutex
	psiUsage         *prometheus.GaugeVec
	psipath          string
}

type U_Vmstat_Exporter struct {
	mu          	sync.RWMutex
	memoryUsage     *prometheus.GaugeVec
	vmstatpath  	string
}

type Free_Exporter struct {
	memoryUsage      *prometheus.GaugeVec
	mu          	 sync.RWMutex
	freepath		 string
}

func Free_NewExporter(freepath string) *Free_Exporter {
	exporter := &Free_Exporter {
		memoryUsage: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "cainiao_memory_usage",
				Help: "usr Free to view memory",
			},
			[]string{"mode"},
		),
		freepath: freepath,
	}

	go exporter.startCollector()
	return exporter
}

func (e *Free_Exporter) startCollector() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		e.collectMetrics()
	}
}

func (e *Free_Exporter) collectMetrics() {
	cmd := exec.Command(e.freepath, "-b")
	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}()

	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("error when 'free -b' execute: %v", err)
		return
	}

	lines := strings.Split(string(out), "\n")
	if len(lines) < 3 {
		log.Printf("error Not enough lines in output: %s", lines)
		return
	}

	DataLine := lines[1]
	DataLine_trim := strings.Fields(DataLine)
	if len(DataLine_trim) < 7 {
		log.Printf("error Not enough load average values found: %v", err)
		return
	}
	var cnt = map[string]int {
		"total":1,
		"used":2,
		"free":3,
		"shared":4,
		"buff/cache":5,
		"available":6,
	}
	e.mu.Lock()
	for metric, index := range cnt {
		if index >= len(DataLine_trim) {
			log.Printf("error Index %d out of range for metric %s", index, metric)
			return
		}
		value, err := strconv.ParseFloat(DataLine_trim[cnt[metric]], 64)
		if err != nil {
			log.Printf("error parsing value %s for metric %s", DataLine_trim[cnt[metric]], metric)
			return
		}

		e.memoryUsage.WithLabelValues(metric).Set(value)
	}
	e.mu.Unlock()
}

func (e *Free_Exporter) Describe(ch chan<- *prometheus.Desc) {
	e.memoryUsage.Describe(ch)
}

func (e *Free_Exporter) Collect(ch chan<- prometheus.Metric) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.memoryUsage.Collect(ch)
}

func PSI_NewExporter(psipath string) *Psi_Exporter {
	exporter := &Psi_Exporter {
		psiUsage: prometheus.NewGaugeVec(
			prometheus.GaugeOpts {
				Name: "cainiao_psi_usage_memory",
				Help: "(memory)PSI usage percentage by mode",
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
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("error when read /proc/pressure/memory: %v", err)
		return
	}

	line := string(out)
	var some []float64
	var full []float64

	lines := strings.Split(line, "\n")
	if len(lines) < 2 {
		log.Printf("error Not enough lines in output: %s", line)
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
			log.Printf("Invalid line format: %s", line)
			return //有一个不对，重来
		}

		new_line := line[vIndex + 1:]
		value, err := strconv.ParseFloat(new_line, 64)
		if err != nil {
			log.Printf("Invalid value format: %s", new_line)
			return
		}
		some = append(some, value)
	}
	if len(some) < 4 {
		log.Printf("error Not enough load average values found: %v", some)
		return
	}

	for i, line := range full_line {
		if i == 0 {
			continue
		}
		vIndex := strings.Index(line, "=")
		if vIndex == -1 {
			log.Printf("Invalid line format: %s", line)
			return //有一个不对，重来
		}

		new_line := line[vIndex + 1:]
		value, err := strconv.ParseFloat(new_line, 64)
		if err != nil {
			log.Printf("Invalid value format: %s", new_line)
			return
		}
		full = append(full, value)
	}
	if len(full) < 4 {
		log.Printf("error Not enough load average values found: %v", some)
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

func Sar_NewExporter(sarpath string) *Sar_Exporter {
	exporter := &Sar_Exporter {
		sarpath: sarpath,
		sarUsage: prometheus.NewGaugeVec(
			prometheus.GaugeOpts {
				Name: "cainiao_sar_memory_usage",
				Help: "sar -B memory usage",
			},
			[]string{"mode"},
		),
	}

	go exporter.startcollector()
	return exporter
}

func (e *Sar_Exporter) startcollector() {
	timer := time.NewTicker(1 * time.Second)
	defer timer.Stop()

	for range timer.C {
	e.collectMetrics()
	}
}

func (e *Sar_Exporter) collectMetrics() {
	cmd := exec.Command(e.sarpath, "-B", "1", "1")
	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}()
	out, err := cmd.CombinedOutput()

	if err != nil {
		log.Printf("Error executing sar command: %v", err)
		return
	}

	lines := strings.Split(string(out), "\n")

	// Parse the output
	var result []float64
	lines = lines[len(lines)-3:] //取最后一行
	//fmt.Println(lines[0])
	lines_trim := strings.Fields(lines[0])
	for i, line := range lines_trim {
		if i == 0 || i == 1 {
			continue
		}

		value, err := strconv.ParseFloat(line, 64)
		if err != nil {
			log.Printf("Error parsing value: %v", err)
			return
		}
		result = append(result, value)
	}

	if len(result) < 9 {
		log.Printf("error Unexpected number of values from sar command: %d", len(result))
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.sarUsage.Reset()

	e.sarUsage.WithLabelValues("pgpgin/s").Set(result[0])
	e.sarUsage.WithLabelValues("pgpgout/s").Set(result[1])
	e.sarUsage.WithLabelValues("fault/s").Set(result[2])
	e.sarUsage.WithLabelValues("majflt/s").Set(result[3])
	e.sarUsage.WithLabelValues("pgfree/s").Set(result[4])
	e.sarUsage.WithLabelValues("pgscank/s").Set(result[5])
	e.sarUsage.WithLabelValues("pgscand/s").Set(result[6])
	e.sarUsage.WithLabelValues("pgsteal/s").Set(result[7])
	e.sarUsage.WithLabelValues("%vmeff").Set(result[8])

	cmd = exec.Command(e.sarpath, "-r", "1", "1")
	out, err = cmd.CombinedOutput()

	if err != nil {
		log.Printf("Error executing sar command: %v", err)
		return
	}

	lines = strings.Split(string(out), "\n")
	lines = lines[len(lines)-3:] //取最后一行
	lines_trim = strings.Fields(lines[0])
	result = []float64{}
	for i, line := range lines_trim {
		if i == 0 || i == 1 {
			continue
		}
		value, err := strconv.ParseFloat(line, 64)
		if err != nil {
			log.Printf("Error parsing value: %v", err)
			return
		}
		result = append(result, value)
	}

	if len(result) < 11 {
		log.Printf("error Unexpected number of values from sar command: %d", len(result))
		return
	}

	e.sarUsage.WithLabelValues("kbmemfree").Set(result[0])
	e.sarUsage.WithLabelValues("kbavail").Set(result[1])
	e.sarUsage.WithLabelValues("kbmemused").Set(result[2])
	e.sarUsage.WithLabelValues("%memused").Set(result[3])
	e.sarUsage.WithLabelValues("kbbuffers").Set(result[4])
	e.sarUsage.WithLabelValues("kbcached").Set(result[5])
	e.sarUsage.WithLabelValues("kbcommit").Set(result[6])
	e.sarUsage.WithLabelValues("%commit").Set(result[7])
	e.sarUsage.WithLabelValues("kbactive").Set(result[8])
	e.sarUsage.WithLabelValues("kbinact").Set(result[9])
	e.sarUsage.WithLabelValues("kbdirty").Set(result[10])
}

func (e *Sar_Exporter) Describe(ch chan<- *prometheus.Desc) {
	e.sarUsage.Describe(ch)
}

func (e *Sar_Exporter) Collect(ch chan<- prometheus.Metric) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sarUsage.Collect(ch)
}

func Vmstat_NewExporter(vmstatpath string) *U_Vmstat_Exporter {
	exporter := &U_Vmstat_Exporter{
		vmstatpath: vmstatpath,
		memoryUsage: prometheus.NewGaugeVec(
			prometheus.GaugeOpts {
				Name: "vm_cainiao_memory_usage_percent",
				Help: "memory usage(MB) percentage by mode(vmstat)",
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
	// 启动持续采集
	cmd := exec.Command(e.vmstatpath, "-Sm", "1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal("error getting stdout pipe:", err)
	}

	if err := cmd.Start(); err != nil {
		log.Fatal("error when exec command 'vmstat -Sm 1':", err)
	}
	defer cmd.Process.Kill() // 确保退出时清理进程

	// 实时解析输出
	scanner := bufio.NewScanner(stdout)

	var fieldIndexes = map[string]int{
		"swpd": 2,
		"free": 3,
		"buff": 4,
		"cache": 5,
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// 跳过表头行与目录行
		if strings.Contains(line, "procs") || strings.Contains(line, "us") {
			continue
		}

		// 解析数据行
		fields := strings.Fields(line)
		if len(fields) < 6 {
			log.Printf("error Invalid data line: %s", line)
			continue
		}

		// 更新指标
		e.mu.Lock()
		for metric, idx := range fieldIndexes {
			if idx >= len(fields) {
				log.Printf("error Index %d out of range for metric %s", idx, metric)
				return
			}
			value, err := strconv.ParseFloat(fields[idx], 64)
			if err != nil {
				log.Printf("error when parsing %s: %v", metric, err)
				return
			}
			e.memoryUsage.WithLabelValues(metric).Set(value)
		}
		e.mu.Unlock()
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error reading output: %v", err)
		return
	}
}

func (e *U_Vmstat_Exporter) Describe(ch chan<- *prometheus.Desc) {
	e.memoryUsage.Describe(ch)
}

func (e *U_Vmstat_Exporter) Collect(ch chan<- prometheus.Metric) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.memoryUsage.Collect(ch)
}