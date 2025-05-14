package filesystem

import (
	//"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)


type Sar_Exporter struct {
	mu                    sync.RWMutex
	SarUsage              *prometheus.GaugeVec
	Sarpath               string
}

type Pid_FileSystem_exporter struct {
	mu                          sync.RWMutex
	Pid_FileSystem_Usage        *prometheus.GaugeVec
}

func Pid_FileSystem_NewExporter() *Pid_FileSystem_exporter {
	exporter := &Pid_FileSystem_exporter{
		Pid_FileSystem_Usage: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "cainiao_pid_comm_filesystem_io_usage",
				Help: "Every pid(comm) FileSystem io metric",
			},
			[]string{"pid","comm","mode"},
		),
	}

	go exporter.startCollector()
	return exporter
}

func (e *Pid_FileSystem_exporter)startCollector() {
		ticker := time.NewTicker(2 * time.Second) //定时器
	defer ticker.Stop()

	for range ticker.C{
		e.collectMetrics()
	}
}

/* eg.
	rchar: 7690783
	wchar: 741580
	syscr: 22026
	syscw: 4468
	read_bytes: 33672192
	write_bytes: 249856
	cancelled_write_bytes: 4096
*/

func (e *Pid_FileSystem_exporter)collectMetrics() {
	var pids []string

	entries, err := os.ReadDir("/proc/")
	if err != nil {
		log.Printf("Failed to read /proc/ directory: %v", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}

		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		pids = append(pids, e.Name())
	}

	type metricValue struct {
        pid   string
        comm  string
        mode  string
        value float64
    }

    var metricsToUpdate []metricValue

	for _, pidstr := range pids {
		pidpath := filepath.Join("/proc/", pidstr)
		if _, err := os.Stat(pidpath); os.IsNotExist(err) {
			continue
		}
		
		commFile := filepath.Join(pidpath, "comm")
		comm, err := os.ReadFile(commFile)
		if err != nil {
			log.Printf("can not read %s %v", commFile, err)
			continue
		}

		ioFile := filepath.Join(pidpath, "io")
		io, err := os.ReadFile(ioFile)
		if err != nil {
			log.Printf("can not read %s %v", ioFile, err)
			continue
		}

		lines := strings.Split(string(io), "\n")
		//fmt.Print(string(io))
		for _, line := range lines {
			if line == "" {
				continue
			}

			line_trim  := strings.SplitN(line, ":", 2)
            if len(line_trim) != 2 {
				log.Printf("Invalid line format: %s", line)
                continue
            }

			value, err := strconv.ParseFloat(strings.TrimSpace(line_trim[1]), 64)
			if err != nil {
				log.Printf("Error parsing value: %v", err)
				continue
			}
			metricsToUpdate = append(metricsToUpdate, metricValue{
				pid: pidstr,
				comm: string(comm),
				mode: strings.TrimSpace(line_trim[0]),
				value: value, 
			})
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.Pid_FileSystem_Usage.Reset()
	for _, metric := range metricsToUpdate {
		e.Pid_FileSystem_Usage.WithLabelValues(metric.pid, metric.comm, metric.mode).Set(metric.value)
	}
}

/*func (e *Pid_FileSystem_exporter) collectMetrics() {
    var pids []string

    entries, err := os.ReadDir("/proc/")
    if err != nil {
        log.Printf("Failed to read /proc directory: %v", err)
        return
    }

    for _, entry := range entries {
        if !entry.IsDir() {
            continue
        }
        if _, err := strconv.Atoi(entry.Name()); err != nil {
            continue
        }
        pids = append(pids, entry.Name())
    }

    type metricValue struct {
        pid   string
        comm  string
        mode  string
        value float64
    }

    var metricsToUpdate []metricValue

    for _, pidStr := range pids {
        pidPath := filepath.Join("/proc", pidStr)
        
        if _, err := os.Stat(pidPath); os.IsNotExist(err) {
            continue
        }

        commPath := filepath.Join(pidPath, "comm")
        commData, err := os.ReadFile(commPath)
        if err != nil {
            log.Printf("Failed to read %s: %v", commPath, err)
            continue
        }
        comm := strings.TrimSpace(string(commData))

        ioPath := filepath.Join(pidPath, "io")
        ioData, err := os.ReadFile(ioPath)
        if err != nil {
            log.Printf("Failed to read %s: %v", ioPath, err)
            continue
        }

        lines := strings.Split(string(ioData), "\n")
        for _, line := range lines {
            if line == "" {
                continue
            }

            parts := strings.SplitN(line, ":", 2)
            if len(parts) != 2 {
                log.Printf("Invalid line format in %s: %s", ioPath, line)
                continue
            }

            key := strings.TrimSpace(parts[0])
            valueStr := strings.TrimSpace(parts[1])

            value, err := strconv.ParseFloat(valueStr, 64)
            if err != nil {
                log.Printf("Failed to parse value '%s' in %s: %s (error: %v)", valueStr, ioPath, line, err)
                continue
            }

            switch key {
            case "rchar", "wchar", "syscr", "syscw", "read_bytes", "write_bytes", "cancelled_write_bytes":
                metricsToUpdate = append(metricsToUpdate, metricValue{
                    pid:   pidStr,
                    comm:  comm,
                    mode:  key,
                    value: value,
                })
            }
        }
    }

    e.mu.Lock()
    defer e.mu.Unlock()
    
    e.Pid_FileSystem_Usage.Reset()
    
    for _, metric := range metricsToUpdate {
        e.Pid_FileSystem_Usage.WithLabelValues(metric.pid, metric.comm, metric.mode).Set(metric.value)
    }
}*/

func (e *Pid_FileSystem_exporter)Describe(ch chan<- *prometheus.Desc) {
	e.Pid_FileSystem_Usage.Describe(ch)
}

func (e *Pid_FileSystem_exporter)Collect(ch chan<- prometheus.Metric) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.Pid_FileSystem_Usage.Collect(ch)
}

func Sar_NewExporter(sarpath string) *Sar_Exporter {
	exporter := &Sar_Exporter{
		Sarpath: sarpath,
		SarUsage: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "cainiao_sar_FileSystem_Usage",
				Help: "sar -v 1: FileSystem situation",
			},
			[]string{"mode"},
		),
	}

	go exporter.startCollector()
	return exporter
}


func (e *Sar_Exporter)startCollector() {
	ticker := time.NewTicker(1 * time.Second) //定时器
	defer ticker.Stop()

	for range ticker.C{
		e.collectMetrics()
	}
}

func (e *Sar_Exporter) collectMetrics() {
	cmd := exec.Command(e.Sarpath, "-v", "1", "1")
	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}()
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("error when 'sar -v 1 1' execute: %v", err)
		return
	}

	line := string(out)

	var result []int64

	lines := strings.Split(line, "\n")

	lines = lines[len(lines) - 3:] //只要最后一行
	lines_trim := strings.Fields(lines[1]) //分割成数组
	//log.Print(lines[1])
	for i, line := range lines_trim {
		if i == 1 || i == 2 || i == 3 || i == 4 {
			value, err := strconv.ParseInt(line, 10, 64)
			if err != nil {
				log.Printf("error when parsing load average value: %v", err)
				return //有一个不对，重来
			}
			result = append(result, value)
		}
	}

	if len(result) < 4 {
		log.Printf("error when (in 'sar -q 1 1') values found: %v", result)
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.SarUsage.Reset()

	e.SarUsage.WithLabelValues("dentunusd").Set(float64(result[0]))
	e.SarUsage.WithLabelValues("file-nr").Set(float64(result[1]))
	e.SarUsage.WithLabelValues("inode-nr").Set(float64(result[2]))
	e.SarUsage.WithLabelValues("pty-nr").Set(float64(result[3]))
}

func (e *Sar_Exporter)Describe(ch chan<- *prometheus.Desc) {
	e.SarUsage.Describe(ch)
}

func (e *Sar_Exporter)Collect(ch chan<- prometheus.Metric) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.SarUsage.Collect(ch)
}
