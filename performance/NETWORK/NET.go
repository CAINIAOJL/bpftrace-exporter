package network

import (
	//"bufio"
	"bufio"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	//"fmt"
	//"os"
	"github.com/prometheus/client_golang/prometheus"
)

type Nstat_exporter struct {
	Nstat_usage              *prometheus.GaugeVec
	mu                       sync.RWMutex
	Nstatpath                string
}

type Netstat_exporter struct {
	Netstat_usage              *prometheus.GaugeVec
	mu                         sync.RWMutex
	Netstatpath                string
}

type Nicstat_exporter struct {
	Nicstat_usage              *prometheus.GaugeVec
	mu                         sync.RWMutex
	Nicstatpath                string
}

type Sockstat_exporter struct {
	mu                         sync.RWMutex
	Sockstat_usage             *prometheus.GaugeVec
}

func Sockstat_Newexporter() *Sockstat_exporter {
	exporter := &Sockstat_exporter{
		Sockstat_usage: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "cainiao_socket_usage",
				Help: "kernel socket usage information",
			},
			[]string{"item","mode"},
		),
	}
	go exporter.startCollector()
	return exporter
}

func (e *Sockstat_exporter)startCollector() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		e.collectMetrics()
	}
}

func (e *Sockstat_exporter)collectMetrics() {
	socketData, err := os.ReadFile("/proc/net/sockstat")
	if err != nil {
		log.Printf("error when read /proc/net/sockstat: %v", err)
		return
	}
	lines := strings.Split(string(socketData), "\n")
	for _, line := range lines {
		if strings.Contains(line, "TCP:") {
			data := strings.Fields(line)
			//TCP: inuse 204 orphan 0 tw 54 alloc 243 mem 0
			inuse, _ := strconv.ParseFloat(data[2], 64)
			orphan, _ := strconv.ParseFloat(data[4], 64)
			tw, _ := strconv.ParseFloat(data[6], 64)
			alloc, _ := strconv.ParseFloat(data[8], 64)
			mem, _ := strconv.ParseFloat(data[10], 64)
			e.mu.Lock()
			e.Sockstat_usage.WithLabelValues("tcp", "inuse").Set(inuse)
			e.Sockstat_usage.WithLabelValues("tcp", "orphan").Set(orphan)
			e.Sockstat_usage.WithLabelValues("tcp", "tw").Set(tw)
			e.Sockstat_usage.WithLabelValues("tcp", "alloc").Set(alloc)
			e.Sockstat_usage.WithLabelValues("tcp", "mem").Set(mem)
			e.mu.Unlock()
		} else if strings.Contains(line, "UDP:") {
			//UDP: inuse 9 mem 512
			//log.Print(line)
			data := strings.Fields(line)
			inuse, _ := strconv.ParseFloat(data[2], 64)
			mem, _ := strconv.ParseFloat(data[4], 64)
			e.mu.Lock()
			e.Sockstat_usage.WithLabelValues("udp", "inuse").Set(inuse)
			e.Sockstat_usage.WithLabelValues("udp", "mem").Set(mem)
			e.mu.Unlock()
		}
	}
}	

func (e *Sockstat_exporter) Describe(ch chan<- *prometheus.Desc) {
	e.Sockstat_usage.Describe(ch)
}

func (e *Sockstat_exporter) Collect(ch chan<- prometheus.Metric) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.Sockstat_usage.Collect(ch)
}

func Nicstat_Newexporter(nicstatpath string) *Nicstat_exporter {
	exporter := &Nicstat_exporter{
		Nicstat_usage: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "cainiao_nicstat_usage",
				Help: "net(nicstat) ethernet usage information",
			},
			[]string{"interface","mode"},
		),
		Nicstatpath: nicstatpath,
	}
	go exporter.startCollector()
	return exporter
}

func (e *Nicstat_exporter)startCollector() {
	e.collectMetrics()
}

func (e *Nicstat_exporter)collectMetrics() {
	cmd := exec.Command(e.Nicstatpath, "1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("error when exec command 'nicstat -i' :%v", err)
		return
	}

	if err := cmd.Start(); err != nil {
		log.Printf("error when exec command 'nicstat -i' :%v", err)
		return
	}

	scanner := bufio.NewScanner(stdout)

	for scanner.Scan() {
		line := scanner.Text()

		lines := strings.Split(line, "\n")
		for _, Data := range lines {
			line_trim := strings.Fields(Data)
			if len(line_trim) < 10 {
				log.Printf("error when parse nicstat data: %v", err)
				return
			}

			//    Time      Int   rKB/s   wKB/s   rPk/s   wPk/s    rAvs    wAvs %Util    Sat
			rKB_pps, _ := strconv.ParseFloat(line_trim[2], 64)
			wKB_pps, _ := strconv.ParseFloat(line_trim[3], 64)
			rPk_pps, _ := strconv.ParseFloat(line_trim[4], 64)
			wPk_pps, _ := strconv.ParseFloat(line_trim[5], 64)
			rAvs, _ := strconv.ParseFloat(line_trim[6], 64)
			wAvs, _ := strconv.ParseFloat(line_trim[7], 64)
			Util, _ := strconv.ParseFloat(line_trim[8], 64)
			Sat, _ := strconv.ParseFloat(line_trim[9], 64)

			e.mu.Lock()
			e.Nicstat_usage.
				WithLabelValues(line_trim[1], "rKB/s").Set(rKB_pps)
			e.Nicstat_usage.
				WithLabelValues(line_trim[1], "wKB/s").Set(wKB_pps)
			e.Nicstat_usage.
				WithLabelValues(line_trim[1], "rPk/s").Set(rPk_pps)
			e.Nicstat_usage.
				WithLabelValues(line_trim[1], "wPk/s").Set(wPk_pps)
			e.Nicstat_usage.
				WithLabelValues(line_trim[1], "rAvs").Set(rAvs)
			e.Nicstat_usage.
				WithLabelValues(line_trim[1], "wAvs").Set(wAvs)
			e.Nicstat_usage.
				WithLabelValues(line_trim[1], "%Util").Set(Util)
			e.Nicstat_usage.
				WithLabelValues(line_trim[1], "Sat").Set(Sat)
			e.mu.Unlock()
		}
	}
}

func (e *Nicstat_exporter) Describe(ch chan<- *prometheus.Desc) {
	e.Nicstat_usage.Describe(ch)
}

func (e *Nicstat_exporter) Collect(ch chan<- prometheus.Metric) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.Nicstat_usage.Collect(ch)
}

func Netstat_Newexporter(nstatpath string) *Netstat_exporter {
	exporter := &Netstat_exporter{
		Netstat_usage: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "cainiao_netstat_usage",
				Help: "net(netstat) ethernet usage information",
			},
			[]string{"interface","mode"},
		),
		Netstatpath: nstatpath,
	}
	go exporter.startCollector()
	return exporter
}

func (e *Netstat_exporter)startCollector() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		e.collectMetrics()
	}
}

func (e *Netstat_exporter)collectMetrics() {
	cmd := exec.Command(e.Netstatpath, "-i")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("error when exec command 'netstat -i' :%v", err)
		return
	}

	lines := strings.Split(string(out), "\n")
	//RX-OK RX-ERR RX-DRP RX-OVR    TX-OK TX-ERR TX-DRP TX-OVR
	type InterfaceData struct {
		InterfaceName       string
		Netdata             map[string]float64
	}

	var netstatData []InterfaceData
	for _, line := range lines {
		if line == "" || strings.Contains(line, "MTU") || strings.Contains(line, "table") {
			continue
		}
		valueData := strings.Fields(line)
		if len(valueData) < 11 {
			log.Printf("error when parse netstat data: %v", err)
			return
		}
		var tempData InterfaceData
		tempData.Netdata = make(map[string]float64)
		tempData.InterfaceName = valueData[0]
		tempData.Netdata["RX-OK"], _ = strconv.ParseFloat(valueData[2], 64)
		tempData.Netdata["RX-ERR"], _ = strconv.ParseFloat(valueData[3], 64)
		tempData.Netdata["RX-DRP"], _ = strconv.ParseFloat(valueData[4], 64)
		tempData.Netdata["RX-OVR"], _ = strconv.ParseFloat(valueData[5], 64)
		tempData.Netdata["TX-OK"], _ = strconv.ParseFloat(valueData[6], 64)
		tempData.Netdata["TX-ERR"], _ = strconv.ParseFloat(valueData[7], 64)
		tempData.Netdata["TX-DRP"], _ = strconv.ParseFloat(valueData[8], 64)
		tempData.Netdata["TX-OVR"], _ = strconv.ParseFloat(valueData[9], 64)
		netstatData = append(netstatData, tempData)
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	for _, v := range netstatData {
		e.Netstat_usage.
			WithLabelValues(v.InterfaceName, "RX-OK").Set(v.Netdata["RX-OK"])
		e.Netstat_usage.
			WithLabelValues(v.InterfaceName, "RX-ERR").Set(v.Netdata["RX-ERR"])
		e.Netstat_usage.
			WithLabelValues(v.InterfaceName, "RX-DRP").Set(v.Netdata["RX-DRP"])
		e.Netstat_usage.
			WithLabelValues(v.InterfaceName, "RX-OVR").Set(v.Netdata["RX-OVR"])
		e.Netstat_usage.
			WithLabelValues(v.InterfaceName, "TX-OK").Set(v.Netdata["TX-OK"])
		e.Netstat_usage.
			WithLabelValues(v.InterfaceName, "TX-ERR").Set(v.Netdata["TX-ERR"])
		e.Netstat_usage.
			WithLabelValues(v.InterfaceName, "TX-DRP").Set(v.Netdata["TX-DRP"])
		e.Netstat_usage.
			WithLabelValues(v.InterfaceName, "TX-OVR").Set(v.Netdata["TX-OVR"])
	}

}

func (e *Netstat_exporter) Describe(ch chan<- *prometheus.Desc) {
	e.Netstat_usage.Describe(ch)
}

func (e *Netstat_exporter) Collect(ch chan<- prometheus.Metric) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.Netstat_usage.Collect(ch)
}

func MountInfo_NewExporter(nstatpath string) *Nstat_exporter {
	exporter := &Nstat_exporter{
		Nstat_usage: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "cainiao_nstat_usage",
				Help: "net(nstat) usage information",
			},
			[]string{"mode"},
		),
		Nstatpath: nstatpath,
	}
	go exporter.startCollector()
	return exporter
}

func (e *Nstat_exporter)startCollector() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		e.collectMetrics()
	}
}

func (e *Nstat_exporter) collectMetrics() {
	/*
IpInReceives                    11781              0.0
IpInDelivers                    11769              0.0
IpOutRequests                   11824              0.0
IpOutTransmits                  11824              0.0
IcmpInMsgs                      7                  0.0
IcmpInDestUnreachs              4                  0.0
IcmpInEchos                     1                  0.0
IcmpInEchoReps                  2                  0.0
IcmpOutMsgs                     7                  0.0
IcmpOutDestUnreachs             4                  0.0
IcmpOutEchos                    2                  0.0
IcmpOutEchoReps                 1                  0.0
IcmpMsgInType0                  2                  0.0
IcmpMsgInType3                  4                  0.0
IcmpMsgInType8                  1                  0.0
IcmpMsgOutType0                 1                  0.0
IcmpMsgOutType3                 4                  0.0
IcmpMsgOutType8                 2                  0.0
TcpActiveOpens                  150                0.0
TcpPassiveOpens                 108                0.0
TcpAttemptFails                 17                 0.0
TcpEstabResets                  78                 0.0
TcpInSegs                       11959              0.0
TcpOutSegs                      12026              0.0
TcpOutRsts                      94                 0.0
UdpInDatagrams                  32                 0.0
UdpOutDatagrams                 32                 0.0
Ip6InReceives                   241                0.0
Ip6InDelivers                   229                0.0
Ip6OutRequests                  229                0.0
Ip6OutNoRoutes                  1                  0.0
Ip6InMcastPkts                  12                 0.0
Ip6InOctets                     50681              0.0
Ip6OutOctets                    49601              0.0
Ip6InMcastOctets                1080               0.0
Ip6InNoECTPkts                  241                0.0
Ip6OutTransmits                 229                0.0
TcpExtTW                        43                 0.0
TcpExtDelayedACKs               1027               0.0
TcpExtDelayedACKLost            2                  0.0
TcpExtTCPHPHits                 3445               0.0
TcpExtTCPPureAcks               923                0.0
TcpExtTCPHPAcks                 5628               0.0
TcpExtTCPTimeouts               12                 0.0
TcpExtTCPDSACKOldSent           2                  0.0
TcpExtTCPAbortOnData            74                 0.0
TcpExtTCPRcvCoalesce            352                0.0
TcpExtTCPSpuriousRtxHostQueues  12                 0.0
TcpExtTCPAutoCorking            21                 0.0
TcpExtTCPOrigDataSent           7572               0.0
TcpExtTCPKeepAlive              114                0.0
TcpExtTCPDelivered              7628               0.0
TcpExtTcpTimeoutRehash          12                 0.0
IpExtInOctets                   2030240            0.0
IpExtOutOctets                  2067499            0.0
IpExtInNoECTPkts                11798              0.0
	*/

	cmd := exec.Command(e.Nstatpath, "-s")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("error when exec command 'nstat -s' :%v", err)
		return
	}

	nstat_data := map[string]float64 {
		"IpInReceives":             	0,
		"IpInDelivers":             	0,
		"IpOutRequests":      		 	0,
		"IpOutTransmits":           		0,
		"IcmpInMsgs":               		0,
		"IcmpInDestUnreachs":       		0,
		"IcmpInEchos":              		0,
		"IcmpInEchoReps":      	 		0,
		"IcmpOutMsgs":          	 		0,
		"IcmpOutDestUnreachs":      		0,
		"IcmpOutEchos":          	 	0,
		"IcmpOutEchoReps":          		0,
		"IcmpMsgInType0":  		 		0,
		"IcmpMsgInType3":           		0,
		"IcmpMsgInType8":           		0,
		"IcmpMsgOutType0":          		0,    
		"IcmpMsgOutType3":          		0,     
		"IcmpMsgOutType8":          		0,     
		"TcpActiveOpens":           		0,      
		"TcpPassiveOpens":          		0,     
		"TcpAttemptFails":          		0,     
		"TcpEstabResets":           		0,     
		"TcpInSegs":                		0,  
		"TcpOutSegs":               		0,     
		"TcpOutRsts":               		0, 
		"UdpInDatagrams":           		0,
		"UdpOutDatagrams":          		0,
		"Ip6InReceives":            		0,
		"Ip6InDelivers":            		0,
		"Ip6OutRequests":           		0,
		"Ip6OutNoRoutes":           		0,
		"Ip6InMcastPkts":           		0,
		"Ip6InOctets":              		0,
		"Ip6OutOctets":             		0,
		"Ip6InMcastOctets":         		0,
		"Ip6InNoECTPkts":           		0,
		"Ip6OutTransmits":          		0,
		"TcpExtTW":                 		0,
		"TcpExtDelayedACKs":        		0,
		"TcpExtDelayedACKLost":     		0,
		"TcpExtTCPHPHits":          		0,
		"TcpExtTCPPureAcks":        		0,
		"TcpExtTCPHPAcks":          		0,
		"TcpExtTCPTimeouts":        		0,
		"TcpExtTCPDSACKOldSent":    		0,
		"TcpExtTCPAbortOnData":     		0,
		"TcpExtTCPRcvCoalesce":     		0,
		"TcpExtTCPSpuriousRtxHostQueues":  0,
		"TcpExtTCPAutoCorking":            0,
		"TcpExtTCPOrigDataSent":           0,
		"TcpExtTCPKeepAlive":              0,
		"TcpExtTCPDelivered":              0,
		"TcpExtTcpTimeoutRehash":          0,
		"IpExtInOctets":                   0,
		"IpExtOutOctets":                  0,
		"IpExtInNoECTPkts":                0,
	}

	lines := strings.Split(string(out), "\n")
	for _, data := range lines { //跳过第一行
		//log.Print(data)
		if data == "" || strings.HasPrefix(data, "#") {
			continue
		}
		datas := strings.Fields(data)
		if len(datas) < 2 {
			log.Printf("error when get data from nstat: %v", err)
			return
		}
		value, err := strconv.ParseFloat(datas[1], 64)
		if err != nil {
			log.Printf("(network)error when ParseFloat string to float: %v", err)
			return
		}
		nstat_data[datas[0]] = value
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.Nstat_usage.Reset()
	for k, v := range nstat_data {
		e.Nstat_usage.WithLabelValues(k).Set(v)
	}

}

func (e * Nstat_exporter) Describe(ch chan<- *prometheus.Desc) {
	e.Nstat_usage.Describe(ch)
}

func (e * Nstat_exporter) Collect(ch chan<- prometheus.Metric) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.Nstat_usage.Collect(ch)
}

