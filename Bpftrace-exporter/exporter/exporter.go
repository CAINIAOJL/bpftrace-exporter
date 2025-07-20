package exporter

import (
	"encoding/json"
	"fmt"
	"log"
	"path"
	"strings"
	"sync"

	"github.com/CAINIAOJL/bpftrace-exporter/Bpftrace-exporter/bpftrace"
	"github.com/prometheus/client_golang/prometheus"
)

type Exporter struct {
	mutex 				sync.RWMutex
	numProbesDesc   	*prometheus.Desc
	process 			*bpftrace.Process
	scriptName	        string
	vars                map[string]*VarDef
}
//可不可以理解成嵌套Desc
type VarDef struct {
	VarType         int
	IsMap           bool
	Desc            *prometheus.Desc
	PromType        prometheus.ValueType
}

/*
{"type": "map", "data": {"@a": 1}}                                                @a = count();
{"type": "hist", "data": {"@b": [{"min": 2, "max": 3, "count": 1}, {"min": 4, "max": 7, "count": 1}]}}	     @b = hist(2); && @b = hist(5);
{"type": "map", "data": {"@c": {"1": 2}}}										  @c[1] = 2; 	
{"type": "map", "data": {"@d": {"1": 1}}}                                         @d[1] = count();
{"type": "hist", "data": {"@var": {"2": [{"min": 2, "max": 3, "count": 1}]}}}     @var[2] = hist(3);
*/


//数据导出器
func NewExporter (bpftracePath string, scriptPath string, varDefs string)(*Exporter, error) {
	process, err := bpftrace.NewProcess(bpftracePath, scriptPath) 
	if err != nil {
		return nil, err
	}

	err = process.Start()
	if err != nil {
		return nil, err
	}

	scriptName := strings.Split(path.Base(scriptPath), ".")[0] //split 分割字符串，将分割后的字符串放入数组中
	numPorbesDsec := prometheus.NewDesc(prometheus.BuildFQName("bpftrace", scriptName, "probes_total"), "number of attached probes", nil, nil)

	vars, err := parseVarDefs(scriptName, varDefs)
	if err != nil {
		return nil, err
	}

	return &Exporter{
		numProbesDesc: numPorbesDsec,
		process: process,
		scriptName: scriptName,
		vars: vars,		
	}, nil
}


//./bpftrace_exporter -script /usr/share/bpftrace/tools/runqlat.bt -vars usecs:hist,ns:hist
func parseVarDefs (scriptName string, varDefs string) (map[string]*VarDef, error) {
	result := map[string]*VarDef{}

	//分割字符串指标
	for _, varDef := range strings.Split(varDefs, ",") {
		if varDef == "" {
			continue
		}
		//-vars usecs:hist,ns:hist
		s := strings.Split(varDef, ":")
		name := s[0]
		def := ""
		if len(s) > 1 {
			def = s[1]
		}

		switch def {
		case "":
			result[name] = &VarDef{
				VarType:         bpftrace.VarTypeNumber,
				IsMap: 		     false,	
				Desc:            prometheus.NewDesc(prometheus.BuildFQName("bpftrace", scriptName, name), fmt.Sprintf("bpftrace variable @%s", name), nil, nil),
				PromType:        prometheus.GaugeValue,
			}
		case "counter":
			result[name] = &VarDef{
				VarType:         bpftrace.VarTypeNumber,
				IsMap: 		     false,	
				Desc:            prometheus.NewDesc(prometheus.BuildFQName("bpftrace", scriptName, name), fmt.Sprintf("bpftrace variable @%s", name), nil, nil),
				PromType:        prometheus.CounterValue,
			}
		case "map":
			result[name] = &VarDef{
				VarType:         bpftrace.VarTypeNumber,
				IsMap: 		     true,	
				Desc:            prometheus.NewDesc(prometheus.BuildFQName("bpftrace", scriptName, name), fmt.Sprintf("bpftrace map @%s", name), []string{"key"}, nil),
				PromType:        prometheus.GaugeValue,
			}
		case "countermap":
			result[name] = &VarDef{
				VarType:         bpftrace.VarTypeNumber,
				IsMap: 		     true,	
				Desc:            prometheus.NewDesc(prometheus.BuildFQName("bpftrace", scriptName, name), fmt.Sprintf("bpftrace map @%s", name), []string{"key"}, nil),
				PromType:        prometheus.CounterValue,
			}
		case "hist":
			result[name] = &VarDef{
				VarType:         bpftrace.VarTypeHistogram,
				IsMap: 		     false,	
				Desc:            prometheus.NewDesc(prometheus.BuildFQName("bpftrace", scriptName, name), fmt.Sprintf("bpftrace histogram @%s", name), nil, nil),
			}
		case "histmap":
			result[name] = &VarDef{
				VarType:         bpftrace.VarTypeHistogram,
				IsMap: 		     true,	
				Desc:            prometheus.NewDesc(prometheus.BuildFQName("bpftrace", scriptName, name), fmt.Sprintf("bpftrace histogram @%s", name), []string{"key"}, nil),
			}
		default:
			return nil, fmt.Errorf("unknown variable definition: \"%s\"", def)
		}
	}
	return result, nil
}



func (e *Exporter) Describe (ch chan<- *prometheus.Desc) {
	ch <- e.numProbesDesc
	for _, v := range e.vars {
		ch <- v.Desc
	}
}

func (e *Exporter) Collect (ch chan<- prometheus.Metric) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	e.scape(ch)
}

//eg.
//{"data": {"@a": 134}} 
// name:"@a", val:134
func exportNumber (ch chan<- prometheus.Metric, varDef *VarDef, val json.RawMessage, labelValues ...string) {
	
	var number bpftrace.Number
	err := json.Unmarshal(val, &number)
	if err != nil {
		log.Printf("cannot parse JSON of line %s, %v", val, err)
		return
	}
	//将新造的metric加入到channel中
	ch <- prometheus.MustNewConstMetric(varDef.Desc, varDef.PromType, float64(number), labelValues...)
}
//eg.
//"data": {"@h": [{"min": 2, "max": 3, "count": 2}, {"min": 8, "max": 15, "count": 1}, {"min": 16, "max": 31, "count": 2}]}
//name:"@h", val:[{"min": 2, "max": 3, "count": 1}, {"min": 8, "max": 15, "count": 1}, {"min": 16, "max": 31, "count": 2}]
//
func exportHistogram (ch chan<- prometheus.Metric, varDef *VarDef, val json.RawMessage, labelValues ...string) {
	var hist bpftrace.Hist
	err := json.Unmarshal(val, &hist)
	if err != nil {
		log.Printf("cannot parse JSON of line %s, %v", val, err)
		return 
	}

	buckets := map[float64]uint64{}
	count := uint64(0)

	for _, bucket := range hist {
		upperBound := bucket.Max
		count += uint64(bucket.Count)
		buckets[upperBound] = count
	}
	ch <- prometheus.MustNewConstHistogram(varDef.Desc, count, -1, buckets, labelValues...)
	//ch <- prometheus.MustNewConstHistogram(varDef.Desc, count, 0, buckets, labelValues...)
}


func exportScalarVar (ch chan<- prometheus.Metric, varDef *VarDef, val json.RawMessage, labelValues ...string) {
	switch varDef.VarType {
	case bpftrace.VarTypeNumber:
		exportNumber(ch, varDef, val, labelValues ...)
	case bpftrace.VarTypeHistogram:
		exportHistogram(ch, varDef, val, labelValues ...)
	}
}

//"data": {"@usecs": [{"min": 0, "max": 0, "count": 513}, {"min": 1, "max": 1, "count": 2523}, {"min": 2, "max": 3, "count": 10799}, {"min": 4, "max": 7, "count": 44037}, {"min": 8, "max": 15, "count": 102199}, {"min": 16, "max": 31, "count": 121331}, {"min": 32, "max": 63, "count": 89574}, {"min": 64, "max": 127, "count": 61092}, {"min": 128, "max": 255, "count": 28698}, {"min": 256, "max": 511, "count": 14741}, {"min": 512, "max": 1023, "count": 7635}, {"min": 1024, "max": 2047, "count": 3536}, {"min": 2048, "max": 4095, "count": 1434}, {"min": 4096, "max": 8191, "count": 206}, {"min": 8192, "max": 16383, "count": 56}, {"min": 16384, "max": 32767, "count": 18}, {"min": 32768, "max": 65535, "count": 7}]}}
func exportVal (ch chan<- prometheus.Metric, varDef *VarDef, val json.RawMessage) {
	if !varDef.IsMap {
		//@a = count() || @a = hist(2)
		exportScalarVar(ch, varDef, val)
	} else {
		//@a = mapcount() || @a = maphist()
		var mapData bpftrace.VarData
		err := json.Unmarshal(val, &mapData)
		if err != nil {
			log.Printf("cannot parse JSON of line %s, %v", val, err)
			return
		}

		for k, v := range mapData {
			exportScalarVar(ch, varDef, v, k)
		}
	}
}

func (e *Exporter) scape (ch chan<- prometheus.Metric) {
	//先处理probes的指标
	ch <- prometheus.MustNewConstMetric(e.numProbesDesc, prometheus.GaugeValue, float64(e.process.NumberPorbe))

	err := e.process.SendSigusr1()
	if err != nil {
		log.Printf("error sending signal: %v", err)
		return
	}

	var out bpftrace.Output
	for remvals := len(e.vars); remvals > 0 && e.process.Stdoutscanner.Scan(); {
		line := e.process.Stdoutscanner.Text()
		err := json.Unmarshal([]byte(line), &out)
		if err != nil {
			log.Printf("can not parse Json of line %s, %v", line, err)
			return
		}

		switch out.Type {
		//捕捉到printf
		case "printf":
			log.Printf("bpftrace output: %s", out.Data)
		case "map", "hist":
			var varData bpftrace.VarData
			err := json.Unmarshal(out.Data, &varData) //把json数据解析成VarData结构体
			if err != nil {
				log.Printf("cannnot parse JSON of line %s, %v", line, err)
				return
			}

			for name/*string*/, val/*json.RawMessage*/ := range varData {
				varDef, ok := e.vars[name[1:]]
				if ok {
					exportVal(ch, varDef, val)
					remvals--
				}
			}
		default:
			log.Printf("unknown output type: %s", out.Type)
		}
	}
}

func (e *Exporter) Stop() error {
	return e.process.SendSigInt()
}
