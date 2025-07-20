package bpftrace

import (
	"encoding/json"
)

const (
	VarTypeNumber = iota
	VarTypeHistogram
)
//{"type": "attached_probes", "data": {"probes": 5}}
type Output struct{
	Type	string 		 		`json:"type"`
	Data    json.RawMessage 	`json:"data"` //json.RawMessage json格式的数据
}

type AttachProbes struct {
	Probes    int    `json:"probes"`  // Number of probes attached
}
/*
{"type": "hist", "data": {"@usecs": [{"min": 0, "max": 0, "count": 513}, {"min": 1, "max": 1, "count": 2523}, {"min": 2, "max": 3, "count": 10799}, {"min": 4, "max": 7, "count": 44037}, {"min": 8, "max": 15, "count": 102199}, {"min": 16, "max": 31, "count": 121331}, {"min": 32, "max": 63, "count": 89574}, {"min": 64, "max": 127, "count": 61092}, {"min": 128, "max": 255, "count": 28698}, {"min": 256, "max": 511, "count": 14741}, {"min": 512, "max": 1023, "count": 7635}, {"min": 1024, "max": 2047, "count": 3536}, {"min": 2048, "max": 4095, "count": 1434}, {"min": 4096, "max": 8191, "count": 206}, {"min": 8192, "max": 16383, "count": 56}, {"min": 16384, "max": 32767, "count": 18}, {"min": 32768, "max": 65535, "count": 7}]}}
*/
type Histbucket struct {
	Min      float64 	`json:"min"`      // Minimum value of the bucket
	Max      float64 	`json:"max"`      // Maximum value of the bucket
	Count    int64      `json:"count"`    // Count of samples in the bucket
}

type VarData map[string]json.RawMessage
type Number float64

//type Hist = map[string]Histbucket
type Hist = []Histbucket