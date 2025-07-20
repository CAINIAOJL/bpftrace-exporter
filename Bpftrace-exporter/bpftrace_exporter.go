package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/CAINIAOJL/bpftrace-exporter/Bpftrace-exporter/exporter"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)


func main() {
	var(
		//-bpftracePath bpftrace 
		bpftracePath 	= flag.String("bpftrace", "bpftrace", "Path to bpftrace binary")
		scriptPath 		= flag.String("script", "", "Path to bpftrace script (bpftrace.bt)")
		address 	    = flag.String("address", ":9928", "Address to listen on for HTTP requests")
		vars            = flag.String("vars", "", "Variables to export (e.g. usecs:hist,ns:hist)")
	)
	//解析命令行
	flag.Parse()

	exporter, err := exporter.NewExporter(*bpftracePath, *scriptPath, *vars)
	if err != nil {
		log.Fatalln("Error creating exporter ", err)
		os.Exit(1)
	}

	prometheus.MustRegister(exporter)
	//prometheus.MustRegister(version.NewCollector("bpftrace_exporter"))

	http.Handle("/metrics", promhttp.HandlerFor(
		prometheus.DefaultGatherer,
		promhttp.HandlerOpts{
			EnableOpenMetrics:  true,
			Timeout: 5 * time.Second,
		},
	))

	log.Fatal(http.ListenAndServe(*address, nil))

}