package main

import(
	"flag"
	"net/http"
	"time"
	"log"
	CPU "performance/CPU"
	MEMORY "performance/MEMORY"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)



func main() {
	mpstatPath := flag.String("mpstat", "/usr/bin/mpstat", "Path to mpstat binary")
	vmstatPath := flag.String("vmstat", "/usr/bin/vmstat", "Path to vmstat binary")
	address := flag.String("address", ":9929", "Listen address")
	sarpath := flag.String("sar", "/usr/bin/sar", "Path to sar binary")
	psi_cpu_path := flag.String("psi_cpu", "/proc/pressure/cpu", "Path to psi cpu")
	psi_memory_path := flag.String("psi_memory", "/proc/pressure/memory", "Path to psi memory")
	freepath := flag.String("free", "/usr/bin/free", "Path to free binary")
	//isSar_r := flag.Bool("sar_r", false, "Is sar -r")

	flag.Parse()

	//CPU
	C_mp_exporter := CPU.Mpstat_NewExporter(*mpstatPath)
	C_up_exporter := CPU.Uptime_NewExporter()
	C_vm_exporter := CPU.Vmstat_NewExporter(*vmstatPath)
	C_psi_exporter := CPU.PSI_NewExporter(*psi_cpu_path)
	C_sar_exporter := CPU.Sar_NewExporter(*sarpath)

	//MEMORY
	M_sar_exporter := MEMORY.Sar_NewExporter(*sarpath)
	M_psi_exporter := MEMORY.PSI_NewExporter(*psi_memory_path)
	M_vm_exporter := MEMORY.Vmstat_NewExporter(*vmstatPath)
	M_free_exporter := MEMORY.Free_NewExporter(*freepath)

	//CPU
	prometheus.MustRegister(C_up_exporter)
	prometheus.MustRegister(C_mp_exporter)
	prometheus.MustRegister(C_vm_exporter)
	prometheus.MustRegister(C_psi_exporter)
	prometheus.MustRegister(C_sar_exporter)

	//MEMORY
	prometheus.MustRegister(M_sar_exporter)
	prometheus.MustRegister(M_psi_exporter)
	prometheus.MustRegister(M_vm_exporter)
	prometheus.MustRegister(M_free_exporter)

	//http.Handle("/metrics", promhttp.Handler())
	http.Handle("/metrics", promhttp.HandlerFor(
		prometheus.DefaultGatherer,
		promhttp.HandlerOpts{
			Timeout: 			10 * time.Second,
			EnableOpenMetrics:  true,
		},
	))
	log.Printf("Starting server on %s", *address)
	log.Fatal(http.ListenAndServe(*address, nil))
}