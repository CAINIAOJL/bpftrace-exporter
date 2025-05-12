package main

import(
	"flag"
	"net/http"
	"time"
	"log"
	CPU "performance/CPU"
	MEMORY "performance/MEMORY"
	FILE_SYSTEM "performance/FILE_SYSTEM"
	EXT "performance/EXT"
	NETWORK "performance/NETWORK"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)



func main() {
	mpstatPath := flag.String("mpstat", "/usr/bin/mpstat", "Path to mpstat binary")
	vmstatPath := flag.String("vmstat", "/usr/bin/vmstat", "Path to vmstat binary")
	nstatpath  := flag.String("nstat", "/usr/bin/nstat", "path to nstat binary")
	netstatpath := flag.String("netstat", "/usr/bin/netstat", "Path to netstat binary")
	nicstatpath := flag.String("nicstat", "/usr/bin/nicstat", "Path to nicstat binary")
	address := flag.String("address", ":9929", "Listen address")
	sarpath := flag.String("sar", "/usr/bin/sar", "Path to sar binary")
	psi_cpu_Path := flag.String("psi_cpu", "/proc/pressure/cpu", "Path to psi cpu")
	psi_memory_Path := flag.String("psi_memory", "/proc/pressure/memory", "Path to psi memory")
	freePath := flag.String("free", "/usr/bin/free", "Path to free binary")
	pid_cpu := flag.Int64("pid_cpu", -1, "The pid you want to get cpu time on '/proc/pid/schedstat'bu count all task on pid process: /proc/pid/task/ppid/schedstat")
	//isSar_r := flag.Bool("sar_r", false, "Is sar -r")

	flag.Parse()

	//CPU
	C_mp_exporter := CPU.Mpstat_NewExporter(*mpstatPath)
	C_up_exporter := CPU.Uptime_NewExporter()
	C_vm_exporter := CPU.Vmstat_NewExporter(*vmstatPath)
	C_psi_exporter := CPU.PSI_NewExporter(*psi_cpu_Path)
	C_sar_exporter := CPU.Sar_NewExporter(*sarpath)
	C_pid_schedstat_exporter := CPU.Schedstat_NewExporter(*pid_cpu)

	//MEMORY
	M_sar_exporter := MEMORY.Sar_NewExporter(*sarpath)
	M_psi_exporter := MEMORY.PSI_NewExporter(*psi_memory_Path)
	M_vm_exporter := MEMORY.Vmstat_NewExporter(*vmstatPath)
	M_free_exporter := MEMORY.Free_NewExporter(*freePath)

	//FILE_SYSTEM
	F_sar_exporter := FILE_SYSTEM.Sar_NewExporter(*sarpath)
	F_Pid_FileSystem_exporter := FILE_SYSTEM.Pid_FileSystem_NewExporter()


	//EXT
	E_iostat_exporter := EXT.Iostat_NewExporter()
	E_mountinfo_exporter := EXT.MountInfo_NewExporter()

	//NETWORK
	N_nstat_exporter := NETWORK.MountInfo_NewExporter(*nstatpath)
	N_netstat_exporter := NETWORK.Netstat_Newexporter(*netstatpath)
	N_nicstat_exporter := NETWORK.Nicstat_Newexporter(*nicstatpath)
	N_socket_exporter := NETWORK.Sockstat_Newexporter()

	//CPU
	prometheus.MustRegister(C_up_exporter)
	prometheus.MustRegister(C_mp_exporter)
	prometheus.MustRegister(C_vm_exporter)
	prometheus.MustRegister(C_psi_exporter)
	prometheus.MustRegister(C_sar_exporter)
	if C_pid_schedstat_exporter != nil {
		prometheus.MustRegister(C_pid_schedstat_exporter)
	} else {
		log.Printf("The exporter for pid_cpu meet error")
	}

	//MEMORY
	prometheus.MustRegister(M_sar_exporter)
	prometheus.MustRegister(M_psi_exporter)
	prometheus.MustRegister(M_vm_exporter)
	prometheus.MustRegister(M_free_exporter)

	//FILE_SYSTEM
	prometheus.MustRegister(F_sar_exporter)
	prometheus.MustRegister(F_Pid_FileSystem_exporter)

	//EXT
	prometheus.MustRegister(E_iostat_exporter)
	prometheus.MustRegister(E_mountinfo_exporter)

	//NETWORK
	prometheus.MustRegister(N_nstat_exporter)
	prometheus.MustRegister(N_netstat_exporter)
	prometheus.MustRegister(N_nicstat_exporter)
	prometheus.MustRegister(N_socket_exporter)

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