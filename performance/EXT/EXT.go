package EXT

import (
	//"bufio"
	//"fmt"
	//"io"
	"log"
	"os"
	"syscall"
	//"os/exec"
	//"runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type Iostat_Exporter struct {
	mu           				sync.RWMutex
	Iostat_usage 				*prometheus.GaugeVec
}

type MountInfo_Exporter struct {
	MountInfo_usage           	 *prometheus.GaugeVec
	mu                           sync.RWMutex
}

func MountInfo_NewExporter() *MountInfo_Exporter {
	exporter := &MountInfo_Exporter{
		MountInfo_usage: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "cainiao_disk_usage",
				Help: "disk usage information",
			},
			[]string{"diskpath","mode"},
		),
	}
	go exporter.startCollector()
	return exporter
}

func (e *MountInfo_Exporter)startCollector() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		e.collectMetrics()
	}
}

func (e *MountInfo_Exporter) collectMetrics() {
	Mountinfo, err := os.ReadFile("/proc/1/mountinfo")
	if err != nil {
		log.Printf("Error when reading /proc/1/mountinfo %v", err)
		return
	}

	Mountinfo_data := strings.Split(string(Mountinfo), "\n")

	/*
	TOOD: man statfs(syscall)
	struct statfs {
              // __fsword_t f_type;       /* Type of filesystem (see below) */
               //__fsword_t f_bsize;      /* Optimal transfer block size */
               //fsblkcnt_t f_blocks;     /* Total data blocks in filesystem */
               //fsblkcnt_t f_bfree;      /* Free blocks in filesystem */
               //fsblkcnt_t f_bavail;     /* Free blocks available to unprivileged user */
               //fsfilcnt_t f_files;      /* Total inodes in filesystem */
               //fsfilcnt_t f_ffree;      /* Free inodes in filesystem */
               //fsid_t     f_fsid;       /* Filesystem ID */
               //__fsword_t f_namelen;    /* Maximum length of filenames */
               //__fsword_t f_frsize;     /* Fragment size (since Linux 2.6) */
               //__fsword_t f_flags;      /* Mount flags of filesystem(since Linux 2.6.36) */
               //__fsword_t f_spare[xxx]; /* Padding bytes reserved for future use */
           //};
	type mountinfo_data struct {
		statfs_data             syscall.Statfs_t
		diskpath                string
	}
	mountinfo_datas := []mountinfo_data{}

	for _, line := range Mountinfo_data {
		if strings.Contains(line, "0:") {
			lines := strings.Fields(line)
			diskpath := lines[4]
			var disk_statfs syscall.Statfs_t
			err := syscall.Statfs(diskpath, &disk_statfs)
			if err != nil {
				log.Printf("error when do syscall-statfs: %v", err)
			}
			mountinfo_datas = append(mountinfo_datas, mountinfo_data{disk_statfs, diskpath})
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.MountInfo_usage.Reset()
	for _, data := range mountinfo_datas {
		Bavail_ := float64(data.statfs_data.Bavail)
		Bfree_ := float64(data.statfs_data.Bfree)
		e.MountInfo_usage.
			WithLabelValues(data.diskpath, "f_bavail").Set(Bavail_)
		e.MountInfo_usage.
			WithLabelValues(data.diskpath, "f_bfree").Set(Bfree_)
	}
}

func (e * MountInfo_Exporter) Describe(ch chan<- *prometheus.Desc) {
	e.MountInfo_usage.Describe(ch)
}

func (e * MountInfo_Exporter) Collect(ch chan<- prometheus.Metric) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.MountInfo_usage.Collect(ch)
}

func Iostat_NewExporter() *Iostat_Exporter {
	exporter := &Iostat_Exporter{
		Iostat_usage: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "cainiao_iostat_usage",
				Help: "Usage of iostat",
			},
			[]string{"maj", "min", "device", "metric"},
		),
	}
	go exporter.startCollector()
	return exporter
}

func (e *Iostat_Exporter)startCollector() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		e.collectMetrics()
	}
}

func (e *Iostat_Exporter) collectMetrics() {
	out, err := os.ReadFile("/proc/diskstats")
	if err != nil {
		log.Printf("error when read /proc/diskstats: %v", err)
		return
	}
	type diskmetric struct {
		maj                 string   //主设备号
		min                 string   //次设备号
		name                string   //磁盘名称
		read_pps			float64  //read I/Os
		read_merges			float64	 //read merges
		read_sectors		float64  //read sectors
		read_ticks			float64  //read ticks
		write_pps			float64  //write I/Os
		write_merges		float64  //write merges
		write_sectors		float64  //write sectors
		write_ticks			float64  //write ticks
		in_flight			float64  //in_flight
		io_ticks			float64  //io_ticks
		time_in_queue		float64  //time_in_queue
		discard_pps			float64  //discard I/Os
		discard_merges		float64  //discard merges
		discard_sectors		float64  //discard sectors
		discard_ticks		float64  //discard ticks
		flush_pps			float64  //flush I/Os
		flush_ticks			float64  //flush ticks
	}

	var newmetric []diskmetric

	datas := strings.Split(string(out), "\n")
	for _, data := range datas {
		if data == "" {
			continue
		}
		SingleData := strings.Fields(data)
		if len(SingleData) < 20 {
			log.Printf("error when Analysis data in /proc/diskstats: %v", err)
			return
		}
		rp, _ := strconv.ParseFloat(SingleData[3],64)
		rm, _ := strconv.ParseFloat(SingleData[4],64)
		rs, _ := strconv.ParseFloat(SingleData[5],64)
		rt, _ := strconv.ParseFloat(SingleData[6],64)

		wp, _ := strconv.ParseFloat(SingleData[7],64)
		wm, _ := strconv.ParseFloat(SingleData[8],64)
		ws, _ := strconv.ParseFloat(SingleData[9],64)
		wt, _ := strconv.ParseFloat(SingleData[10],64)

		If, _ := strconv.ParseFloat(SingleData[11],64)
		It, _ := strconv.ParseFloat(SingleData[12],64)
		tiq, _ := strconv.ParseFloat(SingleData[13],64)

		dp, _ := strconv.ParseFloat(SingleData[14],64)
		dm, _ := strconv.ParseFloat(SingleData[15],64)
		ds, _ := strconv.ParseFloat(SingleData[16],64)
		dt, _ := strconv.ParseFloat(SingleData[17],64)

		fp, _ := strconv.ParseFloat(SingleData[18],64)
		ft, _ := strconv.ParseFloat(SingleData[19],64)

		m := diskmetric {
			maj: SingleData[0],
			min: SingleData[1],
			name: SingleData[2],
			read_pps: rp,
			read_merges: rm,
			read_sectors: rs,
			read_ticks: rt,
			write_pps: wp,
			write_merges: wm,
			write_sectors: ws,
			write_ticks: wt,
			in_flight: If,
			io_ticks: It,
			time_in_queue: tiq,
			discard_pps: dp,
			discard_merges: dm,
			discard_sectors: ds,
			discard_ticks: dt,
			flush_pps: fp,
			flush_ticks: ft,
		}

		newmetric = append(newmetric, m)
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.Iostat_usage.Reset()
	for _, metirc := range newmetric {
		e.Iostat_usage.
			WithLabelValues(metirc.maj, metirc.min, metirc.name, "read I/Os").Set(metirc.read_pps)
		e.Iostat_usage.
			WithLabelValues(metirc.maj, metirc.min, metirc.name, "read merges").Set(metirc.read_merges)
		e.Iostat_usage.
			WithLabelValues(metirc.maj, metirc.min, metirc.name, "read sectors").Set(metirc.read_sectors)
		e.Iostat_usage.
			WithLabelValues(metirc.maj, metirc.min, metirc.name, "read ticks").Set(metirc.read_ticks)
		e.Iostat_usage.
			WithLabelValues(metirc.maj, metirc.min, metirc.name, "write I/Os").Set(metirc.write_pps)
		e.Iostat_usage.
			WithLabelValues(metirc.maj, metirc.min, metirc.name, "write merges").Set(metirc.write_merges)
		e.Iostat_usage.
			WithLabelValues(metirc.maj, metirc.min, metirc.name, "write sectors").Set(metirc.write_sectors)
		e.Iostat_usage.
			WithLabelValues(metirc.maj, metirc.min, metirc.name, "write ticks").Set(metirc.write_ticks)
		e.Iostat_usage.
			WithLabelValues(metirc.maj, metirc.min, metirc.name, "io_ticks").Set(metirc.io_ticks)
		e.Iostat_usage.
			WithLabelValues(metirc.maj, metirc.min, metirc.name, "in_flight").Set(metirc.in_flight)
		e.Iostat_usage.
			WithLabelValues(metirc.maj, metirc.min, metirc.name, "time_in_queue").Set(metirc.time_in_queue)
		e.Iostat_usage.
			WithLabelValues(metirc.maj, metirc.min, metirc.name, "discard I/Os").Set(metirc.discard_pps)
		e.Iostat_usage.
			WithLabelValues(metirc.maj, metirc.min, metirc.name, "discard merges").Set(metirc.discard_merges)
		e.Iostat_usage.
			WithLabelValues(metirc.maj, metirc.min, metirc.name, "discard sectors").Set(metirc.discard_sectors)
		e.Iostat_usage.
			WithLabelValues(metirc.maj, metirc.min, metirc.name, "discard ticks").Set(metirc.discard_ticks)
		e.Iostat_usage.
			WithLabelValues(metirc.maj, metirc.min, metirc.name, "flush I/Os").Set(metirc.flush_pps)
		e.Iostat_usage.
			WithLabelValues(metirc.maj, metirc.min, metirc.name, "flush ticks").Set(metirc.flush_ticks)
	}
}

func (e * Iostat_Exporter) Describe(ch chan<- *prometheus.Desc) {
	e.Iostat_usage.Describe(ch)
}

func (e * Iostat_Exporter) Collect(ch chan<- prometheus.Metric) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.Iostat_usage.Collect(ch)
}