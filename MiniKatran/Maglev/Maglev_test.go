package maglev_test

import (
	"flag"
	"slices"
	"testing"

	Maglev "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/Maglev"
	Structs "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/Structs"
)

var (
	nreals     = flag.Int("nreals", 400, "number of backend endpoints")
	weight     = flag.Int("weight", 100, "primary weight of endpoints")
	freq       = flag.Int("freq", 1, "frequency of endpoints")
	diffweight = flag.Int("diffweight", 1, "secondary weight of endpoints")
	deletePos  = flag.Int("deletepos", -1, "position of endpoint to delete")
	useV2      = flag.Bool("v2", true, "use Maglev V2 algorithm")
)

func TestMaglev(t *testing.T) {
	flag.Parse()

	endpoints := []Structs.Endpoint{}
	freqs := make([]uint32, *nreals)
	for i := range freqs {
		freqs[i] = 0
	}
	var endpoint Structs.Endpoint

	for i := 0; i < *nreals; i++ {
		endpoint.Num = uint32(i)
		endpoint.Hash = uint64(10 * i)
		if i%*freq == 0 {
			endpoint.Weight = uint32(*weight)
		} else {
			endpoint.Weight = uint32(*diffweight)
		}
		endpoints = append(endpoints, endpoint)
	}

	var ch []int //hash环
	if *useV2 {
		//v2
		ch = Maglev.GenerateHashRingV2(endpoints, Structs.KDefaultChRingSize)
	} else {
		//v1
		ch = Maglev.GenerateHashRingV1(endpoints, Structs.KDefaultChRingSize)
	}

	var delete_real_num int = 0

	if *deletePos >= 0 && *deletePos < *nreals {
		endpoints = append(endpoints[:*deletePos], endpoints[*deletePos+1:]...)
		delete_real_num = *deletePos
	} else {
		delete_real_num = *nreals - 1
		endpoints = endpoints[:delete_real_num] //删除最后一个endpoint
	}
	//删除一个后端节点后的hash环
	var ch2 []int
	if *useV2 {
		ch2 = Maglev.GenerateHashRingV2(endpoints, Structs.KDefaultChRingSize)
	} else {
		ch2 = Maglev.GenerateHashRingV1(endpoints, Structs.KDefaultChRingSize)
	}

	//计数
	for i := 0; i < len(ch); i++ {
		freqs[ch[i]]++
	}

	// 复制切片避免原地修改
	sort_freq := make([]uint32, len(freqs))
	copy(sort_freq, freqs)
	slices.Sort(sort_freq)

	t.Logf(" min freq is %d and max freq is %d", sort_freq[0], sort_freq[len(sort_freq)-1])

	// 更鲁棒的分位数计算
	total := len(sort_freq)
	p95 := sort_freq[total*19/20]
	p75 := sort_freq[total*15/20]
	p50 := sort_freq[total/2]
	p25 := sort_freq[total/4]
	p5 := sort_freq[total/20]

	t.Logf("\nP95: %d\nP75: %d\nP50: %d\nP25: %d\nP5: %d\n", p95, p75, p50, p25, p5)

	n1, n2 := 0, 0
	//计算删除一个后端节点后的hash环的分布的误差
	for i := 0; i < len(ch); i++ {
		if ch[i] != ch2[i] {
			if ch[i] == delete_real_num {
				n1++
				continue
			}
			n2++
		}
	}

	chLen := len(ch)
	n1Percent := float64(n1) / float64(chLen) * 100
	n2Percent := float64(n2) / float64(chLen) * 100

	t.Logf("Affected changes: %d (%.2f%%)\n", n1, n1Percent)
	t.Logf("Not affected changes: %d (%.2f%%)\n", n2, n2Percent)
}

/*
v1下测试结果：
Running tool: /usr/local/go/bin/go test -timeout 30s -run ^TestMaglev$ github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/Maglev

=== RUN   TestMaglev
    /home/cainiao/bpftrace-exporter/MiniKatran/Maglev/Maglev_test.go:78:  min freq is 100 and max freq is 200
    /home/cainiao/bpftrace-exporter/MiniKatran/Maglev/Maglev_test.go:88:
        P95: 200
        P75: 200
        P50: 200
        P25: 100
        P5: 100
    /home/cainiao/bpftrace-exporter/MiniKatran/Maglev/Maglev_test.go:106: Affected changes: 100 (0.15%)
    /home/cainiao/bpftrace-exporter/MiniKatran/Maglev/Maglev_test.go:107: Not affected changes: 495 (0.76%)
--- PASS: TestMaglev (0.01s)
PASS
ok      github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/Maglev        (cached)
*/

/*
v2下测试结果
Running tool: /usr/local/go/bin/go test -timeout 30s -run ^TestMaglev$ github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/Maglev

=== RUN   TestMaglev
    /home/cainiao/bpftrace-exporter/MiniKatran/Maglev/Maglev_test.go:78:  min freq is 163 and max freq is 164
    /home/cainiao/bpftrace-exporter/MiniKatran/Maglev/Maglev_test.go:88:
        P95: 164
        P75: 164
        P50: 164
        P25: 164
        P5: 163
    /home/cainiao/bpftrace-exporter/MiniKatran/Maglev/Maglev_test.go:106: Affected changes: 163 (0.25%)
    /home/cainiao/bpftrace-exporter/MiniKatran/Maglev/Maglev_test.go:107: Not affected changes: 617 (0.94%)
--- PASS: TestMaglev (0.02s)
PASS
ok      github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/Maglev        0.026s
*/
