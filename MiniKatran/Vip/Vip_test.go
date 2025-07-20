package vip_test

import (
	"testing"
	"github.com/stretchr/testify/assert"
	Structs "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/Structs"
	Vip "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/Vip"

)

var Global_vip1 *Vip.Vip
var Global_vip2 *Vip.Vip
var reals []Structs.UpdateReal

func SetUp() {
	Global_vip1 = Vip.NewVip(1, 0, Structs.KDefaultChRingSize, 2) //maglev V2
	Global_vip2 = Vip.NewVip(2, 0, Structs.KDefaultChRingSize, 2) //maglev V2

	ureals := Structs.UpdateReal{}

	for i := 0; i < 100; i++ {
		ureals.Op = Structs.ADD
		ureals.UpdateReal.Num = uint32(i)
		ureals.UpdateReal.Weight = 10
		ureals.UpdateReal.Hash = uint64(i)
		reals = append(reals, ureals)
	}
}

func TestBatchUpdateReals(t *testing.T) {
	SetUp()

	delta  := Global_vip1.BatchRealsUpdate(reals)
	delta2 := Global_vip2.BatchRealsUpdate(reals)


	assert.Equal(t, 
			 	Global_vip1.GetChringSize(), 
				uint32(len(delta)), 
				"BatchRealsUpdate (when there is no reals in Vip for first), its size must be equal to GetChringSize()")
	
	assert.Equal(t, 
				Global_vip2.GetChringSize(), 
				uint32(len(delta2)), 
				"BatchRealsUpdate (when there is no reals in Vip for first), its size must be equal to GetChringSize()")

	
	delta  = Global_vip1.BatchRealsUpdate(reals)
	delta2 = Global_vip2.BatchRealsUpdate(reals)

	assert.Equal(t,  
	 			0,
				len(delta),
				"BatchRealsUpdate (when there is already reals in Vip not for first), its size must be equal to 0")

	assert.Equal(t, 
	 			0,
				len(delta2),
				"BatchRealsUpdate (when there is already reals in Vip not for first), its size must be equal to 0")

	delta = Global_vip1.DelReal(0)
	delta2 = Global_vip2.DelReal(0)

	assert.Equal(t, 1020, len(delta), "delete the first real, its size must be equal to 1020")
	assert.Equal(t, 1020, len(delta2), "delete the first real, its size must be equal to 1020")
}


func TestBatchUpdateRealsWeight(t *testing.T) {
	SetUp()

	delta  := Global_vip1.BatchRealsUpdate(reals)
	delta2 := Global_vip2.BatchRealsUpdate(reals)

	 assert.Equal(t, 
			 	Global_vip1.GetChringSize(), 
				uint32(len(delta)), 
				"BatchRealsUpdate (when there is no reals in Vip for first), its size must be equal to GetChringSize()")
	
	assert.Equal(t, 
				Global_vip2.GetChringSize(), 
				uint32(len(delta2)), 
				"BatchRealsUpdate (when there is no reals in Vip for first), its size must be equal to GetChringSize()")



	delta  = Global_vip1.BatchRealsUpdate(reals)
	delta2 = Global_vip2.BatchRealsUpdate(reals)

	assert.Equal(t, 
	 			0,
				len(delta),
				"BatchRealsUpdate (when there is already reals in Vip not for first), its size must be equal to 0")

	assert.Equal(t, 
	 			0, 
				len(delta2), 
				"BatchRealsUpdate (when there is already reals in Vip not for first), its size must be equal to 0")


	for _, r := range reals {
		r.UpdateReal.Weight = 13
	}

	delta  = Global_vip1.BatchRealsUpdate(reals)
	delta2 = Global_vip2.BatchRealsUpdate(reals)

	assert.Equal(t, 0, len(delta2), "batch update reals, its size must be equal to 0")
	assert.Equal(t, 0, len(delta), "batch update reals, its size must be equal to 0")


	reals[0] = Structs.UpdateReal{Op: Structs.ADD, UpdateReal: Structs.Endpoint{Num: 0, Weight: 26, Hash: 0}}
	delta2 = Global_vip2.BatchRealsUpdate(reals)

	assert.Equal(t, 1445, len(delta2), "only update the first real of reals, its size must be equal to 1013")
}

func TestAddRemoveReal(t *testing.T) {
	vip := Vip.NewVip(1, 0, Structs.KDefaultChRingSize, 2)
	var real Structs.Endpoint
	real.Hash = 0
	real.Num = 0
	real.Weight = 1

	delta := vip.AddReal(real)
	assert.Equal(t, vip.GetChringSize(), uint32(len(delta)), "add one real, its size must be equal to chring size")

	real.Num = 1
	real.Hash = 1
	delta = vip.AddReal(real)
	assert.Equal(t, 32768, len(delta), "add another one real, its size must be equal to 32768")

	delta = vip.DelReal(1)
	assert.Equal(t, 32768, len(delta), "delete one real, its size must be equal to 32768")

	delta = vip.DelReal(1) //删除已经删除的
	assert.Equal(t, 0, len(delta), "delete one real which is not in vip, its size must be equal to 0")
}

func TestGetRealsAndWeight(t *testing.T) {
	SetUp()
	Global_vip2.BatchRealsUpdate(reals)
	endpoints := Global_vip2.GetRealsAndWeight()

	assert.Equal(t, 100, len(endpoints), "get endpoints, its size must be equal to 100")

	for _, r := range endpoints {
		assert.Equal(t, 10, int(r.Weight), "get endpoint, its weight must be equal to 10")
	}
}

func TestGetReals(t *testing.T) {
	SetUp()
	delta := Global_vip2.BatchRealsUpdate(reals)
	vip_reals := Global_vip2.GetReals()
	assert.Equal(t, 65537, len(delta), "get delta, its size must be equal to 100")
	assert.Equal(t, 100, len(vip_reals), "get vip_reals, its size must be equal to 65537")

	delta = Global_vip2.BatchRealsUpdate(reals) //没有变化
	assert.Equal(t, 0, len(delta), "get delta when no change reals, its size must be equal to 0")

	delta = Global_vip2.RecalculateHashRing(reals) //没有变化
	assert.Equal(t, 0, len(delta), "recalculateHashRing but no change reals, its size must be equal to 0")
}