package vip

import (
	"sort"

	Maglev "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/Maglev"
	Structs "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/Structs"
)

type Vip struct {
	VipNum_   			uint32
	VipFlags_  			uint32
	ChRingSize_  		uint32
	RealsToVipMeta  	map[uint32]Structs.VipRealMeta
	ChRing_             []int
	Maglev_             int
}

func NewVip(vipNum uint32, vipFlags uint32, ringsize uint32, MaglevOp int) (*Vip){
	v := Vip{
		VipNum_: vipNum,
		VipFlags_: vipFlags,
	}
	if ringsize == 0 {
		v.ChRingSize_ = Structs.KDefaultChRingSize
	} else {
		v.ChRingSize_ = ringsize
	}
	var i uint32
	for i = 0; i < v.ChRingSize_; i++ {
		v.ChRing_ = append(v.ChRing_, -1)
	}
	v.Maglev_ = MaglevOp
	v.RealsToVipMeta = make(map[uint32]Structs.VipRealMeta)
	return &v
}

func (vip *Vip) SetMaglevOp(MaglevOp int) {
	vip.Maglev_ = MaglevOp
}

func (vip *Vip) GetVipNum() uint32 {
	return vip.VipNum_
}

func (vip *Vip) GetVipFlags() uint32 {
	return vip.VipFlags_
}

func (vip *Vip) SetVipFlags(flags uint32) {
	vip.VipFlags_ |= flags
}

func (vip *Vip) UnsetVipFlags(flags uint32) {
	vip.VipFlags_ &= ^flags
}

func (vip *Vip) ClearVipFlags(flags uint32) {
	vip.VipFlags_ = 0
}

func (vip *Vip) GetChringSize() uint32 {
	return vip.ChRingSize_
}

func (vip *Vip) GetReals() []uint32 {
	realNums := make([]uint32, len(vip.RealsToVipMeta))
	i := 0
	for _, r := range vip.RealsToVipMeta {
		realNums[i] = r.Weight
		i++
	}
	return realNums
}

func (vip *Vip) GetRealsAndWeight() []Structs.Endpoint {
	endpoints := make([]Structs.Endpoint, len(vip.RealsToVipMeta))

	endpoint := Structs.Endpoint{}

	i := 0
	for num, r := range vip.RealsToVipMeta {
		endpoint.Hash = r.Hash
		endpoint.Num = num
		endpoint.Weight = r.Weight
		endpoints[i] = endpoint
		i++
	}

	sort.Slice(endpoints, func(i, j int) bool {
		return uint32(endpoints[i].Hash) < uint32(endpoints[j].Hash)
	})
	return endpoints
}

func (vip *Vip) GetEndpoints(ureals []Structs.UpdateReal) []Structs.Endpoint {
	var endpoint Structs.Endpoint
	res := []Structs.Endpoint{}
	
	is_change := false

	for _, ureal := range ureals {
		if ureal.Op == Structs.DEL {
			delete(vip.RealsToVipMeta, ureal.UpdateReal.Num)
			is_change = true
		} else {
			realMeta:= vip.RealsToVipMeta[ureal.UpdateReal.Num]
			cur_weight := realMeta.Weight
			
			if cur_weight != ureal.UpdateReal.Weight {
				realMeta.Weight = ureal.UpdateReal.Weight
				realMeta.Hash = ureal.UpdateReal.Hash
				vip.RealsToVipMeta[ureal.UpdateReal.Num] = realMeta
				is_change = true
			}
		}
	}

	if is_change  {
		for num, r := range vip.RealsToVipMeta {
			if r.Weight != 0 {
				endpoint.Num = num
				endpoint.Hash = r.Hash
				endpoint.Weight = r.Weight
				res = append(res, endpoint)
			}
		}
		sort.Slice(res, func(i, j int) bool {
    		return res[i].Num < res[j].Num
		})
	}
	return res
}

func (vip *Vip) calculateHashRing(endpoints []Structs.Endpoint) []Structs.RealPos {
	var delta []Structs.RealPos
	var new_pos Structs.RealPos
	if len(endpoints) != 0 {
		var new_ch_ring []int
		if vip.Maglev_ == 1 {
			new_ch_ring = Maglev.GenerateHashRingV1(endpoints, vip.ChRingSize_)
		} else {
			new_ch_ring = Maglev.GenerateHashRingV2(endpoints, vip.ChRingSize_)
		}

		for i := 0; i < int(vip.ChRingSize_); i++ {
			if new_ch_ring[i] != int(vip.ChRing_[i]) {
				new_pos.Pos = uint32(i)
				new_pos.Real = uint32(new_ch_ring[i]) //对比差异的地方
				delta = append(delta, new_pos)
				vip.ChRing_[i] = new_ch_ring[i]
			}
		}
	}
	return delta
}

//只得到差异的部分
func (vip *Vip) BatchRealsUpdate(ureals []Structs.UpdateReal) []Structs.RealPos {
	endpoints := vip.GetEndpoints(ureals)
	return vip.calculateHashRing(endpoints)
}

//完整重新计算
func (vip *Vip) RecalculateHashRing(ureals []Structs.UpdateReal) []Structs.RealPos {
	endpoints := vip.GetRealsAndWeight()
	return vip.calculateHashRing(endpoints)
}

func (vip *Vip) AddReal(real Structs.Endpoint) []Structs.RealPos {
	reals := []Structs.UpdateReal{}
	ureal := Structs.UpdateReal{}
	ureal.Op = Structs.ADD
	ureal.UpdateReal = real
	reals = append(reals, ureal)
	return vip.BatchRealsUpdate(reals)
}

func (vip *Vip) DelReal(realNum uint32) []Structs.RealPos {
	reals := []Structs.UpdateReal{}
	ureal := Structs.UpdateReal{}
	ureal.Op = Structs.DEL
	ureal.UpdateReal.Num = realNum
	reals = append(reals, ureal)
	return vip.BatchRealsUpdate(reals)
}