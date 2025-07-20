package maglev

import (
	structs "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/Structs"
)

const (
	kHashSeed0 = 0
	kHashSeed1 = 2307
	kHashSeed2 = 42
	kHashSeed3 = 2718281828
)

func rotl64(x uint64, r uint8) uint64 {
	return (x << r) | (x >> (64 - r))
}

func MurmurHash3_x64_64(A uint64, B uint64, seed uint32) uint64 {

	var c1 uint64 = 0x87c37b91114253d5
	var c2 uint64 = 0x4cf5ad432745937f
	var b1 uint64 = 0xff51afd7ed558ccd
	var b2 uint64 = 0xc4ceb9fe1a85ec53

	h1 := uint64(seed)
	h2 := uint64(seed)

	k1 := A
	k2 := B

	k1 *= c1
	k1 = rotl64(k1, 31)
	k1 *= c2
	h1 ^= k1

	h1 = rotl64(h1, 27)
	h1 += h2
	h1 = h1*5 + 0x52dce729

	k2 *= c2
	k2 = rotl64(k2, 33)
	k2 *= c1
	h2 ^= k2

	h2 = rotl64(h2, 31)
	h2 += h1
	h2 = h2*5 + 0x38495ab5

	// 最终化
	h1 ^= 16
	h2 ^= 16

	h1 += h2
	h2 += h1

	h1 ^= h1 >> 33
	h1 *= b1
	h1 ^= h1 >> 33
	h1 *= b2
	h1 ^= h1 >> 33

	h2 ^= h2 >> 33
	h2 *= b1
	h2 ^= h2 >> 33
	h2 *= b2
	h2 ^= h2 >> 33

	h1 += h2

	return h1
}

/*
 * @brief: 生成maglev的偏好序列
 * @param: endpoint 后端节点的描述
 * @param: pos 当前位置
 * @param: ring_size 环的大小
 */
func genMaglevPermutation(permutation *[]uint32, endpoint *structs.Endpoint, pos uint32, ring_size uint32) {
	offset_hash := MurmurHash3_x64_64(endpoint.Hash, kHashSeed2, kHashSeed0)

	offset := offset_hash % uint64(ring_size)

	skip_hash := MurmurHash3_x64_64(endpoint.Hash, kHashSeed3, kHashSeed1)

	skip := (skip_hash % (uint64(ring_size) - 1)) + 1 //skip >= 1

	p := *permutation
	p[2*pos] = uint32(offset)
	p[2*pos+1] = uint32(skip)
}

/*
 * @brief: 生成hash环
 * @param: endpoints 后端节点的描述
 * @param: ring_size 环的大小(默认65535)
 * @return: hash环
 */
func GenerateHashRingV1(endpoints []structs.Endpoint, ring_size uint32) []int {
	result := make([]int, ring_size)
	for i := range result {
		result[i] = -1
	}

	if len(endpoints) == 0 {
		return result
	} else if len(endpoints) == 1 {
		for i := range result {
			result[i] = int(endpoints[0].Num)
		}
		return result
	}

	//计数器
	var runs uint32 = 0
	//每一个后端节点都有一个偏好序列
	permutation := make([]uint32, len(endpoints)*2)
	next := make([]uint32, len(endpoints))

	//生成偏好序列
	for i := 0; i < len(endpoints); i++ {
		genMaglevPermutation(&permutation, &endpoints[i], uint32(i), ring_size)
	}

	for {
		for i := 0; i < len(endpoints); i++ {
			offset := permutation[2*i]
			skip := permutation[2*i+1]
			for j := 0; j < int(endpoints[i].Weight); j++ {
				cur := (offset + next[i]*skip) % ring_size
				for result[cur] >= 0 {
					//说明这个位置有人
					next[i] += 1
					cur = (offset + next[i]*skip) % ring_size
				}
				result[cur] = int(endpoints[i].Num) //服务器序号
				next[i] += 1
				runs += 1
				//当计数器等于环的大小
				if runs == ring_size {
					return result
				}
			}
			//endpoints[i].Weight = 1
		}
	}
}

func GenerateHashRingV2(endpoints []structs.Endpoint, ring_size uint32) []int {
	result := make([]int, ring_size)
	for i := range result {
		result[i] = -1
	}
	if len(endpoints) == 0 {
		return result
	} else if len(endpoints) == 1 {
		for i := range result {
			result[i] = int(endpoints[0].Num)
		}
		return result
	}

	//这个max_weight变量用来限制权重
	var max_weight uint32 = 0
	//找到最大的权重
	for _, v := range endpoints {
		if v.Weight > max_weight {
			max_weight = v.Weight
		}
	}

	//计数器
	var runs uint32
	//每一个后端节点都有一个偏好序列
	permutation := make([]uint32, len(endpoints)*2)
	next := make([]uint32, len(endpoints))
	csum_weight := make([]uint32, len(endpoints))

	//生成每个后端节点的偏好序列
	for i := 0; i < len(endpoints); i++ {
		genMaglevPermutation(&permutation, &endpoints[i], uint32(i), ring_size)
	}

	for { //大循环，权重小的会在后面处理，直到所有节点都被处理
		for i := 0; i < len(endpoints); i++ {
			csum_weight[i] += endpoints[i].Weight
			if csum_weight[i] >= max_weight {
				csum_weight[i] -= max_weight
				offset := permutation[2*i]
				skip := permutation[2*i+1]
				cur := (offset + next[i]*skip) % ring_size

				for result[cur] >= 0 {
					next[i] += 1 //不断地加步长
					cur = (offset + next[i]*skip) % ring_size
				}
				result[cur] = int(endpoints[i].Num)
				next[i] += 1
				runs += 1
				if runs == ring_size {
					return result
				}
			}
		}
	}
}
