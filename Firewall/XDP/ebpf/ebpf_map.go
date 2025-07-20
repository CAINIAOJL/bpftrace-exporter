package XDP

import(
	"fmt"
	"github.com/cilium/ebpf"
	Log "github.com/CAINIAOJL/bpftrace-exporter/Firewall/XDP/log"
)

func CreateNewInnerMap(mapType ebpf.MapType, KeySize uint32, ValueSize uint32, Max_Entires uint32, Flag uint32)(*ebpf.Map){
	child_map := &ebpf.MapSpec{
		Type: mapType,
		KeySize: KeySize,
		ValueSize: ValueSize,
		MaxEntries: Max_Entires,
		Flags:  Flag,
	}
	inner_map, err := ebpf.NewMap(child_map)
	if err != nil {
		Log.LogV(fmt.Sprintf("【CreateNewInnerMap】error when creating inner Map, which called %s, error: %s",ebpf.MapType.String(mapType), err.Error()), 3)
		return nil
	}
	return inner_map
}

func Lookup_Map(obj *ebpf.Collection, Map_name string) *ebpf.Map {
	ebpf_map := obj.Maps[Map_name]
		if ebpf_map == nil {
			Log.LogV(fmt.Sprintf("【Lookup_Map】error when finding Map which called %s", Map_name), 3)
			return nil
		}
	return ebpf_map
}