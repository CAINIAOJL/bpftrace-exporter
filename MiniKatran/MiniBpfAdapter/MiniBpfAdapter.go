package minibpfadapter

import(
	"log"
	//"golang.org/x/sys/unix"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/ebpf"
	Structs "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/Structs"
	MiniLbLoader "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/MiniLbLoader"
)


type MiniBpfAdapter struct {
	Loader  			*MiniLbLoader.MiniLbLoader
	BatchOpsEnables 	bool
}

func NewMiniBpfAdapter(set_limit bool, enableBatchOpsIfSupported bool) *MiniBpfAdapter {
	if set_limit {
		if err := rlimit.RemoveMemlock(); err != nil {
			log.Fatal("Can't change limit for locked memory!")
		}
	}
	
	return &MiniBpfAdapter{
		Loader: MiniLbLoader.NewMiniLbLoader(),
		BatchOpsEnables: false,
	}
}

func (ba *MiniBpfAdapter) LoadBpfProg(bpf_prog string) int {
	return ba.Loader.LoadBpfFile(bpf_prog, false)
}

func (ba *MiniBpfAdapter) GetMapByName(name string) *ebpf.Map {
  return ba.Loader.GetMapByName(name)
}

//后面再来实现
//func (ba *MiniBpfAdapter) SetInnerMapPrototype(name string, map_fd int) {
  //return loader_.setInnerMapPrototype(name, map_fd);
//}

func (ba *MiniBpfAdapter) GetProgFdByName() int {
  return ba.Loader.GetProgFdByName(Structs.KBalancerProgName);
}

func (ba *MiniBpfAdapter) IsMapInProg(progname string, name string) bool {
	return ba.Loader.IsMapInProg(progname, name)
}

func (ba *MiniBpfAdapter) BpfUpdateMap(Map *ebpf.Map, key interface{}, value interface{}, flags uint64) int {
	//log.Print(map_fd)
	//M, err := ebpf.NewMapFromID(ebpf.MapID(map_fd)) //更改
	/*M, err := ebpf.NewMapFromFD(map_fd) //更改
	if err != nil {
		log.Printf("1 NewMapFromID error: %v", err.Error())
		return -1
	}*/

	ok := Map.Update(key, value, ebpf.MapUpdateFlags(flags))
	if ok != nil {
		log.Printf("Update error: %v", ok.Error())
		return -1
	}
	return 0
}

func (ba *MiniBpfAdapter) getBpfMapInfo(Map *ebpf.Map) *ebpf.MapInfo {
	/*M, err:= ebpf.NewMapFromID(ebpf.MapID(map_fd))
	if err != nil {
		return nil
	}*/
	info, err := Map.Info()
	if err != nil{
		log.Printf("getBpfMapInfo error: %v", err.Error())
	}
	return info
}

func (ba *MiniBpfAdapter) BpfUpdateMapBatch(Map *ebpf.Map, key []uint32, values []uint32, count uint32) int {
	if ba.BatchOpsEnables {
		//批更新
		/*_, err := unix.FcntlInt(uintptr(map_fd), unix.F_GETFD, 0)
		if err != nil {
			log.Printf("unix fcntInt err: %v", err)
		}
		log.Printf("map_fd is %v", map_fd)
		M, err:= ebpf.NewMapFromFD(map_fd) //修改
		if err != nil {
			log.Printf("2 NewMapFromID error: %v", err.Error())
			return -1
		}*/
		log.Printf("batchUpdate start")
		res, err := Map.BatchUpdate(key, values, &ebpf.BatchOptions{
			ElemFlags: 0,
			Flags: 0,
		})
		if err != nil {
			log.Printf("BatchUpdate error: %v ! ", err.Error())
			return -1
		}
		if res != int(count) {
			log.Printf("BatchUpdate res != count !")
			return -1
		}
	} else {
		//info := ba.getBpfMapInfo(Map)
		var i uint32
		for i = 0; i < count; i++ {
			res := ba.BpfUpdateMap(Map, 
										key[i], 
										values[i], 0)
			if res != 0 {
				return -1
			}
		}
	}
	return 0
}

func (ba *MiniBpfAdapter) BpfMapDeleteElement(Map *ebpf.Map, key interface{}) int {
	/*M, err := ebpf.NewMapFromID(ebpf.MapID(map_fd))
	if err != nil {
		log.Printf("3 NewMapFromID error: %v", err.Error())
		return -1
	}*/
	err := Map.Delete(key)
	if err != nil {
		log.Printf("Error while deleting key from map! ")
		return -1
	}
	return 0
}

//记住，value传递指针
func (ba *MiniBpfAdapter) BpfMapLookupElement(Map *ebpf.Map, key interface{}, value interface{}, flags uint64) int { 
	/*M, err := ebpf.NewMapFromID(ebpf.MapID(map_fd))
	if err != nil {
		log.Printf("4 NewMapFromID error: %v", err.Error())
		return -1
	}*/

	res := Map.Lookup(key, value)
	if res != nil {
		log.Printf("Error while geting value from map: %v", res.Error())
		return -1
	}
	return 0
}

func (ba *MiniBpfAdapter) CreateNameBpfMap(name string, kind int, key_size int, value_size int, max_entries int, map_flags int, numa_node int) int {
	var fd *ebpf.Map
	var err error
	log.Printf("name %v kind %v key %v value %v max_entries %v map_flags %v numa_node %v", name, kind, key_size, value_size, max_entries, map_flags, numa_node)
	if numa_node == -1 {
		fd, err = ebpf.NewMap(&ebpf.MapSpec{
			Name: name,
			Type: ebpf.MapType(kind),
			Flags: uint32(map_flags),
			KeySize: uint32(key_size),
			ValueSize: uint32(value_size),
			MaxEntries: uint32(max_entries),
		})
	} else {
		fd, err = ebpf.NewMap(&ebpf.MapSpec{
			Name: name,
			Type: ebpf.MapType(kind),
			Flags: uint32(map_flags),
			NumaNode: uint32(numa_node),
			KeySize: uint32(key_size),
			ValueSize: uint32(value_size),
			MaxEntries: uint32(max_entries),
		})
	}
	if err != nil {
		log.Printf("Error while creating map: %v", err)
		return -1
	}
	return fd.FD()
}

func (ba *MiniBpfAdapter) SetInnerMapPrototype(name string, fd int) int {
	return ba.Loader.SetInnerMapPrototype(name, fd)
}

func (ba *MiniBpfAdapter) GetMiniKatranProgFd(name string) int {
	return ba.Loader.GetProgFdByName(name)
}

func (ba *MiniBpfAdapter) TestXdpProg(option *ebpf.RunOptions, target *ebpf.Program) int {
	prog := &ebpf.ProgramSpec{
		Name: "Test Balancer program",
		Type: ebpf.XDP,
		AttachType: ebpf.AttachXDP,
		AttachTarget: target,
		//License: "GPL",
		SectionName: "xdp",
		AttachTo: "lo",
	}

	//测试选项
	if res, err := prog.AttachTarget.Run(option); err != nil {
		return -1
	} else {
		return int(res)
	}
}