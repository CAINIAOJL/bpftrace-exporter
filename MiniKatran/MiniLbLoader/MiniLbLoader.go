package minilbloader

import (
	"log"

	"github.com/cilium/ebpf"
)

const (
	kError = 1
	kNotExists = -1
	kSuccess = 0
	kMaxSharedMapNameSize = 15
)

type CurrentMaps struct {
    // 修改字段类型为 map[string]map[string]bool
    CurrentMaps_ map[string]map[string]bool
}

type MiniLbLoader struct { 
	Maps_ map[string]*ebpf.Map 
	Progs_ map[string]int

	//sharedMaps_ map[string]int
	InnerMapsProto_ map[string]int
	BpfObj map[string] *ebpf.Collection
	CurrentMaps_ CurrentMaps
	//KnownDuplicateMaps_ map[string]bool
}

func NewMiniLbLoader() *MiniLbLoader {
	return &MiniLbLoader{
		Maps_: make(map[string]*ebpf.Map),
		Progs_: make(map[string]int),
		InnerMapsProto_: make(map[string]int),
		BpfObj: make(map[string] *ebpf.Collection),
		CurrentMaps_: CurrentMaps{CurrentMaps_: make(map[string]map[string]bool)},
		//KnownDuplicateMaps_: make(map[string]bool),
	}
}

func (ld *MiniLbLoader) LoadBpfFile(path string, use_name bool) int {
	obj, err := ebpf.LoadCollection(path)
	if err != nil {
		log.Printf("Error while opening bpf object: %v", path)
		ld.closeBpfObject(obj)
		return kError
	}

	return ld.loadBpfObject(obj, path)
}

func (ld *MiniLbLoader) closeBpfObject(obj *ebpf.Collection) int {
	obj.Close()
	return  kError
}

//第一次加载ebpf程序
func (ld *MiniLbLoader) loadBpfObject(obj *ebpf.Collection, objName string) int {
	_, ok := ld.BpfObj[objName]
	if ok {
		log.Printf("collision while trying to load bpf object: %v", objName)
		return ld.closeBpfObject(obj)
	}

	for name := range obj.Programs {
		if _, ok :=ld.Progs_[name]; ok {
			log.Printf("bpf's program name collision: %v", name)
			return ld.closeBpfObject(obj)
		}
	}
	//缺少KnownDuplicateMaps_
	//for name, m := range obj.Maps {
		//if _, ok := ld.Maps_[name]; ok {
			//log.Printf("bpf's map name collision - %v", name)
			//return  ld.closeBpfObject(obj)
		//}

		//if fd, ok := ld.InnerMapsProto_[name]; ok {
			//log.Printf("setting inner id for map-in-map: %v fd: %v", name, fd)
			
		//}
	//}
	var loadedProgNames []string
	var loadedMapNames []string

	for n, prog := range obj.Programs {
		ld.Progs_[n] = prog.FD()
		loadedProgNames = append(loadedProgNames, n)
	}

	for n, m := range obj.Maps {
		ld.Maps_[n] = m
		loadedMapNames = append(loadedMapNames, n)
	}

	for _, n := range loadedProgNames {
		if _, exists := ld.CurrentMaps_.CurrentMaps_[n]; !exists {
        	ld.CurrentMaps_.CurrentMaps_[n] = make(map[string]bool)
    	}
		for _, m := range loadedMapNames {
			ld.CurrentMaps_.CurrentMaps_[n][m] = true
		}
	}
	
	ld.BpfObj[objName] = obj
	return kSuccess
}

/*func (ld *MiniLbLoader) GetMapFdByName(name string) int {
	m, ok := ld.Maps_[name]
	if !ok {
		log.Printf("Can't find prog with name: %v", name)
		return kNotExists
	}
	return m
}*/

func (ld *MiniLbLoader) GetMapByName(name string) *ebpf.Map {
	m, ok := ld.Maps_[name]
	if !ok {
		log.Printf("Can't find map with name: %v", name)
		return nil
	}
	return m
}

func (ld *MiniLbLoader) GetProgFdByName(name string) int {
  	m, ok := ld.Progs_[name]
  	if !ok {
    	log.Printf("Can't find prog with name: %v", name)
    	return kNotExists
  	}
  	return m
}

func (ld *MiniLbLoader) IsMapInProg(progname string, name string) bool {
	progmaps, ok:= ld.CurrentMaps_.CurrentMaps_[progname]
	if !ok {
		return false
	}
	_, ok = progmaps[name]
	if !ok {
		return false
	}
	return true
}

func (ld *MiniLbLoader) SetInnerMapPrototype(name string, fd int) int {
	if _, ok := ld.InnerMapsProto_[name]; ok {
		log.Printf("map-in-map prototype's name collision")
		return kError
	}
	ld.InnerMapsProto_[name] = fd
	return kSuccess
} 