package minikatrangrpcservice

import (
	"context"
	"errors"
	"log"
	"sync"

	lb_MiniKatran "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/Example/goclient/MiniKatranC/lb_MiniKatran"
	MacHelper "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/MacHelpers"
	MiniLbLoader "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/MiniLB"
	Structs "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/Structs"
)

type MiniKatranGrpcService struct {
	lb_MiniKatran.UnimplementedMiniKatranServiceServer
	Lb_ *MiniLbLoader.MiniLb
	Mutex sync.Mutex
	//HcForwarding_ bool
}

// NewKatranGrpcService 创建服务实例
func NewKatranGrpcService(config *Structs.MiniKatranConfig) *MiniKatranGrpcService {
    GrpcService := &MiniKatranGrpcService{
		Lb_: MiniLbLoader.NewMiniKatran(config),
    }
	if ok := GrpcService.Lb_.LoadBpfProgs(); !ok {
		log.Print("loadProgs failed")
	}
	if ok := GrpcService.Lb_.AttachBpfProgs(GrpcService.Lb_.MiniKatranConfig.BalancerProgPath); !ok {
		log.Print("attachProgs failed")
	}
	return GrpcService
}

func translateVipObject(vip *lb_MiniKatran.Vip) Structs.VipKey  {
  var vk Structs.VipKey
  vk.Address = vip.Address
  vk.Proto = uint8(vip.Protocol)
  vk.Port = uint16(vip.Port)
  return vk
}

func translateQuicRealObject(quicReal *lb_MiniKatran.QuicReal) Structs.QuicReal{
	var qr Structs.QuicReal
	qr.Address = quicReal.Address
	qr.Id = uint32(quicReal.Id)
	return qr
}

func translateRealObject(real *lb_MiniKatran.Real) Structs.NewReal {
	var nr Structs.NewReal
	nr.Address = real.Address
	nr.Flags = uint8(real.Flags)
	nr.Weight = uint32(real.Weight)
	return nr
}

func (Ms *MiniKatranGrpcService) ChangeMac(context context.Context, request *lb_MiniKatran.Mac) (*lb_MiniKatran.Bool, error) {
	Ms.Mutex.Lock()
	defer Ms.Mutex.Unlock()

	machelpers := MacHelper.MacHelper{}
	mac := machelpers.ConvertMacToUint(request.GetMac())
	if res := Ms.Lb_.ChangeMac(mac); !res {
		//Ms.Mutex.Unlock()
		return &lb_MiniKatran.Bool{Success: false}, errors.New("Failed to change mac")
	}
	return &lb_MiniKatran.Bool{Success: true}, nil
}

func (Ms *MiniKatranGrpcService) GetMac(context context.Context, request *lb_MiniKatran.Empty) (*lb_MiniKatran.Mac, error) {
	Ms.Mutex.Lock()
	defer Ms.Mutex.Unlock()

	mac := Ms.Lb_.GetMac()
	machelpers := MacHelper.MacHelper{}
	macAddress := machelpers.ConvertMacToString(mac[:])
	return &lb_MiniKatran.Mac{Mac: macAddress}, nil
}

func (Ms *MiniKatranGrpcService) AddVip(context context.Context, request *lb_MiniKatran.VipMeta) (*lb_MiniKatran.Bool, error) {
	vk := translateVipObject(request.GetVip())

	Ms.Mutex.Lock()
	defer Ms.Mutex.Unlock()

	if res := Ms.Lb_.AddVip(&vk, uint32(request.GetFlags())); !res {
		return &lb_MiniKatran.Bool{Success: false}, errors.New("Add vip failed !")
	}
	return &lb_MiniKatran.Bool{Success: true}, nil
}

func (Ms *MiniKatranGrpcService) DelVip(context context.Context, request *lb_MiniKatran.Vip) (*lb_MiniKatran.Bool, error) {
	vk := translateVipObject(request)

	Ms.Mutex.Lock()
	defer Ms.Mutex.Unlock()

	if res := Ms.Lb_.DelVip(&vk); !res {
		return &lb_MiniKatran.Bool{Success: false}, errors.New("Delete vip failed !")
	}
	return &lb_MiniKatran.Bool{Success: true}, nil
}

func (Ms *MiniKatranGrpcService) GetAllVips(context context.Context, request *lb_MiniKatran.Empty) (*lb_MiniKatran.Vips, error) {
	Vips := &lb_MiniKatran.Vips{
		Vips: make([]*lb_MiniKatran.Vip, len(Ms.Lb_.GetAllVips())),
	}

	Ms.Mutex.Lock()
	defer Ms.Mutex.Unlock()

	vips := Ms.Lb_.GetAllVips()
	for i := 0; i < len(vips); i++ {
		vip := &lb_MiniKatran.Vip{
			Address: vips[i].Address,
			Port: int32(vips[i].Port),
			Protocol: int32(vips[i].Proto),
		}
		Vips.Vips[i] = vip
	}

	return Vips, nil
}

func (Ms *MiniKatranGrpcService) ModifyVip(context context.Context, request *lb_MiniKatran.VipMeta) (*lb_MiniKatran.Bool, error) {
	vk := translateVipObject(request.GetVip())

	Ms.Mutex.Lock()
	defer Ms.Mutex.Unlock()

	if res := Ms.Lb_.ModifyVip(&vk, uint32(request.GetFlags()), request.GetSetFlag()); !res {
		return &lb_MiniKatran.Bool{Success: false}, errors.New("Modify vip failed !")
	}
	return &lb_MiniKatran.Bool{Success: true}, nil
}

func (Ms *MiniKatranGrpcService) ModifyReal(context context.Context, request *lb_MiniKatran.RealMeta) (*lb_MiniKatran.Bool, error) {
	Ms.Mutex.Lock()
	defer Ms.Mutex.Unlock()
	
	if res := Ms.Lb_.ModifyReal(request.GetAddress(), uint8(request.GetFlags()), request.GetSetFlag()); !res {
		return &lb_MiniKatran.Bool{Success: false}, errors.New("Modify real failed !")
	}
	return &lb_MiniKatran.Bool{Success: true}, nil
}

func (Ms *MiniKatranGrpcService) GetVipFlags(context context.Context, request *lb_MiniKatran.Vip) (*lb_MiniKatran.Flags, error) {
	vk := translateVipObject(request)

	Ms.Mutex.Lock()
	defer Ms.Mutex.Unlock()

	flags, ok := Ms.Lb_.GetVipFlags(&vk) 
	if ok == -1 {
		return &lb_MiniKatran.Flags{Flags: 0}, errors.New("vip not found, flags: -1, but 0")

	}
	return &lb_MiniKatran.Flags{Flags: uint64(flags)}, nil
}

func (Ms *MiniKatranGrpcService) AddRealForVip(context context.Context, request *lb_MiniKatran.RealForVip) (*lb_MiniKatran.Bool, error) {
	vk := translateVipObject(request.GetVip())
	nr := translateRealObject(request.GetReal())

	Ms.Mutex.Lock()
	defer Ms.Mutex.Unlock()
	
	if res := Ms.Lb_.AddRealForVip(&nr, &vk); !res {
		return &lb_MiniKatran.Bool{Success: false}, errors.New("AddRealForVip failed !")
	}
	return &lb_MiniKatran.Bool{Success: true}, nil
}


func (Ms *MiniKatranGrpcService) DelRealForVip(context context.Context, request *lb_MiniKatran.RealForVip) (*lb_MiniKatran.Bool, error) {
	vk := translateVipObject(request.GetVip())
	nr := translateRealObject(request.GetReal())

	Ms.Mutex.Lock()
	defer Ms.Mutex.Unlock()

	if res := Ms.Lb_.DelRealForVip(&nr, &vk); !res {
		return &lb_MiniKatran.Bool{Success: false}, errors.New("DelRealForVip failed !")
	}
	return &lb_MiniKatran.Bool{Success: true}, nil
}


func (Ms *MiniKatranGrpcService) ModifyRealsForVip(context context.Context, request *lb_MiniKatran.ModifiedRealsForVip) (*lb_MiniKatran.Bool, error) {
	var action int
	var nreals []Structs.NewReal
	switch request.GetAction() {
	case Structs.ADD:
		action = Structs.ADD
		break
	case Structs.DEL:
		action = Structs.DEL
		break
	default:
		break
	}

	vk := translateVipObject(request.GetVip())

	for i := 0; i < len(request.Real.Reals); i++ {
		nr := translateRealObject(request.GetReal().Reals[i])
		nreals = append(nreals, nr)
	}	

	Ms.Mutex.Lock()
	defer Ms.Mutex.Unlock()

	if res := Ms.Lb_.ModifyRealsForVip(action, &nreals, &vk); !res {
		return &lb_MiniKatran.Bool{Success: false}, errors.New("ModifyRealsForVip failed !")
	}

	return &lb_MiniKatran.Bool{Success: true}, nil
}

func (Ms *MiniKatranGrpcService) GetRealsForVip(context context.Context, request *lb_MiniKatran.Vip) (*lb_MiniKatran.Reals, error) {
	var reals []Structs.NewReal
	vk := translateVipObject(request)
	Ms.Mutex.Lock()
	defer Ms.Mutex.Unlock()
	reals = Ms.Lb_.GetRealsForVip(&vk)

	ret := &lb_MiniKatran.Reals{
		Reals: make([]*lb_MiniKatran.Real, len(reals)),
	}

	for id, real := range reals {
		r := &lb_MiniKatran.Real{
			Address: real.Address,
			Flags: int32(real.Flags),
			Weight: int32(real.Weight),
		}
		ret.Reals[id] = r
	}
	return ret, nil
}

func (Ms *MiniKatranGrpcService) ModifyQuicRealsMapping(context context.Context, request *lb_MiniKatran.ModifiedQuicReals) (*lb_MiniKatran.Bool, error) {
	var action int
	var qreals []Structs.QuicReal
	switch request.GetAction() {
	case Structs.ADD:
		action = Structs.ADD
		break
	case Structs.DEL:
		action = Structs.DEL
		break
	default:
		break		
	}

	for i := 0; i < len(request.Reals.Qreals); i++ {
		qr := translateQuicRealObject(request.GetReals().Qreals[i])
		qreals = append(qreals, qr)
	}

	Ms.Mutex.Lock()
	defer Ms.Mutex.Unlock()
	if res := Ms.Lb_.ModifyQuicRealsMapping(action, &qreals); !res {
		return &lb_MiniKatran.Bool{Success: false}, errors.New("ModifyQuicRealsMapping failed !")
	}
	return &lb_MiniKatran.Bool{Success: true}, nil
}

func (Ms *MiniKatranGrpcService) GetQuicRealsMapping(context context.Context, request *lb_MiniKatran.Empty) (*lb_MiniKatran.QuicReals, error) {
	var qreals []Structs.QuicReal

	Ms.Mutex.Lock()
	defer Ms.Mutex.Unlock()
	qreals = Ms.Lb_.GetQuicRealsMapping()
	ret := &lb_MiniKatran.QuicReals{
		Qreals: make([]*lb_MiniKatran.QuicReal, len(qreals)),
	}
	for _, qreal := range qreals {
		qr := &lb_MiniKatran.QuicReal{
			Address: qreal.Address,
			Id: int32(qreal.Id),
		}
		ret.Qreals = append(ret.Qreals, qr)
	}
	return ret, nil

}

func (Ms *MiniKatranGrpcService) GetStatsForVip(context context.Context, request *lb_MiniKatran.Vip) (*lb_MiniKatran.Stats, error) {
	vk := translateVipObject(request)

	Ms.Mutex.Lock()
	defer Ms.Mutex.Unlock()
	stats := Ms.Lb_.GetStatsForVip(&vk)

	ret := &lb_MiniKatran.Stats{
		V1: stats.V1,
		V2: stats.V2,
	}
	return ret, nil
}

func (Ms *MiniKatranGrpcService) GetLruStats(context context.Context, request *lb_MiniKatran.Empty) (*lb_MiniKatran.Stats, error) {
	Ms.Mutex.Lock()
	defer Ms.Mutex.Unlock()
	stats := Ms.Lb_.GetLruStats()

	ret := &lb_MiniKatran.Stats{
		V1: stats.V1,
		V2: stats.V2,
	}
	return ret, nil
}

func (Ms *MiniKatranGrpcService) GetLruMissStats(context context.Context, request *lb_MiniKatran.Empty) (*lb_MiniKatran.Stats, error) {
	Ms.Mutex.Lock()
	defer Ms.Mutex.Unlock()
	stats := Ms.Lb_.GetLruMissStats()

	ret := &lb_MiniKatran.Stats{
		V1: stats.V1,
		V2: stats.V2,
	}
	return ret, nil
}

func (Ms *MiniKatranGrpcService) GetLruFallbackStats(context context.Context, request *lb_MiniKatran.Empty) (*lb_MiniKatran.Stats, error) {
	Ms.Mutex.Lock()
	defer Ms.Mutex.Unlock()
	stats := Ms.Lb_.GetLruFallbackStats()

	ret := &lb_MiniKatran.Stats{
		V1: stats.V1,
		V2: stats.V2,
	}
	return ret, nil
}
func (Ms *MiniKatranGrpcService) GetIcmpTooBigStats(context context.Context, request *lb_MiniKatran.Empty) (*lb_MiniKatran.Stats, error) {
	Ms.Mutex.Lock()
	defer Ms.Mutex.Unlock()
	stats := Ms.Lb_.GetIcmpTooBigStats()

	ret := &lb_MiniKatran.Stats{
		V1: stats.V1,
		V2: stats.V2,
	}
	return ret, nil
}