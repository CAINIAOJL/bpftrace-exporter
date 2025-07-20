package iphelper

import (
	"encoding/binary"
	"fmt"
	"net"
)

/* c.
struct real_definition {
    __be32 dst;
    __be32 dstv6[4];
    __u8 flags;
};
*/
type BeAddr struct {
	Dst     	 uint32	
	Dstv6		 [4]uint32 
	Flags      	 uint8
	Padding    	 [3]byte   
}

type IPHelpers struct{}

const (

	Uint32Bytes = 4

	V6DADDR = 1
)

func (ip IPHelpers) ParseAddrToBe(addr string, bigEndian bool) (BeAddr, error) {
	ipAddr := net.ParseIP(addr)
	if ipAddr == nil {
		return BeAddr{}, fmt.Errorf("无效的IP地址: %s", addr)
	}
	return ip.parseIPToBe(ipAddr, bigEndian), nil
}


func (ip IPHelpers) ParseAddrToInt(addr string) (BeAddr, error) {
	return ip.ParseAddrToBe(addr, false)
}

func (ip IPHelpers) parseIPToBe(addr net.IP, bigEndian bool) BeAddr {
	var result BeAddr
	
	if ip4 := addr.To4(); ip4 != nil {
		result.Flags = 0
		if bigEndian {
			result.Dst = binary.BigEndian.Uint32(ip4)
		} else {
			result.Dst = binary.LittleEndian.Uint32(ip4)
		}
	} else {
		ip16 := addr.To16()
		for i := 0; i < 4; i++ {
			offset := i * 4
			bytes := ip16[offset : offset+4]
			
			if bigEndian {
				result.Dstv6[i] = binary.BigEndian.Uint32(bytes)
			} else {
				result.Dstv6[i] = binary.LittleEndian.Uint32(bytes)
			}
		}
		result.Flags = V6DADDR
	}
	
	return result
}