package iphelper_test

import (
	"testing"

	IpHelper "github.com/CAINIAOJL/bpftrace-exporter/MiniKatran/IpHelper"
	"github.com/stretchr/testify/assert"
)

func TestV4ParsingBe(t *testing.T) {
	iphelper := IpHelper.IPHelpers{}
	addr, err := iphelper.ParseAddrToBe("1.1.1.2", true)
	if err != nil {
		t.Logf("ParseAddrToBe error: %v", err.Error())
	}
	assert.Equal(t, uint8(0), addr.Flags)
	assert.Equal(t, uint32(16843010), addr.Dst)
}

func TestV4ParsingInt(t *testing.T) {
	iphelper := IpHelper.IPHelpers{}
	addr, err := iphelper.ParseAddrToInt("1.1.1.2")
	if err != nil {
		t.Logf("ParseAddrToInt error: %v", err.Error())
	}
	assert.Equal(t, uint8(0), addr.Flags)
	assert.Equal(t, uint32(33620225), addr.Dst)
}

func TestV6ParseingBe(t *testing.T) {
	iphelper := IpHelper.IPHelpers{}
	addr, err := iphelper.ParseAddrToBe("2401:db00:f01c:2002:face:0:d:0", true)
	if err != nil {
		t.Logf("ParseAddrToBe error: %v", err.Error())
	}
	assert.Equal(t, uint8(1), addr.Flags)
	//大端序
	assert.Equal(t, uint32(0x2401db00), addr.Dstv6[0])
	assert.Equal(t, uint32(0xf01c2002), addr.Dstv6[1])
	assert.Equal(t, uint32(0xface0000), addr.Dstv6[2])
	assert.Equal(t, uint32(0x000d0000), addr.Dstv6[3])
}

func TestV6ParseingInt(t *testing.T) {
	iphelper := IpHelper.IPHelpers{}
	addr, err := iphelper.ParseAddrToInt("2401:db00:f01c:2002:face:0:d:0")
	if err != nil {
		t.Logf("ParseAddrToBe error: %v", err.Error())
	}
	assert.Equal(t, uint8(1), addr.Flags)
	//小端序
	assert.Equal(t, uint32(0x00db0124), addr.Dstv6[0]) // 14352676
	assert.Equal(t, uint32(0x02201cf0), addr.Dstv6[1]) // 35658992
	assert.Equal(t, uint32(0x0000cefa), addr.Dstv6[2]) // 52986
	assert.Equal(t, uint32(0x00000d00), addr.Dstv6[3]) // 3328
}
