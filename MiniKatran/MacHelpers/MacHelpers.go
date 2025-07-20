package machelpers

import(
	"net"
	"log"
)

type MacHelper struct{

}

func (MacHelper MacHelper) ConvertMacToUint(macAddress string) []uint8 {
	mac, err := net.ParseMAC(macAddress)
	if err != nil {
		log.Printf("Invalid MAC address: %v", macAddress)
		return nil
	}
	return mac
} 

func (MacHelper MacHelper) ConvertMacToString(macAddress []uint8) string {
	mac := net.HardwareAddr(macAddress)
	return mac.String()
}