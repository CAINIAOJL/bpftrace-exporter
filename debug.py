from scapy.all import Ether
import base64

b64 = "AADerb6vAgAAAAAACABFAAA/AAAAAEAEpUu6wRCsCgAAA0UAACsAAQAAQBGtT8CoAQEKyAEBemkAUAAXl95rYXRyYW4gdGVzdCBwa3Q="
raw = base64.b64decode(b64)
pkt = Ether(raw)
pkt.show2()