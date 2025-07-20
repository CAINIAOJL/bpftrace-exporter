sudo ip link set dev ens33 xdpgeneric obj xdp.o sec xdp
sudo ip link set dev ens33 xdpgeneric off
sudo xdp-loader load -m skb ens33 xdp.o
sudo xdp-loader status ens33

llvm-objdump -S xdp.o > xdp.s
