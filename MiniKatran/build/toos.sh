sudo ip link set dev lo xdpgeneric obj /home/cainiao/bpftrace-exporter/MiniKatran/build/balancer.bpf.o sec xdp
sudo ip link set dev ens33 xdpgeneric off