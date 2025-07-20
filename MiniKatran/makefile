CC=clang

BUILD_DIR=build
XDP_SRC_DIR=bpf
TPR_SRC_DIR=tpr
BUILD_XDP_DIR=$(BUILD_DIR)
CFLAGS=#-DGUE_ENCAP

XDP_SRC=balancer.bpf.c
XDP_OBJ=balancer.bpf.o

TPR_SRC=tpr_pckt_routing_bpf.c
TPR_OBJ=tpr_pckt_routing_bpf.o

FLAGS=-g -O2 -lelf -lbpf -lxdp -Wcompare-distinct-pointer-types -Wunused-command-line-argument

INCS=-I /usr/include -I /usr/local/include -I $(XDP_SRC_DIR)  

all: xdp #tpr

xdp:
	$(CC) $(INCS) $(FLAGS) $(CFLAGS) -target bpf -c -o $(BUILD_XDP_DIR)/$(XDP_OBJ) $(XDP_SRC_DIR)/$(XDP_SRC)


tpr:
	$(CC) $(INCS) $(FLAGS) -target bpf -c -o $(BUILD_XDP_DIR)/$(TPR_OBJ) $(XDP_SRC_DIR)/$(TPR_SRC_DIR)/$(TPR_SRC)