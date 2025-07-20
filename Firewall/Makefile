CC=clang

BUILD_DIR=build
SRC_DIR=XDP

BUILD_XDP_DIR=$(BUILD_DIR)/xdp


XDP_SRC=xdp.c
XDP_OBJ=xdp.o

FLAGS=-g -O2 -lelf -lbpf -lxdp

INCS=-I /usr/include -I /usr/local/include -I $(SRC_DIR)  

all: xdp 

xdp:
	$(CC) $(INCS) $(FLAGS) -target bpf -c -o $(BUILD_XDP_DIR)/$(XDP_OBJ) $(SRC_DIR)/$(XDP_SRC)