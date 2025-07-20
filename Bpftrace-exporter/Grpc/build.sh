#!/bin/bash

GOPATH=""
PROTOFILE="Bpftrace.proto"

# 编译proto文件
build_proto() {
    GOPATH=$(go env GOPATH)
    echo "The go path is $GOPATH"
    if [ -z "$GOPATH" ]; then
        echo "GOPATH is not set"
        echo "Please ckeck your go path"
        exit 1
    fi
    protoc \
    --go_out=. \
    --go-grpc_out=.  \
    --plugin=protoc-gen-go=$GOPATH/bin/protoc-gen-go \
    --plugin=protoc-gen-go-grpc=$GOPATH/bin/protoc-gen-go-grpc \
    $PROTOFILE

    #if [ -z "$?" ]; then 
        #echo "Build proto file success"
    #else
        #echo "Build proto file failed"
        #echo "
        #eg.
            #go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28
            #go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2
        #"
    #fi
}
build_proto
#protoc --go_out=. --go-grpc_out=. --plugin=protoc-gen-go=/home/cainiao/go/bin/protoc-gen-go --plugin=protoc-gen-go-grpc=/home/cainiao/go/bin/protoc-gen-go-grpc Bpftrace.proto