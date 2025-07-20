#!/bin/bash

build_grpc() {
    rm -rf goclient/MiniKatranC/lb_MiniKatran
    mkdir -p goclient/MiniKatranC/lb_MiniKatran

    export PATH=$PATH:$(go env GOPATH)/bin
    
    protoc -I protos protos/MiniKatran.proto \
        --go_out=goclient/MiniKatranC/lb_MiniKatran \
        --go-grpc_out=goclient/MiniKatranC/lb_MiniKatran

    if [ $? -ne 0 ]; then
        echo "error: protoc failed"
        return 1
    fi

    echo "success: goclient/lb.MiniKatran"
}


#检查版本
go version 1>/dev/null
protoc --version 1>/dev/null

build_grpc