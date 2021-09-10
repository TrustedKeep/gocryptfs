#! /bin/bash
TKFS_VERSION=`./get_current_version.sh`

docker run -it --rm \
    -v "$HOME/.ssh:/root/.ssh" \
    -v "$HOME/.aws:/root/.aws" \
    -v "$GOPATH/src/github.com/TrustedKeep/gocryptfs/build:/root/build" \
    -w /root \
    centos:7 \
    ./build/docker_build.sh ${TKFS_VERSION}