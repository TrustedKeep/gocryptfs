#! /bin/bash

######################################################
# Parameters
######################################################
TKFS_VERSION=$1
echo "Building ${TKFS_VERSION}"
GO_FILE="boringgo.1.15.15.tgz"
GO_CHECKSUM="2e21e4af6798dbb7743d427ff1cae5cb34181d69be7fd25fe5ccdff1c9cd9358"
GO_OS="linux"
GO_ARCH="amd64"

######################################################
# Constants
######################################################
DL_PATH="/root/downloads"
export GOPATH="/root/go"
export GOROOT="/usr/local/go"
export GOPRIVATE="github.com/TrustedKeep"
TK_ROOT="$GOPATH/src/github.com/TrustedKeep"

######################################################
# Setup
######################################################
export PATH="$GOROOT/bin:$GOPATH/bin:$PATH"
mkdir -p $DL_PATH
mkdir -p $TK_ROOT
mkdir -p /root/build/artifacts

message() {
    echo ""
    echo "*******************************************************"
    echo "        $1"
    echo "*******************************************************"
    echo ""
}

installGo() {
    message "Installing Golang"

    aws s3 cp s3://trustedkeep-thirdparty-artifacts/$GO_FILE $DL_PATH/$GO_FILE

    echo "Verifying checksum"
    local sum=`sha256sum $DL_PATH/$GO_FILE | awk '{print $1}'`
    if [ "$sum" != $GO_CHECKSUM ]; then
        message "Checksum verification failure"
        exit 1
    fi
    echo "Checksum $sum verified"

    tar -C /usr/local -xzf $DL_PATH/$GO_FILE
    go version

    echo "getting goversion"
    go get -u rsc.io/goversion
}

verifyBoring() {
    echo "Verifying boring crypto"
    local isBoring=`goversion -crypto $GOPATH/bin/tkfs | grep "boring"`
    if [ "$isBoring" == "" ]; then 
        message "Boring Crypto not found!"
        exit 1
    fi
    message "Boring crypto module verified"
    echo "crypto string $isBoring"
}

installTools() {
    message "Installing Tools"
    yum install git -y
    git config --global url."git@github.com:".insteadOf "https://github.com/"
    yum install rpm-build -y
    yum install awscli -y
    yum install gcc -y
    yum install openssl-devel -y
    yum install fuse -y
    yum install fuse-devel -y
    yum install systemd-devel -y
    ldconfig
}

installTkfs() {
    message "Building TKFS"
    mkdir -p $GOPATH/src/github.com/TrustedKeep
    cd $GOPATH/src/github.com/TrustedKeep
    git clone git@github.com:TrustedKeep/gocryptfs
    cd gocryptfs
    git checkout $TKFS_VERSION

    go install

    rm -rf /root/build/artifacts
    mkdir /root/build/artifacts
    cp $GOPATH/bin/gocryptfs /root/build/artifacts/tkfs
}

buildRPM() {
    message "Building RPM"
    cd /root/build
    rpmbuild -ba tkfs.spec
    cp /root/rpmbuild/RPMS/x86_64/*.rpm /root/build/artifacts
}

installTools
installGo
installTkfs
verifyBoring
buildRPM