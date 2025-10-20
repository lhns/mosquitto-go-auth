#!/bin/bash

set -eo pipefail

apt-get update
apt-get install -y gcc-arm-linux-gnueabi binutils-arm-linux-gnueabi gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu
cd /usr/src/mosquitto-$MOSQUITTO_VERSION/include
cp *.h /usr/include
cd /usr/src/mosquitto-go-auth

echo "build amd64 Linux" >&2
make without-vcs
cp go-auth.so pw /usr/src/output/linux-amd64

echo "build arm64 Linux" >&2
make clean
export CGO_ENABLED=1
export GOARCH=arm64
export CC=aarch64-linux-gnu-gcc
make without-vcs
cp go-auth.so pw /usr/src/output/linux-arm64

echo "build armv7 Linux" >&2
make clean
export CGO_ENABLED=1
export GOARCH=arm
export GOARM=7
export CC=arm-linux-gnueabi-gcc
make without-vcs
cp go-auth.so pw /usr/src/output/linux-armv7

echo "build armv7 Linux" >&2
make clean
export CGO_ENABLED=1
export GOARCH=arm
export GOARM=6
export CC=arm-linux-gnueabi-gcc
make without-vcs
cp go-auth.so pw /usr/src/output/linux-armv6
