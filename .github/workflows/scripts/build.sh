#!/bin/bash

set -eo pipefail

apt-get update
# libcjson-dev: Mosquitto 2.1 headers transitively #include <cjson/cJSON.h>.
apt-get install -y gcc-arm-linux-gnueabi binutils-arm-linux-gnueabi gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu libcjson-dev
cd /usr/src/mosquitto-$MOSQUITTO_VERSION/include
# Copy both the top-level shim headers and the mosquitto/ subdirectory
# introduced in 2.1 (shims #include <mosquitto/broker.h> etc.).
cp -r . /usr/include/
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
