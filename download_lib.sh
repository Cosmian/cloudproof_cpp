#!/bin/bash
set -ux

download_package() {
    wget "https://package.cosmian.com/cloudproof_rust/$1/all.zip" &&
    unzip -j -d lib/ all.zip \
        x86_64-unknown-linux-gnu/x86_64-unknown-linux-gnu/release/libcloudproof.so \
        x86_64-pc-windows-gnu/x86_64-pc-windows-gnu/release/cloudproof.dll \
        x86_64-pc-windows-gnu/x86_64-pc-windows-gnu/release/libcloudproof.dll.a \
        x86_64-apple-darwin/x86_64-apple-darwin/release/libcloudproof.dylib &&
    unzip -j -d include/ all.zip x86_64-unknown-linux-gnu/cloudproof.h &&
    rm all.zip
}

cd "$(dirname "$0")"
download_package "v2.1.1"
if [ $? -ne 0 ]; then
    download_package "last_build/fix/binaries_archive"
fi

exit 0