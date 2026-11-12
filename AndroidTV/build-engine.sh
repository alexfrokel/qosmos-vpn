#!/bin/bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
project="$PWD"
sdk_default="$project/.build/tools/android-sdk"
java_default="$project/.build/tools/jdk/Contents/Home"
export JAVA_HOME="${JAVA_HOME:-$java_default}"
export ANDROID_HOME="${ANDROID_HOME:-$sdk_default}"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/28.2.13676358}"
export GOPATH="${GOPATH:-$project/.build/go}"
export GOCACHE="${GOCACHE:-$project/.build/go-cache}"
export GOTOOLCHAIN="${GOTOOLCHAIN:-go1.26.10}"
export GOBIN="$GOPATH/bin"
export PATH="$JAVA_HOME/bin:$GOBIN:$PATH"
mkdir -p .build
engine="$project/.build/upstream/sing-box"
revision=c005f35300ce76427dc285481ec5695f5b179cd2
if [[ ! -d "$engine/.git" ]]; then
    mkdir -p "$project/.build/upstream"
    git clone --depth 1 --branch v1.14.4 https://github.com/SagerNet/sing-box.git "$engine"
fi
[[ "$(git -C "$engine" rev-parse HEAD)" == "$revision" ]]
patch_file="$project/libbox-no-profile-snapshot.patch"
if ! git -C "$engine" apply --reverse --check "$patch_file" 2>/dev/null; then
    git -C "$engine" apply "$patch_file"
fi
if [[ ! -x "$GOBIN/gomobile" || ! -x "$GOBIN/gobind" ]]; then
    go install github.com/sagernet/gomobile/cmd/gomobile@v0.1.12 github.com/sagernet/gomobile/cmd/gobind@v0.1.12
fi
cd "$engine"
# gVisor supplies the TUN stack and uTLS supplies the REALITY handshake.
gomobile bind -target=android/arm64,android/arm,android/amd64 -androidapi=26 \
    -javapkg=io.nekohasekai -libname=box -trimpath -buildvcs=false \
    -tags=with_gvisor,with_utls,badlinkname,tfogo_checklinkname0 \
    -ldflags="-s -w -checklinkname=0 -X github.com/sagernet/sing-box/constant.Version=v1.14.4" \
    -o "$project/.build/libbox.aar" ./experimental/libbox
