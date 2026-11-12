#!/bin/bash
set -euo pipefail
umask 077
cd -- "$(dirname -- "$0")"
project="$PWD"
sdk="${ANDROID_HOME:-$project/.build/tools/android-sdk}"
export JAVA_HOME="${JAVA_HOME:-$project/.build/tools/jdk/Contents/Home}"
export PATH="$JAVA_HOME/bin:$PATH"
tools="$sdk/build-tools/35.0.0"
platform="$sdk/platforms/android-35/android.jar"
engine="$project/.build/libbox.aar"
[[ -f "$engine" ]] || { echo "Сначала запустите build-engine.sh" >&2; exit 1; }
[[ -f "$platform" && -x "$tools/aapt2" && -x "$JAVA_HOME/bin/javac" ]] || { echo "Нужны Java 17, Android SDK 35 и build-tools 35.0.0" >&2; exit 1; }

mkdir -p "$project/.build" "$project/dist"
work=$(mktemp -d "$project/.build/apk.XXXXXXXX")
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/res/drawable-nodpi" "$work/generated" "$work/classes" "$work/dex"
cp -R "$project/src/main/res/." "$work/res/"
swift -module-cache-path "$project/.build/swift-cache" "$project/../MacVPN/Icon.swift" "$work/icon.png"
sips -z 192 192 "$work/icon.png" --out "$work/res/drawable-nodpi/qosmos_icon.png" >/dev/null
swift -module-cache-path "$project/.build/swift-cache" "$project/MakeBanner.swift" "$work/icon.png" \
    "$work/res/drawable-nodpi/qosmos_banner.png"
"$tools/aapt2" compile --dir "$work/res" -o "$work/res.zip"
link_options=()
if [[ "${QOSMOS_TV_DEBUG:-0}" == 1 ]]; then link_options+=(--debug-mode); fi
"$tools/aapt2" link ${link_options[@]+"${link_options[@]}"} -I "$platform" --manifest "$project/src/main/AndroidManifest.xml" \
    --java "$work/generated" -o "$work/unsigned.apk" "$work/res.zip"

unzip -oq "$engine" classes.jar 'jni/*' -d "$work"
mv "$work/jni" "$work/lib"
sources=("$project"/src/main/java/com/alexfrokel/qosmos/tv/*.java "$work"/generated/com/alexfrokel/qosmos/tv/R.java)
"$JAVA_HOME/bin/javac" -encoding UTF-8 -source 8 -target 8 \
    -classpath "$platform:$work/classes.jar" -d "$work/classes" "${sources[@]}"
"$JAVA_HOME/bin/jar" cf "$work/app.jar" -C "$work/classes" .
"$tools/d8" --lib "$platform" --min-api 26 --output "$work/dex" "$work/app.jar" "$work/classes.jar"
(cd "$work/dex" && zip -q -j "$work/unsigned.apk" classes*.dex)
(cd "$work" && zip -q -r unsigned.apk lib -i '*.so')
"$tools/zipalign" -P 16 -f 4 "$work/unsigned.apk" "$work/aligned.apk"

key="$project/.build/qosmos-tv-local.p12"
if [[ ! -f "$key" ]]; then
    "$JAVA_HOME/bin/keytool" -genkeypair -storetype PKCS12 -keystore "$key" -alias qosmos-tv \
        -storepass android -keypass android -keyalg RSA -keysize 2048 -validity 10000 \
        -dname 'CN=Qosmos VPN Local Build'
fi
apk="$project/dist/Qosmos-TV.apk"
"$tools/apksigner" sign --ks "$key" --ks-key-alias qosmos-tv --ks-pass pass:android \
    --out "$work/signed.apk" "$work/aligned.apk"
"$tools/apksigner" verify "$work/signed.apk"
mv -f "$work/signed.apk" "$apk"
printf '%s\n' "$apk"
