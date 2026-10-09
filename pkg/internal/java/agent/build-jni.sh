#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

cc="${CC:-gcc}"
java_home="${JAVA_HOME:-$(java -XshowSettings:properties -version 2>&1 | awk '/java.home =/ { print $3; exit }')}"
jni_headers_dir="${JNI_HEADERS_DIR:-build/generated/jni-headers}"
build_dir="${BUILD_DIR:-build}"
target_dir="${TARGET_DIR:-target/classes}"

mkdir -p "$build_dir" "$target_dir"
"$cc" -fPIC -O2 -Wall -Wextra -Wno-unused-parameter \
	-I"$java_home/include" -I"$java_home/include/linux" -I"$jni_headers_dir" -Isrc/main/c \
	-c src/main/c/io_opentelemetry_obi_java_jni.c \
	-o "$build_dir/io_opentelemetry_obi_java_jni.o"
"$cc" -shared -o "$target_dir/libobijni.so" "$build_dir/io_opentelemetry_obi_java_jni.o"
echo "Built JNI library: $target_dir/libobijni.so"
