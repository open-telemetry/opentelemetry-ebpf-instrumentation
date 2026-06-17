#!/bin/bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
test_dir="${script_dir}"
src_dir="${test_dir}/src"
classes_dir="${test_dir}/classes"
build_dir="${test_dir}/build"

javac_bin="${JAVAC:-javac}"
jar_bin="${JAR:-jar}"

require_cmd() {
	local cmd="$1"
	if ! command -v "${cmd}" >/dev/null 2>&1; then
		echo "missing required command: ${cmd}" >&2
		exit 1
	fi
}

require_cmd "${javac_bin}"
require_cmd "${jar_bin}"

if [[ ! -d "${src_dir}" ]]; then
	echo "missing Java source directory: ${src_dir}" >&2
	exit 1
fi

rm -rf "${classes_dir}" "${build_dir}"
mkdir -p "${classes_dir}" "${build_dir}"

source_list="${build_dir}/sources.txt"
find "${src_dir}" -name '*.java' | sort >"${source_list}"

if [[ ! -s "${source_list}" ]]; then
	echo "no Java sources found under ${src_dir}" >&2
	exit 1
fi

"${javac_bin}" -g -d "${classes_dir}" @"${source_list}"

rm -f \
	"${test_dir}/regular-app.jar" \
	"${test_dir}/spring-boot-app.jar" \
	"${test_dir}/war-app.jar"

"${jar_bin}" cf "${test_dir}/regular-app.jar" -C "${classes_dir}" .

mkdir -p "${build_dir}/spring-boot/BOOT-INF/classes"
cp -R "${classes_dir}/." "${build_dir}/spring-boot/BOOT-INF/classes/"
"${jar_bin}" cf "${test_dir}/spring-boot-app.jar" -C "${build_dir}/spring-boot" .

mkdir -p "${build_dir}/war/WEB-INF/classes"
cp -R "${classes_dir}/." "${build_dir}/war/WEB-INF/classes/"
"${jar_bin}" cf "${test_dir}/war-app.jar" -C "${build_dir}/war" .

rm -rf "${build_dir}"

echo "rebuilt Java route harvest tests in ${test_dir}"
