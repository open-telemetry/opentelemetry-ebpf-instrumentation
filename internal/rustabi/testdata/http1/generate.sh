#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
cd "$(dirname "$0")"
build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT

export CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"
cargo +1.100.0 rustc --locked --release --target x86_64-unknown-linux-gnu --target-dir "$build_dir" -- \
    -C debuginfo=2 -C codegen-units=1 -C opt-level=z --emit="obj=$build_dir/http1.o" \
    --remap-path-prefix="$PWD=/fixture"

# Resolve the debug relocations from this crate alone. Keep dependency source
# paths in .rodata alongside the compiler version and DWARF for Inspect.
ld -m elf_x86_64 --unresolved-symbols=ignore-all -e 0 -o "$build_dir/http1" "$build_dir/http1.o"
objcopy -j .comment -j '.rodata*' -j '.debug_*' --compress-debug-sections=zlib "$build_dir/http1" "$build_dir/http1.elf"
install -m 0644 "$build_dir/http1.elf" http1.elf
