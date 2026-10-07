#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

fixture_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
output_dir=$(mktemp -d "${TMPDIR:-/tmp}/obi-jvm-language.XXXXXXXX")
mkdir "$output_dir/classes"
printf 'Artifacts: %s\n' "$output_dir"

: "${KOTLIN_STDLIB:?Set KOTLIN_STDLIB to the matching kotlin-stdlib JAR}"
compiler=(kotlinc)
if [[ -n ${KOTLIN_COMPILER_CLASSPATH:-} ]]; then
    compiler=(java -cp "$KOTLIN_COMPILER_CLASSPATH" org.jetbrains.kotlin.cli.jvm.K2JVMCompiler)
fi

java -version
"${compiler[@]}" -version
javac -d "$output_dir/classes" "$fixture_dir/JavaHelper.java" "$fixture_dir/JavaPlain.java"
"${compiler[@]}" -no-stdlib -no-reflect \
    -classpath "$output_dir/classes:$KOTLIN_STDLIB" \
    -d "$output_dir/classes" "$fixture_dir/KotlinEntries.kt"
javac -cp "$output_dir/classes:$KOTLIN_STDLIB" \
    -d "$output_dir/classes" "$fixture_dir/JavaEntry.java"

inspect_entry() {
    local entry=$1
    local expected=$2
    local classpath=$3
    local observed=absent
    java -cp "$classpath" "$entry"
    javap -v -classpath "$output_dir/classes" "$entry" > "$output_dir/$entry.javap"
    # Only inspect the class-level annotation section, not constant-pool strings.
    if awk '/^RuntimeVisibleAnnotations:/ { annotations=1; next }
        annotations && /^[^ ]/ { annotations=0 }
        annotations && /kotlin.Metadata\(/ { found=1 }
        END { exit !found }' "$output_dir/$entry.javap"; then
        observed=present
    fi
    printf '%s\tkotlin.Metadata=%s\n' "$entry" "$observed"
    [[ "$observed" == "$expected" ]]
}

inspect_entry JavaPlain absent "$output_dir/classes"
inspect_entry JavaPlain absent "$output_dir/classes:$KOTLIN_STDLIB"
inspect_entry JavaEntry absent "$output_dir/classes:$KOTLIN_STDLIB"
inspect_entry KotlinEntriesKt present "$output_dir/classes:$KOTLIN_STDLIB"
inspect_entry ObjectEntry present "$output_dir/classes:$KOTLIN_STDLIB"
inspect_entry CompanionEntry present "$output_dir/classes:$KOTLIN_STDLIB"

printf 'PASS: six launch cases; bytecode evidence only, not detector validation.\n'
