#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
fixture_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
: "${JVM_RESEARCH_COMPILERS:?Set JVM_RESEARCH_COMPILERS to the Maven dependency output directory}"
output_dir=$(mktemp -d "${TMPDIR:-/tmp}/obi-jvm-fixtures.XXXXXXXX")
compiler_cp="$JVM_RESEARCH_COMPILERS/*"
scala2_cp="$JVM_RESEARCH_COMPILERS/scala-compiler-2.13.16.jar:$JVM_RESEARCH_COMPILERS/scala-library-2.13.16.jar:$JVM_RESEARCH_COMPILERS/scala-reflect-2.13.16.jar"
kotlin_stdlib="$JVM_RESEARCH_COMPILERS/kotlin-stdlib-2.2.20.jar"
mkdir "$output_dir/classes" "$output_dir/scala2" "$output_dir/scala3"

java -version
java -cp "$compiler_cp" org.jetbrains.kotlin.cli.jvm.K2JVMCompiler -version -no-stdlib -no-reflect
java -cp "$scala2_cp" scala.tools.nsc.Main -version
java -cp "$compiler_cp" dotty.tools.dotc.Main -version
javac --release 17 -d "$output_dir/classes" "$fixture_dir/JavaHelper.java" "$fixture_dir/JavaPlain.java" "$fixture_dir/JavaDecoy.java"
java -cp "$compiler_cp" org.jetbrains.kotlin.cli.jvm.K2JVMCompiler -no-stdlib -no-reflect \
    -jvm-target 17 -classpath "$output_dir/classes:$kotlin_stdlib" -d "$output_dir/classes" "$fixture_dir/KotlinEntries.kt"
javac --release 17 -cp "$output_dir/classes:$kotlin_stdlib" -d "$output_dir/classes" "$fixture_dir/JavaEntry.java"
java -cp "$scala2_cp" scala.tools.nsc.Main -release 17 \
    -classpath "$output_dir/classes:$JVM_RESEARCH_COMPILERS/scala-library-2.13.16.jar" \
    -d "$output_dir/scala2" "$fixture_dir/ScalaEntry.scala"
java -cp "$compiler_cp" dotty.tools.dotc.Main -release 17 \
    -classpath "$output_dir/classes:$JVM_RESEARCH_COMPILERS/scala-library-2.13.16.jar:$JVM_RESEARCH_COMPILERS/scala3-library_3-3.3.6.jar" \
    -d "$output_dir/scala3" "$fixture_dir/ScalaEntry.scala"
jar --create --file "$output_dir/kotlin.jar" --main-class KotlinEntriesKt -C "$output_dir/classes" .
printf '\nOBI_JVM_FIXTURES=%s\n' "$output_dir"
