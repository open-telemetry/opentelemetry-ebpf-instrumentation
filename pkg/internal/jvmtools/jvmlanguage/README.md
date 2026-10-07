# JVM language detector PoC

This research implementation addresses the request for an end-to-end view in
[issue #2646](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/2646).
It inspects a running Java process and passes its result through the existing
`svc.Attrs.JVMLanguage` and `otelcfg.GetAppResourceAttrs` export path. The CLI prints
the two language resource attributes as JSON; it does not send OTLP or enable
automatic language discovery in OBI.

## Detection policy

Inspect the resolved entry class, not the languages present in dependencies.
Kotlin metadata, Scala signature annotations, and Scala 3 TASTY attributes provide
positive compiler evidence. The shared parser also recognizes the GroovyObject
interface, but the live fixture suite does not validate Groovy.

No recognized marker means omit `jvm.language`. A Java entry calling Kotlin is
therefore unresolved; a Kotlin entry calling Java is Kotlin under this policy.
An observed Java source-file launch provides positive Java evidence. The runtime
attribute remains `telemetry.sdk.language=java` in every successful inspection.
Conflicting markers or unsupported resolution return an error, not a guessed label.

This is the interpretation of the branch's development-stage `jvm.language`
convention. It does not establish predominant application language. The registry
uses a string rather than a closed enum so future positively identified JVM
languages do not require an attribute-type change. No `mixed` or `unknown` value
is emitted to hide unresolved cases.

## Reproduce

Prerequisites: Linux, a JDK with `java`, `javac`, and `jar`, Maven, and the
repository's Go toolchain and generated bindings. Run from the repository root.
Maven resolves the pinned Kotlin 2.2.20, Scala 2.13.16, and Scala 3.3.6 compiler
dependencies; fixture sources target Java 17 bytecode.

```bash
export JVM_RESEARCH_COMPILERS=$(mktemp -d /tmp/obi-jvm-compilers.XXXXXXXX)
mvn -q -f internal/test/tools/jvm-language-research/pom.xml \
  org.apache.maven.plugins:maven-dependency-plugin:3.8.1:copy-dependencies \
  -DoutputDirectory="$JVM_RESEARCH_COMPILERS"
bash internal/test/tools/jvm-language-research/build-fixtures.sh
```

Set `OBI_JVM_FIXTURES` to the output directory printed by the build script, then:

```bash
export OBI_JVM_FIXTURES=/tmp/obi-jvm-fixtures.REPLACE_WITH_PRINTED_SUFFIX
export OBI_JVM_POC_BINARY=/tmp/obi-jvmlang-poc
go build -o "$OBI_JVM_POC_BINARY" ./pkg/internal/jvmtools/jvmlanguage/cmd/jvmlang-poc
go test -v -count=1 -run TestLivePoC ./pkg/internal/jvmtools/jvmlanguage
```

The suite launches real JVM processes, invokes the compiled CLI on their PIDs,
checks emitted resource attributes, and terminates the fixture processes. It
covers Java bytecode, Java source launch, Kotlin top-level/object/companion mains,
Scala 2/3, both delegation directions, a dependency-only Kotlin case, decoy marker
strings, an application `-jar` argument, and an executable JAR. Without the
environment variables, ordinary unit tests skip this opt-in suite.

Inspect an existing supported Java process with:

```bash
/tmp/obi-jvmlang-poc PID
```

The caller must have permission to read the process's `/proc` entries and files.
An unsupported inspection has an `error` field and a nonzero exit status. A
successful but unresolved inspection has a `reason`, no `jvm.language` key, and
exit status zero.

## Deliberate limits

- Supports explicit classpaths and executable JARs. It recognizes standard Boot
  JarLauncher manifests and `BOOT-INF/classes`, but this layout is not covered
  by the real JVM fixture suite yet.
- Rejects modules, argfiles, wildcard classpaths, manifest classpaths, multi-release
  JARs, launcher-option environment variables, agents, custom-loader options,
  PropertiesLauncher, and unrecognized JVM options. Interpreter launchers are not
  yet classified. Java source mode currently requires a `.java` filename.
- Reads at most 2 MiB per class/member, 16 MiB per archive, 32 MiB across archive
  reads and decompressed members, and 32 classpath roots. Archives are held in
  memory and checked against a 4096-entry limit after ZIP indexing; this is not
  a production memory-budget guarantee. Annotation nesting is bounded.
- Uses existing process-root and bounded-file helpers. It checks process start
  time and command line for changes, but does not provide an atomic filesystem
  snapshot or eliminate intermediate-directory symlink races. Transformed classes
  loaded in memory can differ from their files. Metadata is not authenticity proof.
- The PoC parser bounds JVM arguments before calling the existing classpath
  helpers. The existing general-purpose `ParseJavaLaunch` behavior is unchanged;
  a future production integration should unify the launch parsing API.

## Validation

```bash
go test ./pkg/internal/jvmtools/... ./pkg/internal/transform/route/harvest/java ./pkg/export/otel/otelcfg
go vet ./pkg/internal/jvmtools/... ./pkg/internal/transform/route/harvest/java ./pkg/export/otel/otelcfg
go test ./pkg/internal/jvmtools/classfile -run '^$' \
  -fuzz FuzzInspectLanguage -fuzztime=10s -parallel=2
```

All 12 live cases passed with OpenJDK 25.0.4.1 and the pinned compiler versions
listed above. Compiler sources and build instructions are checked in; generated
class files are not.
