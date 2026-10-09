# JVM entry-point language detector

This package is a research PoC for [issue #2646](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/2646).
It identifies the language evidenced by a running JVM application's entry
point, not every language used by the application. It is not yet connected to
OBI's automatic discovery or OTLP export.

## How detection works

1. `DetectPID(pid)` checks for a standard `java` executable with a `libjvm.so`
   mapping. It reads the process's command line, environment, and current
   working directory from `/proc`, and checks its start time and command line
   again after inspection to catch process changes or PID reuse.
2. `Detect` parses only the JVM launch arguments, stopping before application
   arguments. It resolves a named main class from the classpath or an
   executable JAR's `Main-Class`. For a supported Spring Boot `JarLauncher`, it
   uses `Start-Class` and `BOOT-INF/classes`.
3. For a compiled entry point, it reads only the resolved entry `.class` file.
   The shared [class-file parser](../../transform/route/harvest/java/classmarkers.go) looks for Kotlin
   metadata, Scala 2 signatures, or Scala 3 `TASTY`. Conflicting markers are an
   error.
4. The result contains a language and its evidence when a marker is found. A
   Java source-file launch is reported as `java` based on the launch mode.
   Marker-free bytecode returns an empty language and a reason; it is **not**
   inferred to be Java.

For example, a Java entry class calling Kotlin code remains unresolved, while
a Kotlin entry class calling Java code is reported as Kotlin. The detector does
not scan dependencies or determine the application's predominant language.

## Using the result

A future discovery integration can place a positive result in
`svc.Attrs.Metadata[attr.JVMLanguage]` so OBI's existing resource builder produces
`jvm.language`. Unresolved results should not add a metadata entry. This does not
change `telemetry.sdk.language`, which describes the telemetry SDK and remains
`java` for JVM instrumentation.

The detector can return an error for unsupported launches, unreadable process
data, unsafe paths, or malformed class files. A future discovery integration
should treat both errors and unresolved results as no `jvm.language`, without
interrupting instrumentation.

## Shared parser

The class-file reader remains in the Java route-harvesting package. The detector
calls its `InspectLanguage` helper, which reuses the existing parsing helpers.
Route-matching rules are unchanged, but the reader now rejects invalid annotation
references and trailing annotation data. These validation
changes affect route harvesting too: a rejected class is skipped, and harvesting
continues with other classes.

## Scope and tests

Launch parsing intentionally supports a bounded subset of classpath and
executable-JAR launches. Modules, argument files, wildcard and manifest
classpaths, multi-release JARs, custom class loaders, and interpreter
launchers are not supported. Groovy, Clojure, JRuby, and Jython detection is not
implemented. File and archive reads have size and entry-count limits.

`detector_test.go` exercises `Detect` with synthetic classes, JARs, source launches,
and unsafe inputs without requiring a JVM. It also tests launcher and archive rules.
