# Java agent design

This guide records the design constraints for changes to OBI's Java agent. The
implementation lives in `pkg/internal/java/agent/`; the [Java package
README](../pkg/internal/java/README.md) describes its current features, build,
and protocol details.

## Runtime boundaries

- Keep the agent small and self-contained. It runs inside application JVMs,
  where extra startup work, classpath conflicts, and behavioral interference
  matter.
- Do not add a logging framework or logging facade. The agent currently has no
  logger abstraction; its diagnostics use direct standard error output and
  optional Byte Buddy diagnostics. Use the existing debug options where
  appropriate, and do not add routine output to application processes.
- Keep runtime dependencies deliberate: the agent depends on Byte Buddy and
  Byte Buddy Agent. Do not add dependencies without a concrete need. Advice
  and helpers injected into the bootstrap class loader must remain independent
  of Byte Buddy and the OpenTelemetry SDK/API, which are not runtime
  dependencies of the agent. The packaged agent shades and relocates Byte
  Buddy; preserve that isolation from application classpaths.
- Compile Java sources for Java 8 (`sourceCompatibility` and
  `targetCompatibility` in `agent/build.gradle.kts`). Avoid newer language or
  library APIs unless compatibility is explicitly changed.
- Instrumentation is best-effort: advice should fail open and must not change
  the application's arguments, return values, or thrown exceptions when agent
  work fails. Existing advice generally uses Byte Buddy's
  `suppress = Throwable.class`; preserve that behavior when adding hooks.
- The agent does not export telemetry through an OpenTelemetry SDK. It sends
  compact packets to OBI through JNI and the `ioctl` channel; keep packet
  layout and behavior aligned with the receiving eBPF code. The bundled JNI
  library currently targets Linux amd64 and aarch64; keep both builds and the
  Java-to-native packet ABI in sync when changing this path.

## Implementation and validation

- Keep instrumentation focused: Byte Buddy advice captures application
  behavior, while agent-side helpers build packets and JNI forwards them to
  OBI. The agent injects copies of selected classes into the bootstrap loader;
  those classes have distinct identity from agent-loader copies. Advice on JDK
  classes must resolve the bootstrap copy of shared state, and injected
  helpers must not depend on classes visible only to the agent loader.
- Dynamic attachment retransforms already-loaded classes. Transformations must
  not change class format (`Agent.builder` disables format changes), and the
  retransformation path deliberately skips `$$Lambda$` classes because of a
  Java 8 constant-pool corruption bug (JDK-8145964). Preserve these constraints
  when changing matchers or advice.
- Keep hot-path work and retained state bounded. Use bounded storage for
  correlation data and clean up thread-local state where its scope ends. The
  virtual-thread mount/unmount path is especially sensitive: it uses
  preallocated native buffers and lock-free slot claims; do not allocate,
  block, or lazily initialize classes there. If a buffer is unavailable, the
  existing behavior drops the emit rather than stalling a carrier.
- Add or update tests under `agent/src/test/java`. Run the focused test with
  `gradle :agent:test --tests <TestClass>`; run the complete agent suite with
  `gradle :agent:test`.
- Apply the Java formatter with `gradle :agent:spotlessApply`. The root Java
  build is under `pkg/internal/java`; its README documents build and packaging
  commands. Do not edit the embedded agent JAR by hand: it is produced by the
  build.

Before adding a dependency, changing the runtime boundary, or changing the
supported Java level, update this guide and the package README as appropriate.
