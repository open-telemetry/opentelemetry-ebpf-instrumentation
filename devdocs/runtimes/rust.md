# Rust runtime instrumentation

OBI tracks spawned Tokio tasks on Linux amd64 and arm64 with stable rustc
1.97.x through 1.100.x. OBI reads the compiler version from the executable.
If the version string is absent, OBI can identify the compiler from a known
standard-library commit. The executable must retain the Tokio function symbols
used for poll and task creation or deallocation. Debug information is optional.

A worker can switch between unrelated tasks. OBI follows the task across polls
and copies its parent when it spawns another task. It checks alternative hooks
for optimized builds and keeps generic capture available when hooks are missing.
