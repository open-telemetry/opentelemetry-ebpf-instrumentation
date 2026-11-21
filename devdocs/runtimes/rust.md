# Rust runtime instrumentation

OBI tracks spawned Tokio tasks on Linux amd64 and arm64 with rustc 1.97 through
1.100. The executable must retain the Tokio function symbols used for poll and
task creation or deallocation. Debug information is optional.

A worker can switch between unrelated tasks. OBI follows the task across polls
and copies its parent when it spawns another task. It checks alternative hooks
for optimized builds and keeps generic capture available when hooks are missing.
