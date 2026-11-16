# .NET exception trace fixture

`exceptions-net8.nettrace` was recorded from .NET 8.0.31 on Linux x64 with
`Microsoft.Diagnostics.NETCore.Client`, targeting PID 1 in a container.

The session enabled `Microsoft-Windows-DotNETRuntime` at Warning level with
keyword `0x8000` and rundown disabled. The workload is the integration fixture's
`ExceptionReference.Run` method. Its FirstChanceException reference counted ten
throws across seven types: caught, bare rethrow, explicit rethrow,
`ExceptionDispatchInfo.Throw`, generic, nested, and background exceptions.

The native events carry no metadata field definitions. The fixture exercises
the fixed `ExceptionThrown_V1` payload decoder and short type-name extraction,
including the two events produced by each rethrow case on this runtime.

## Meter traces

`exceptions-net9.nettrace` and `exceptions-net10.nettrace` were recorded from
.NET 9.0.20 and .NET 10.0.12 on Linux amd64, targeting namespace PID 1.
They record one call to the same `ExceptionReference.Run` workload.

The session enables `System.Diagnostics.Metrics`, keyword `0x2`, Informational
level, with rundown disabled and these arguments:

```text
SessionId=test-session;Metrics=System.Runtime\dotnet.exceptions;RefreshInterval=1;MaxTimeSeries=128;MaxHistograms=0
```

The recorded FirstChance and Meter references each counted ten throws across
the seven types. Each ten-second trace also includes zero-delta intervals.

## GC heap history payload

`gc-per-heap-net8.bin` is one raw `GCPerHeapHistory_V3` payload (event ID 204),
captured from .NET 8.0.30 on Linux amd64 with server GC and two heaps. The
session enabled `Microsoft-Windows-DotNETRuntime`, keyword `0x1`, Informational
level, with rundown disabled.

The payload identifies CLR instance 0 and heap 0. Its five generation records
contain 48,032, 0, 0, 1,152, and 0 fragmented bytes, respectively, calculated as
`FreeListAfter + FreeObjAfter`. This fixture checks the native 64-bit layout;
synthetic payloads cover the 32-bit layout and malformed input.

`gc-net10.nettrace` captures .NET 10.0.11 server GC on Linux amd64 with background
GC disabled and a processor count of two. It uses the same provider settings
as the raw payload. The workload allocates and releases small, large, and pinned
objects while requesting full and gen0 collections. The trace contains 17
starts, 17 completions, 17 global histories, and 30 per-heap histories. The
runtime changes its active heap count during the capture.
