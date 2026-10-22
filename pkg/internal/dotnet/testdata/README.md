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
