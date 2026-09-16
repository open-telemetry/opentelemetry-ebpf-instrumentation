// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Diagnostics;
using System.Diagnostics.Tracing;
using System.Globalization;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.Diagnostics.NETCore.Client;
using Microsoft.Diagnostics.Tracing;

try
{
    if (args.Length == 5 && args[0] == "--verify-gc-trace")
    {
        int[] expected = args.Skip(2).Select(value => int.Parse(value, CultureInfo.InvariantCulture)).ToArray();
        VerifyGCTrace(args[1], expected);
    }
    else if (args.Length == 2)
    {
        await CollectAsync(args[0], args[1]);
    }
    else
    {
        Console.Error.WriteLine("Usage: dotnet-runtime-collector <workload.dll> <output-directory>");
        Console.Error.WriteLine("       dotnet-runtime-collector --verify-gc-trace <file> <gen0> <gen1> <gen2>");
        return 1;
    }
    return 0;
}
catch (Exception error)
{
    Console.Error.WriteLine(error);
    return 1;
}

static async Task CollectAsync(string workloadPath, string outputDirectory)
{
    Directory.CreateDirectory(outputDirectory);
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(45));
    var cancellation = timeout.Token;
    var start = new ProcessStartInfo("dotnet")
    {
        RedirectStandardInput = true,
        RedirectStandardOutput = true,
        UseShellExecute = false,
    };
    start.ArgumentList.Add(workloadPath);
    using var workload = Process.Start(start) ?? throw new InvalidOperationException("Workload did not start");
    try
    {
        using var snapshots = new StreamWriter(Path.Combine(outputDirectory, "workload.jsonl")) { AutoFlush = true };
        var startup = await ReadSnapshotAsync(workload, snapshots, cancellation);
        string version = startup.GetProperty("runtimeVersion").GetString()!;
        Check(Version.Parse(version).Major == 8, $"Expected .NET 8, got {version}");
        Check(startup.GetProperty("pid").GetInt32() == workload.Id, "Workload PID does not match child PID");
        Check(DiagnosticsClient.GetPublishedProcesses().Contains(workload.Id), "Workload diagnostic socket is absent");

        var provider = new EventPipeProvider("System.Runtime", EventLevel.Informational, keywords: 0x2,
            arguments: new Dictionary<string, string> { ["EventCounterIntervalSec"] = "1" });
        var client = new DiagnosticsClient(workload.Id);
        using var session = client.StartEventPipeSession(provider, requestRundown: false);
        Console.WriteLine($"EventPipe attached to .NET {version}, PID {workload.Id}");

        using var raw = File.Create(Path.Combine(outputDirectory, "runtime.nettrace"));
        using var recording = new RecordingStream(session.EventStream, raw);
        using var source = new EventPipeEventSource(recording);
        using var decoded = new StreamWriter(Path.Combine(outputDirectory, "events.jsonl")) { AutoFlush = true };
        var records = Channel.CreateBounded<CounterSample>(256);
        int eventCount = 0;
        source.Dynamic.All += data =>
        {
            if (data.ProviderName != "System.Runtime")
            {
                return;
            }

            eventCount++;
            var payload = data.PayloadNames.ToDictionary(name => name, name => data.PayloadByName(name));
            decoded.WriteLine(JsonSerializer.Serialize(new { data.EventName, data.TimeStamp, payload }));
            CounterSample? sample = null;
            if (data.EventName == "EventCounters")
            {
                var outer = (IDictionary<string, object>)data.PayloadValue(0);
                var fields = (IDictionary<string, object>)outer["Payload"];
                string name = (string)fields["Name"];
                bool increment = fields.ContainsKey("Increment");
                double value = Convert.ToDouble(fields[increment ? "Increment" : "Mean"], CultureInfo.InvariantCulture);
                double interval = Convert.ToDouble(fields["IntervalSec"], CultureInfo.InvariantCulture);
                Check(double.IsFinite(value) && value >= 0 && interval > 0, $"Invalid counter payload: {name}");
                sample = new CounterSample(name, value, increment);
            }
            else if (data.EventName == "ProcessorCount")
            {
                sample = new CounterSample("processor-count", Convert.ToDouble(data.PayloadValue(0), CultureInfo.InvariantCulture), false);
            }

            if (sample != null)
            {
                Check(records.Writer.TryWrite(sample), "Reference reader fell behind the EventPipe stream");
            }
        };
        var reader = Task.Run(() =>
        {
            try
            {
                source.Process();
                records.Writer.TryComplete();
            }
            catch (Exception error)
            {
                records.Writer.TryComplete(error);
                throw;
            }
        });

        var counts = new Dictionary<string, int>();
        var values = new Dictionary<string, double>();
        string[] generations = ["gen-0-gc-count", "gen-1-gc-count", "gen-2-gc-count"];
        void Observe(CounterSample sample)
        {
            counts.TryGetValue(sample.Name, out int seen);
            counts[sample.Name] = seen + 1;
            // The first increment can include work from before this listener.
            values[sample.Name] = sample.Increment
                ? values.GetValueOrDefault(sample.Name) + (seen == 0 ? 0 : sample.Value)
                : sample.Value;
        }

        async Task UntilAsync(Func<bool> ready)
        {
            while (!ready())
            {
                Observe(await records.Reader.ReadAsync(cancellation));
            }
        }

        // Observe actual polling before issuing commands, rather than sleeping
        // for an assumed attachment or collection delay.
        await UntilAsync(() => generations.All(name => counts.GetValueOrDefault(name) >= 2)
            && values.GetValueOrDefault("processor-count") > 0
            && values.GetValueOrDefault("working-set") > 0);
        var baseline = generations.Select(name => values[name]).ToArray();
        await workload.StandardInput.WriteLineAsync("snapshot");
        var before = await ReadSnapshotAsync(workload, snapshots, cancellation);
        var after = before;
        const int forcedCollections = 3;
        for (int i = 0; i < forcedCollections; i++)
        {
            await workload.StandardInput.WriteLineAsync("gc");
            after = await ReadSnapshotAsync(workload, snapshots, cancellation);
        }

        var expected = Enumerable.Range(0, generations.Length)
            .Select(i => after.GetProperty($"gen{i}").GetInt32() - before.GetProperty($"gen{i}").GetInt32()).ToArray();
        Check(expected.All(count => count >= forcedCollections), "Workload did not execute the requested collections");
        await UntilAsync(() => generations.Select((name, i) => values[name] - baseline[i] >= expected[i]).All(value => value));

        await session.StopAsync(cancellation);
        await reader.WaitAsync(cancellation);
        while (records.Reader.TryRead(out var sample))
        {
            Observe(sample);
        }
        raw.Close();
        var observed = generations.Select((name, i) => values[name] - baseline[i]).ToArray();
        Check(source.EventsLost == 0, $"EventPipe lost {source.EventsLost} events");
        Check(observed.Select((value, i) => value == expected[i]).All(value => value),
            $"GC increments differ: expected {string.Join(',', expected)}, observed {string.Join(',', observed)}");
        Check(values.GetValueOrDefault("alloc-rate") > 0, "No allocation increments received");
        VerifyReplay(Path.Combine(outputDirectory, "runtime.nettrace"), eventCount);

        var result = new
        {
            runtimeVersion = version,
            forcedCollections,
            expected,
            observed,
            processorCount = values["processor-count"],
            workingSetMB = values["working-set"],
            allocatedBytes = values["alloc-rate"],
            eventsLost = source.EventsLost,
            eventCount,
        };
        string json = JsonSerializer.Serialize(result);
        File.WriteAllText(Path.Combine(outputDirectory, "result.json"), json);
        Console.WriteLine(json);
        workload.StandardInput.Close();
        await workload.WaitForExitAsync(cancellation);
        Check(workload.ExitCode == 0, $"Workload exited with {workload.ExitCode}");
    }
    finally
    {
        if (!workload.HasExited)
        {
            workload.Kill(entireProcessTree: true);
            await workload.WaitForExitAsync();
        }
    }
}

static async Task<JsonElement> ReadSnapshotAsync(Process workload, StreamWriter output, CancellationToken cancellation)
{
    string line = await workload.StandardOutput.ReadLineAsync(cancellation)
        ?? throw new InvalidOperationException("Workload exited before reporting its counters");
    output.WriteLine(line);
    using var document = JsonDocument.Parse(line);
    return document.RootElement.Clone();
}

static void VerifyReplay(string path, int expectedEvents)
{
    using var replay = new EventPipeEventSource(path);
    int events = 0;
    replay.Dynamic.All += data =>
    {
        if (data.ProviderName == "System.Runtime")
        {
            events++;
        }
    };
    replay.Process();
    Check(expectedEvents > 0 && events == expectedEvents,
        $"NetTrace replay differs: expected {expectedEvents} events, read {events}");
    Check(replay.EventsLost == 0, $"NetTrace replay lost {replay.EventsLost} events");
}

// VerifyGCTrace checks a fresh workload's first EventCounter session against its
// final GC.CollectionCount values, including the initial counter increments.
static void VerifyGCTrace(string path, int[] expected)
{
    Check(expected.Length == 3, "Expected a collection count for each GC generation");
    string[] names = ["gen-0-gc-count", "gen-1-gc-count", "gen-2-gc-count"];
    var observed = new double[3];
    var samples = new int[3];
    using var source = new EventPipeEventSource(path);
    source.Dynamic.All += data =>
    {
        if (data.ProviderName != "System.Runtime" || data.EventName != "EventCounters")
        {
            return;
        }

        var outer = (IDictionary<string, object>)data.PayloadValue(0);
        var fields = (IDictionary<string, object>)outer["Payload"];
        int generation = Array.IndexOf(names, (string)fields["Name"]);
        if (generation < 0)
        {
            return;
        }

        double increment = Convert.ToDouble(fields["Increment"], CultureInfo.InvariantCulture);
        Check(double.IsFinite(increment) && increment >= 0,
            $"Invalid GC increment for generation {generation}: {increment}");
        observed[generation] += increment;
        samples[generation]++;
    };
    source.Process();
    Check(source.EventsLost == 0, $"NetTrace lost {source.EventsLost} events");
    for (int generation = 0; generation < expected.Length; generation++)
    {
        Check(samples[generation] > 0, $"No GC samples for generation {generation}");
        Check(observed[generation] == expected[generation],
            $"Generation {generation}: expected {expected[generation]}, observed {observed[generation]}");
    }
    Console.WriteLine(JsonSerializer.Serialize(new { expected, observed, samples, eventsLost = source.EventsLost }));
}

static void Check(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}

sealed record CounterSample(string Name, double Value, bool Increment);
