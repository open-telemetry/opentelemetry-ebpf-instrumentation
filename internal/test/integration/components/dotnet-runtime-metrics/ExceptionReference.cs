// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Runtime.ExceptionServices;
using System.Diagnostics.Metrics;

static class ExceptionReference
{
    private static readonly object gate = new();
    private static readonly Dictionary<string, long> counts = new(StringComparer.Ordinal);
    private static readonly Dictionary<string, long> meterCounts = new(StringComparer.Ordinal);
    private static readonly MeterListener listener = new();
    private static bool meterAvailable;

    [ThreadStatic]
    private static bool recording;

    static ExceptionReference()
    {
        listener.InstrumentPublished = (instrument, current) =>
        {
            if (instrument.Meter.Name == "System.Runtime" && instrument.Name == "dotnet.exceptions")
            {
                lock (gate)
                {
                    meterAvailable = true;
                }
                current.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((_, value, tags, _) =>
        {
            foreach (var tag in tags)
            {
                if (tag.Key == "error.type" && tag.Value is string name && name.StartsWith("Pr5", StringComparison.Ordinal))
                {
                    lock (gate)
                    {
                        meterCounts.TryGetValue(name, out long count);
                        meterCounts[name] = count + value;
                    }
                }
            }
        });
        listener.Start();
        AppDomain.CurrentDomain.FirstChanceException += (_, args) =>
        {
            if (recording || !args.Exception.GetType().Name.StartsWith("Pr5", StringComparison.Ordinal))
            {
                return;
            }
            recording = true;
            try
            {
                lock (gate)
                {
                    string name = args.Exception.GetType().Name;
                    counts.TryGetValue(name, out long count);
                    counts[name] = count + 1;
                }
            }
            finally
            {
                recording = false;
            }
        };
    }

    public static object Run()
    {
        var before = Snapshot();
        Catch(() => throw new Pr5Caught());
        Catch(() =>
        {
            try { throw new Pr5Rethrown(); }
            catch { throw; }
        });
        Catch(() =>
        {
            try { throw new Pr5ExplicitRethrow(); }
            catch (Pr5ExplicitRethrow error) { throw error; }
        });
        Catch(() =>
        {
            try { throw new Pr5Dispatch(); }
            catch (Pr5Dispatch error) { ExceptionDispatchInfo.Capture(error).Throw(); }
        });
        Catch(() => throw new Pr5Generic<string>());
        Catch(() => throw new GenericOuter<string>.Pr5Nested());
        Task.Run(() => Catch(() => throw new Pr5Background())).GetAwaiter().GetResult();
        lock (gate)
        {
            return new { before, after = Snapshot(), meterAvailable, meter = new Dictionary<string, long>(meterCounts) };
        }
    }

    private static void Catch(Action action)
    {
        try { action(); }
        catch (Exception error) when (error.GetType().Name.StartsWith("Pr5", StringComparison.Ordinal)) { }
    }

    public static Dictionary<string, long> Snapshot()
    {
        lock (gate)
        {
            return new Dictionary<string, long>(counts, StringComparer.Ordinal);
        }
    }
}

sealed class Pr5Caught : Exception { }
sealed class Pr5Rethrown : Exception { }
sealed class Pr5ExplicitRethrow : Exception { }
sealed class Pr5Dispatch : Exception { }
sealed class Pr5Generic<T> : Exception { }
sealed class Pr5Background : Exception { }
static class GenericOuter<T>
{
    public sealed class Pr5Nested : Exception { }
}
