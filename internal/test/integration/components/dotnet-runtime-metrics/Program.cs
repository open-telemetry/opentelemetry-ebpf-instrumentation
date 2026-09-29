// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Net;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
using System.Text.Json;

if (args is ["--http"])
{
    await RunHttp();
    return;
}

WriteSnapshot();

while (await Console.In.ReadLineAsync() is { } command)
{
    if (command == "gc")
    {
        GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: true);
    }
    else if (command != "snapshot")
    {
        throw new ArgumentException($"Unknown command: {command}");
    }

    WriteSnapshot();
}

static void WriteSnapshot()
{
    Console.WriteLine(JsonSerializer.Serialize(Snapshot()));
}

static object Snapshot()
{
    return RuntimeSnapshot.Capture();
}

static async Task RunHttp()
{
    using var listener = new HttpListener();
    listener.Prefixes.Add("http://*:8080/");
    listener.Start();
    _ = Snapshot();
    while (true)
    {
        var context = await listener.GetContextAsync();
        object? result = null;
        if (context.Request.HttpMethod == "POST" && context.Request.Url?.AbsolutePath == "/gc")
        {
            GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: true);
        }
        else if (context.Request.HttpMethod == "POST" && context.Request.Url?.AbsolutePath == "/load")
        {
            RuntimeLoad.Start();
        }
        else if (context.Request.HttpMethod == "POST" && context.Request.Url?.AbsolutePath == "/release")
        {
            RuntimeLoad.Release();
        }
        else if (context.Request.HttpMethod == "GET" && context.Request.Url?.AbsolutePath == "/load-result")
        {
            result = RuntimeLoad.Peak ?? throw new InvalidOperationException("Load has not reached its plateau");
        }
        else if (context.Request.HttpMethod != "GET" || context.Request.Url?.AbsolutePath != "/snapshot")
        {
            context.Response.StatusCode = 404;
            context.Response.Close();
            continue;
        }

        context.Response.ContentType = "application/json";
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(result ?? Snapshot());
        context.Response.ContentLength64 = payload.Length;
        await context.Response.OutputStream.WriteAsync(payload);
        context.Response.Close();
    }
}

sealed record RuntimeSnapshot(int pid, string runtimeVersion, int gen0, int gen1, int gen2,
    long workingSet, long gcCommitted, int threadCount, long queueLength, long timerCount, int assemblyCount)
{
    public static RuntimeSnapshot Capture() => new(
        Environment.ProcessId, Environment.Version.ToString(),
        GC.CollectionCount(0), GC.CollectionCount(1), GC.CollectionCount(2),
        Environment.WorkingSet, GC.GetGCMemoryInfo().TotalCommittedBytes,
        ThreadPool.ThreadCount, ThreadPool.PendingWorkItemCount,
        Timer.ActiveCount, AppDomain.CurrentDomain.GetAssemblies().Length);
}

static class RuntimeLoad
{
    private static readonly List<byte[]> memory = new();
    private static readonly List<Timer> timers = new();
    private static readonly List<AssemblyBuilder> assemblies = new();
    public static RuntimeSnapshot? Peak;

    public static void Start()
    {
        if (memory.Count != 0)
        {
            throw new InvalidOperationException("Load already active");
        }
        Allocate();
        GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: true);
        new Thread(HoldThreadPool) { IsBackground = true }.Start();
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void Allocate()
    {
        for (int i = 0; i < 128; i++)
        {
            var bytes = new byte[1024 * 1024];
            Array.Fill(bytes, (byte)1);
            memory.Add(bytes);
        }
        for (int i = 0; i < 32; i++)
        {
            timers.Add(new Timer(_ => { }, null, TimeSpan.FromHours(1), Timeout.InfiniteTimeSpan));
        }
        for (int i = 0; i < 16; i++)
        {
            var assembly = AssemblyBuilder.DefineDynamicAssembly(new AssemblyName($"Load{i}"), AssemblyBuilderAccess.RunAndCollect);
            assembly.DefineDynamicModule("Load").DefineType("LoadType").CreateType();
            assemblies.Add(assembly);
        }
    }

    private static void HoldThreadPool()
    {
        // Let the HTTP response finish before occupying every worker. EventCounters
        // run on the runtime's dedicated counter thread during this plateau.
        Thread.Sleep(TimeSpan.FromSeconds(1));
        ThreadPool.GetMinThreads(out int oldMin, out int minIO);
        ThreadPool.GetMaxThreads(out int oldMax, out int maxIO);
        using var release = new ManualResetEventSlim();
        using var started = new CountdownEvent(4);
        using var completed = new CountdownEvent(20);
        try
        {
            if (!ThreadPool.SetMinThreads(4, minIO) || !ThreadPool.SetMaxThreads(4, maxIO))
            {
                throw new InvalidOperationException("Cannot bound the thread pool");
            }
            for (int i = 0; i < 4; i++)
            {
                ThreadPool.QueueUserWorkItem(_ =>
                {
                    started.Signal();
                    release.Wait();
                    completed.Signal();
                });
            }
            if (!started.Wait(TimeSpan.FromSeconds(10)))
            {
                throw new TimeoutException("Thread-pool workers did not start");
            }
            for (int i = 0; i < 16; i++)
            {
                ThreadPool.QueueUserWorkItem(_ => completed.Signal());
            }
            Peak = RuntimeSnapshot.Capture();
            Thread.Sleep(TimeSpan.FromSeconds(30));
        }
        finally
        {
            release.Set();
            ThreadPool.SetMaxThreads(oldMax, maxIO);
            ThreadPool.SetMinThreads(oldMin, minIO);
            if (!completed.Wait(TimeSpan.FromSeconds(10)))
            {
                throw new TimeoutException("Thread-pool work did not drain");
            }
        }
    }

    public static void Release()
    {
        DropReferences();
        GC.Collect(GC.MaxGeneration, GCCollectionMode.Aggressive, blocking: true, compacting: true);
        GC.WaitForPendingFinalizers();
        GC.Collect(GC.MaxGeneration, GCCollectionMode.Aggressive, blocking: true, compacting: true);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void DropReferences()
    {
        foreach (var timer in timers)
        {
            timer.Dispose();
        }
        timers.Clear();
        assemblies.Clear();
        memory.Clear();
    }
}
