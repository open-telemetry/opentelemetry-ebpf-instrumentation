// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Net;
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
    return new
    {
        pid = Environment.ProcessId,
        runtimeVersion = Environment.Version.ToString(),
        gen0 = GC.CollectionCount(0),
        gen1 = GC.CollectionCount(1),
        gen2 = GC.CollectionCount(2),
    };
}

static async Task RunHttp()
{
    using var listener = new HttpListener();
    listener.Prefixes.Add("http://*:8080/");
    listener.Start();
    while (true)
    {
        var context = await listener.GetContextAsync();
        if (context.Request.HttpMethod == "POST" && context.Request.Url?.AbsolutePath == "/gc")
        {
            GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: true);
        }
        else if (context.Request.HttpMethod != "GET" || context.Request.Url?.AbsolutePath != "/snapshot")
        {
            context.Response.StatusCode = 404;
            context.Response.Close();
            continue;
        }

        context.Response.ContentType = "application/json";
        await JsonSerializer.SerializeAsync(context.Response.OutputStream, Snapshot());
        context.Response.Close();
    }
}
