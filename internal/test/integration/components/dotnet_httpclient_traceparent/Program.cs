var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls("http://0.0.0.0:8080");

var downstream = Environment.GetEnvironmentVariable("DOWNSTREAM_URL") ?? "http://downstream:8086";
builder.Services.AddHttpClient("downstream", client => client.BaseAddress = new Uri(downstream));

var app = builder.Build();

app.MapGet("/health", () => Results.Ok());

// .NET only propagates a traceparent it received, so callers must send one. The
// downstream echoes what arrived on the outgoing HTTP/1 request.
app.MapGet("/call", async (string id, IHttpClientFactory clients) =>
{
    // Resume on a thread-pool thread, which need not be the one that read the request.
    await Task.Delay(TimeSpan.FromMilliseconds(20));

    var response = await clients.CreateClient("downstream").GetAsync($"/record?id={Uri.EscapeDataString(id)}");
    var body = await response.Content.ReadAsStringAsync();
    return Results.Content(body, "application/json", statusCode: (int)response.StatusCode);
});

app.Run();
