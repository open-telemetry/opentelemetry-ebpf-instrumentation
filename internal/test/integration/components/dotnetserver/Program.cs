using System.Text;

// Flush stdout after every write so the logenricher BPF program sees each JSON
// line before the HTTP response is returned to the caller. Without AutoFlush,
// .NET's StreamWriter buffers output and the write syscall may fire after the
// response, causing the enricher to miss the trace context for that request.
Console.OutputEncoding = Encoding.UTF8;
var autoFlushStdout = new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true };
Console.SetOut(autoFlushStdout);

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddHttpClient();
var app = builder.Build();

app.MapGet("/greeting", async (HttpClient httpClient) =>
        {
            var response = await httpClient.GetAsync("https://opentelemetry.io/");
            response.EnsureSuccessStatusCode();
            var content = await response.Content.ReadAsStringAsync();
            return Results.Ok(content);
        });
app.MapGet("/smoke", () => "");

app.MapGet("/json_logger", () =>
{
    const string message = "this is a json log from dotnet";
    Console.WriteLine("{\"message\":\"" + message + "\",\"level\":\"INFO\"}");
    return Results.Ok(message);
});

app.Run();
