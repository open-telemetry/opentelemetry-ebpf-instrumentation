using Grpc.AspNetCore.Server;
using Grpc.Core;
using Grpc.Net.Client;
using DotnetRelay.RelayProto;

var grpcPort = Environment.GetEnvironmentVariable("GRPC_PORT") ?? "50056";
var nextHop = Environment.GetEnvironmentVariable("NEXT_HOP") ?? "";
var healthPort = Environment.GetEnvironmentVariable("HEALTH_PORT") ?? "8095";

// HTTP/2 cleartext (h2c) — matches every other relay in the chain
AppContext.SetSwitch("System.Net.Http.SocketsHttpHandler.Http2UnencryptedSupport", true);

var builder = WebApplication.CreateBuilder();
builder.Services.AddGrpc();
builder.WebHost.ConfigureKestrel(opts =>
{
    opts.ListenAnyIP(int.Parse(grpcPort), lo => lo.Protocols = Microsoft.AspNetCore.Server.Kestrel.Core.HttpProtocols.Http2);
    opts.ListenAnyIP(int.Parse(healthPort)); // HTTP/1.1 health
});

var app = builder.Build();
app.MapGrpcService<RelayService>();
app.MapGet("/health", () => Results.Ok());

await app.RunAsync();

internal sealed class RelayService : Relay.RelayBase
{
    public override async Task<RelayResponse> Relay(RelayRequest request, ServerCallContext context)
    {
        Console.WriteLine("received Relay RPC");
        var hop = Environment.GetEnvironmentVariable("NEXT_HOP");
        if (!string.IsNullOrEmpty(hop))
        {
            using var channel = GrpcChannel.ForAddress($"http://{hop}");
            var client = new Relay.RelayClient(channel);
            await client.RelayAsync(new RelayRequest(), deadline: DateTime.UtcNow.AddSeconds(10));
        }
        return new RelayResponse();
    }
}
