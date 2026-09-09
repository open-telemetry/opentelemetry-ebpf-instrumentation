using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc;

namespace Routes;

[Route("api/[controller]")]
public class ProductsController : ControllerBase
{
    [HttpGet("[action]/{id}")]
    public object Get(int id) => id;

    [HttpPost("~/health")]
    public object Health() => "ok";
}

public static class Endpoints
{
    public static void Map(WebApplication app)
    {
        app.MapGet("/minimal/{id}", () => "ok");
        app.MapPost("/items", () => "ok");
    }

    public static T Echo<T>(T value) => value;

    public static string CallEcho() => Echo("value");
}
