using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;

namespace Routes;

[Route("api/[controller]")]
public class ProductsController : ControllerBase
{
    [HttpGet("[action]/{id}")]
    public object Get(int id) => id;

    [HttpPost("~/health")]
    public object Health() => "ok";

    [HttpQuery("~/search/{term}")]
    public object Search(string term) => term;

    [HttpGet("named/{id}", Name = "named", Order = 1)]
    public object Named(int id) => id;

    [HttpQueryV2("~/v2/search")]
    public object SearchV2() => "ok";

    [HttpFoo("FOO", "~/foo/{id}")]
    public object Foo(int id) => id;

    [HttpBar("BAR")]
    public object Bar() => "ok";

    [AcceptVerbs("GET", "POST", Route = "~/verbs/{id}")]
    public object Verbs(int id) => id;

    [AcceptVerbs("PUT", Route = "[action]")]
    public object Single() => "ok";

    [AcceptVerbs("DELETE")]
    public object NoRoute() => "ok";
}

public class HttpQueryAttribute(string template) : HttpMethodAttribute(["QUERY"], template);

public class HttpQueryV2Attribute(string template) : HttpQueryAttribute(template);

public class HttpFooAttribute(string verb, string template) : HttpMethodAttribute([verb], template);

public class HttpBarAttribute(string verb) : HttpMethodAttribute([verb]);

public static class Endpoints
{
    public static void Map(WebApplication app)
    {
        app.MapGet("/minimal/{id}", () => "ok");
        app.MapPost("/items", () => "ok");
        app.MapControllerRoute("default", "{controller=Home}/{action=Index}/{id?}");
    }

    public static T Echo<T>(T value) => value;

    public static string CallEcho() => Echo("value");
}
