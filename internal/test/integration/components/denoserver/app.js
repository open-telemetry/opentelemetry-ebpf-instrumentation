// Native Deno HTTP test server.
//
// Unlike the node-compat server under ../nodejsserver (Express on top of
// node:http), this uses only native Deno APIs: Deno.serve for incoming requests
// and the global fetch() for outgoing calls. There is no express, node:http,
// node:https or node:net dependency, so it exercises the native Deno code paths.

const port = 3030;

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

async function makeHttpsRequest(hostname, path) {
  const res = await fetch(`https://${hostname}${path}`, {
    headers: { "User-Agent": "OBI-APM-Test/1.0.0" },
    signal: AbortSignal.timeout(10000),
  });
  const raw = await res.text();
  try {
    return JSON.parse(raw);
  } catch {
    return { raw, statusCode: res.status };
  }
}

async function handler(req) {
  const url = new URL(req.url);
  const path = url.pathname;
  const method = req.method;

  if (method === "GET" && path === "/greeting") {
    return json("Hello!");
  }
  if (method === "POST" && path === "/greeting") {
    return json(await req.json());
  }
  if (method === "GET" && path === "/bye") {
    return json("Goodbye!");
  }
  if (method === "POST" && path === "/bye") {
    return json(await req.json());
  }
  if (method === "GET" && path === "/smoke") {
    return new Response("OK", { status: 200 });
  }

  const userURL = new URLPattern({ pathname: "/users/:id" });
  const user = userURL.exec(req.url);
  if (method === "GET" && user) {
    return json("Hello! " + user.pathname.groups.id);
  }

  if (method === "GET" && path === "/dist") {
    // redirect: "manual" so we observe the upstream 301 instead of following it.
    const r = await fetch("http://grafana.com", { redirect: "manual" });
    await r.body?.cancel();
    if (r.status !== 301) {
      console.error(`Did not get an OK from the server. Code: ${r.status}`);
      return new Response(null, { status: 500 });
    }
    return new Response(null, { status: 200 });
  }

  // Plain-HTTP nested call: the server makes an outgoing HTTP (not HTTPS) request
  // to a local endpoint. Exercises trace-context propagation on runtimes whose
  // TLS OBI cannot decrypt (Deno / rustls).
  if (method === "GET" && path === "/nested-plain-target") {
    return json("nested target");
  }
  if (method === "GET" && path === "/nested-plain") {
    try {
      const r = await fetch(`http://localhost:${port}/nested-plain-target`);
      await r.text();
      return json("nested done");
    } catch (error) {
      console.error("nested-plain error:", error.message);
      return new Response(null, { status: 500 });
    }
  }

  if (method === "GET" && path === "/traceme") {
    const r = await fetch("http://testserver:8080/gotracemetoo");
    await r.body?.cancel();
    if (r.status !== 200) {
      console.error(`Did not get an OK from the server. Code: ${r.status}`);
      return new Response(null, { status: 500 });
    }
    return new Response(null, { status: 200 });
  }

  if (method === "GET" && path === "/api/test-apm") {
    const results = {
      message: "APM test completed - external API calls made for tracing",
      Api: { status: "unknown", success: false, data: null },
      SecondApi: { status: "unknown", success: false, data: null },
    };
    try {
      results.Api.data = await makeHttpsRequest("opentelemetry.io", "/");
      results.Api.status = "success";
      results.Api.success = true;
    } catch (error) {
      results.Api.status = `error: ${error.message}`;
    }
    try {
      results.SecondApi.data = await makeHttpsRequest("www.cncf.io", "/");
      results.SecondApi.status = "success";
      results.SecondApi.success = true;
    } catch (error) {
      results.SecondApi.status = `error: ${error.message}`;
    }
    return json(results);
  }

  if (method === "GET" && path === "/json_logger") {
    // Fixed async delay so concurrent in-flight requests interleave in the
    // event loop.
    await new Promise((resolve) => setTimeout(resolve, 35));
    const message = "this is a json log from deno";
    console.log(JSON.stringify({ message, level: "INFO" }));
    return new Response(message, { status: 200 });
  }

  return new Response("Not Found", { status: 404 });
}

Deno.serve({ port, hostname: "0.0.0.0" }, handler);
