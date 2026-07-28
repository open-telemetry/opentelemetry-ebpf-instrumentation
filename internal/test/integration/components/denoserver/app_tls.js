// Native Deno HTTPS test server (TLS counterpart of app.js).
//
// Uses only native Deno APIs: Deno.serve with cert/key for TLS termination and
// the global fetch() for outgoing calls. No express / node:http / node:https.

const port = 3033;

const cert = Deno.readTextFileSync(new URL("./cert.pem", import.meta.url));
const key = Deno.readTextFileSync(new URL("./key.pem", import.meta.url));

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
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
  if (method === "GET" && path === "/smoke") {
    return new Response("OK", { status: 200 });
  }
  if (method === "GET" && path === "/traceme") {
    const r = await fetch("https://pytestserverssl:8380/tracemetoo");
    await r.body?.cancel();
    if (r.status !== 200) {
      console.error(`Did not get an OK from the server. Code: ${r.status}`);
      return new Response(null, { status: 500 });
    }
    return new Response(null, { status: 200 });
  }

  return new Response("Not Found", { status: 404 });
}

Deno.serve({ port, hostname: "0.0.0.0", cert, key }, handler);
