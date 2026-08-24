var express = require("express");
const http = require("http");
const https = require("https");
const { trace, SpanStatusCode } = require("@opentelemetry/api");
var app = express();
const port = 3030;

app.use(express.json({ limit: "50mb" }));

// Uses ONLY @opentelemetry/api, with no SDK registered: these spans are
// no-op/non-recording unless OBI's Node.js span bridge is injected
// (OTEL_EBPF_NODEJS_MANUAL_SPANS=true). The tracer is acquired at module
// load, before OBI injects the bridge, so it exercises the late-attach path.
const tracer = trace.getTracer("nodejs-manual-test", "1.0.0");

// Span names here are deliberately distinct from OBI's own automatic
// sub-span names ("in queue", "processing") that it adds to every HTTP
// server span, so the assertions can tell them apart.
app.get("/manual", (req, res, next) => {
  // Root manual span. OBI re-anchors it onto the in-flight request context,
  // i.e. it becomes a child of OBI's automatic "processing" sub-span.
  tracer.startActiveSpan("checkout", (checkout) => {
    checkout.setAttribute("cart.items", 3);

    // Plain (non-active) child of checkout.
    const validate = tracer.startSpan("validate-cart");
    validate.setAttribute("valid", true);
    validate.end();

    // Nested active span, so its own children nest under it.
    tracer.startActiveSpan("charge-card", (charge) => {
      charge.setAttribute("amount.cents", 4999);
      charge.setStatus({ code: SpanStatusCode.ERROR, message: "card declined" });

      const ledger = tracer.startSpan("ledger-write");
      ledger.setAttribute("account", "acct-1");
      ledger.updateName("ledger-commit");
      ledger.end();

      charge.end();
    });

    checkout.end();
    res.sendStatus(200);
  });
});

// Background manual spans, deliberately created OUTSIDE any request context:
// the interval callback runs with no request in its async context. If one
// fires while a request is still in flight, the kernel-side context map must
// have been cleared (fdextractor's no-request signal) so the span is NOT
// re-anchored into that request's trace. unref() keeps the timer from holding
// the process open.
setInterval(() => {
  tracer.startSpan("bg-tick").end();
}, 100).unref();

// A slow handler that stays in flight long enough for several bg-tick spans
// to fire in between its callbacks. The timer created INSIDE the handler runs
// within the request's async context, so slow-op must still re-anchor onto
// the request trace even after bg-tick callbacks cleared the kernel context.
app.get("/manual-slow", (req, res) => {
  setTimeout(() => {
    tracer.startActiveSpan("slow-op", (s) => {
      s.end();
      res.sendStatus(200);
    });
  }, 300);
});

app.get("/greeting", (req, res, next) => {
  res.json("Hello!");
});

app.post("/greeting", (req, res, next) => {
  res.json(req.body);
});

app.get("/bye", (req, res, next) => {
  res.json("Goodbye!");
});

app.post("/bye", (req, res, next) => {
  res.json(req.body);
});

app.get("/smoke", (req, res, next) => {
  res.sendStatus(200);
});

app.get("/users/:userId", (req, res, next) => {
  res.json("Hello! " + req.params.userId);
});


app.get("/dist", (req, res, next) => {
  http.get("http://grafana.com", {}, (r) => {
    if (r.statusCode !== 301) {
      console.error(`Did not get an OK from the server. Code: ${r.statusCode}`);
      res.sendStatus(500);
      return;
    }
    res.sendStatus(200);
  });
});

app.get("/traceme", (req, res, next) => {
  http.get("http://testserver:8080/gotracemetoo", {}, (r) => {
    if (r.statusCode !== 200) {
      console.error(`Did not get an OK from the server. Code: ${r.statusCode}`);
      res.sendStatus(500);
      return;
    }
    res.sendStatus(200);
  });
});

// Helper function to make HTTPS requests
function makeHttpsRequest(hostname, path) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: hostname,
      path: path,
      method: "GET",
      timeout: 10000,
      headers: {
        "User-Agent": "OBI-APM-Test/1.0.0",
      },
    };

    const req = https.request(options, (res) => {
      let data = "";

      res.on("data", (chunk) => {
        data += chunk;
      });

      res.on("end", () => {
        try {
          const jsonData = JSON.parse(data);
          resolve(jsonData);
        } catch (parseError) {
          resolve({ raw: data, statusCode: res.statusCode });
        }
      });
    });

    req.on("error", (error) => {
      reject(error);
    });

    req.on("timeout", () => {
      req.destroy();
      reject(new Error("Request timeout"));
    });

    req.end();
  });
}

app.get("/api/test-apm", async (req, res) => {
  const results = {
    message: "APM test completed - external API calls made for tracing",
    Api: { status: "unknown", success: false, data: null },
    SecondApi: { status: "unknown", success: false, data: null },
  };

  try {
    // Call first external API with a lot of data
    try {
      const firstResponse = await makeHttpsRequest("opentelemetry.io", "/");
      results.Api.status = "success";
      results.Api.success = true;
      results.Api.data = firstResponse;
    } catch (error) {
      results.Api.status = `error: ${error.message}`;
      results.Api.success = false;
    }

    // Call second external API with a lot of data
    try {
      const secondResponse = await makeHttpsRequest("www.cncf.io", "/");
      results.SecondApi.status = "success";
      results.SecondApi.success = true;
      results.SecondApi.data = secondResponse;
    } catch (error) {
      results.SecondApi.status = `error: ${error.message}`;
      results.SecondApi.success = false;
    }

    res.json(results);
  } catch (error) {
    console.error("APM test error:", error);
    res.status(500).json({
      message: "APM test failed",
      error: error.message,
      ...results,
    });
  }
});

app.get("/json_logger", (_req, res) => {
  // Fixed async delay so all concurrent in-flight callbacks interleave inside
  // the libuv event loop, exercising the traces_ctx_v1 context-switch fix.
  setTimeout(() => {
    const message = "this is a json log from node";
    process.stdout.write(JSON.stringify({ message, level: "INFO" }) + "\n");
    res.send(message);
  }, 35);
});

app.listen(port, () => {
  console.log("Server running on port " + port);
});
