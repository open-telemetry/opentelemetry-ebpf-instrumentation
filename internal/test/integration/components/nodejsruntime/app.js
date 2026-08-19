// Test application for Node.js runtime metrics (nodejs.eventloop.*).
//
// Self-contained (no npm dependencies). Exposes endpoints that drive the
// event loop into known states (busy, idle, mixed) and a ground-truth
// endpoint that reports Node's own perf_hooks readings, so eBPF-derived
// values can be compared against the in-process reference.

const http = require("http");
const { monitorEventLoopDelay, performance } = require("perf_hooks");

// Synchronously block the event loop for `ms` milliseconds.
function spin(ms) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    // busy-wait
  }
}

const port = 3030;
const histogram = monitorEventLoopDelay({ resolution: 10 });
histogram.enable();

const NS_PER_SEC = 1e9;
const MS_PER_SEC = 1e3;

function groundTruth() {
  const elu = performance.eventLoopUtilization(); // ms since loop start
  return {
    pid: process.pid,
    uptime_s: process.uptime(),
    elu: {
      idle_s: elu.idle / MS_PER_SEC,
      active_s: elu.active / MS_PER_SEC,
      utilization: elu.utilization,
    },
    // monitorEventLoopDelay histogram values are nanoseconds
    delay: {
      min_s: histogram.min / NS_PER_SEC,
      max_s: histogram.max / NS_PER_SEC,
      mean_s: histogram.mean / NS_PER_SEC,
      stddev_s: histogram.stddev / NS_PER_SEC,
      p50_s: histogram.percentile(50) / NS_PER_SEC,
      p90_s: histogram.percentile(90) / NS_PER_SEC,
      p99_s: histogram.percentile(99) / NS_PER_SEC,
      samples: histogram.count,
    },
  };
}

function json(res, code, body) {
  res.writeHead(code, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const ms = Number(url.searchParams.get("ms"));

  switch (url.pathname) {
    case "/smoke":
      return json(res, 200, { ok: true });

    // Block the loop synchronously: drives delay.* samples up and forces
    // poll timeout overshoot / zero-timeout (active) polls.
    case "/busy": {
      const blockMs = Number.isFinite(ms) && ms > 0 ? ms : 200;
      spin(blockMs);
      return json(res, 200, { blocked_ms: blockMs });
    }

    // Async wait: the loop parks in epoll with a timeout -> idle time accrues
    // while the request is still in flight.
    case "/async": {
      const waitMs = Number.isFinite(ms) && ms > 0 ? ms : 100;
      setTimeout(() => json(res, 200, { waited_ms: waitMs }), waitMs);
      return;
    }

    // Ground truth: Node's own readings of the target metrics.
    case "/ground-truth":
      return json(res, 200, groundTruth());

    default:
      return json(res, 404, { error: "not found" });
  }
});

server.listen(port, () => {
  console.log(`nodejs runtime-metrics test app listening on :${port}, pid ${process.pid}`);
});
