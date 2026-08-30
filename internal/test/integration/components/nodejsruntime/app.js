// Test application for Node.js runtime metrics (nodejs.eventloop.* and
// v8js.*).
//
// Self-contained (no npm dependencies). Exposes endpoints that drive the
// event loop and the V8 heap into known states, plus a ground-truth endpoint
// that reports Node's own perf_hooks/v8 readings, so eBPF-derived values can
// be compared against the in-process reference. Run with --expose-gc (the
// /gc endpoint needs global.gc).

const http = require("http");
const v8 = require("v8");
const {
  monitorEventLoopDelay,
  performance,
  PerformanceObserver,
  constants,
} = require("perf_hooks");

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

// Independent GC observation for the ground truth: counts per semconv
// v8js.gc.type value, so the exported histogram counts can be compared
// against an in-process reference.
const gcCounts = { major: 0, minor: 0, incremental: 0, weakcb: 0 };
const gcKindNames = {
  [constants.NODE_PERFORMANCE_GC_MAJOR]: "major",
  [constants.NODE_PERFORMANCE_GC_MINOR]: "minor",
  [constants.NODE_PERFORMANCE_GC_INCREMENTAL]: "incremental",
  [constants.NODE_PERFORMANCE_GC_WEAKCB]: "weakcb",
};
new PerformanceObserver((list) => {
  for (const entry of list.getEntries()) {
    const name = gcKindNames[entry.detail && entry.detail.kind];
    if (name) gcCounts[name]++;
  }
}).observe({ entryTypes: ["gc"] });

// Objects retained by /alloc so the allocated heap memory survives GC.
const retained = [];

// Intervals retained by /resources: each pending interval is one live
// "Timeout" entry in process.getActiveResourcesInfo().
const resourceTimers = [];

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
    // v8js.* ground truth: per-space heap statistics (bytes) and GC counts
    heap_spaces: Object.fromEntries(
      v8.getHeapSpaceStatistics().map((s) => [
        s.space_name,
        {
          size: s.space_size,
          used: s.space_used_size,
          available: s.space_available_size,
          physical: s.physical_space_size,
        },
      ]),
    ),
    gc_counts: { ...gcCounts },
    // v8js.resource.active ground truth: one array entry per live resource,
    // folded into a type -> count map
    resource_counts: process.getActiveResourcesInfo().reduce((counts, name) => {
      counts[name] = (counts[name] || 0) + 1;
      return counts;
    }, {}),
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

    // Retain `mb` megabytes of heap objects (arrays of numbers, so the
    // memory lives in the V8 heap — Buffers would be external memory and
    // invisible to the heap-space metrics).
    case "/alloc": {
      const mb = Number(url.searchParams.get("mb")) || 10;
      for (let i = 0; i < mb; i++) {
        // ~1 MB of doubles per array
        retained.push(new Array(128 * 1024).fill(i + Math.random()));
      }
      return json(res, 200, { retained_mb: retained.length });
    }

    // Force a full (major) collection; requires --expose-gc.
    case "/gc": {
      if (typeof global.gc !== "function") {
        return json(res, 500, { error: "run node with --expose-gc" });
      }
      global.gc();
      return json(res, 200, { gc: "done", counts: gcCounts });
    }

    // Retain `timers` never-firing intervals, clearing any previous batch,
    // so the live "Timeout" resource count can be driven up and back down.
    case "/resources": {
      const timers = Number(url.searchParams.get("timers")) || 0;
      while (resourceTimers.length > 0) {
        clearInterval(resourceTimers.pop());
      }
      for (let i = 0; i < timers; i++) {
        // max timer delay (~24.8 days): never fires during a test run
        resourceTimers.push(setInterval(() => {}, 2 ** 31 - 1));
      }
      return json(res, 200, { timers: resourceTimers.length });
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
