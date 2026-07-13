// BullMQ-style worker: a long-lived ioredis connection parked in a blocking
// BZPOPMIN, plus a producer connection. Both connections are established at
// boot, before the agent attaches, which is the scenario under test: the
// blocking reply is the first traffic the agent observes on the worker
// connection.
const http = require("http");
const Redis = require("ioredis");

const QUEUE = "bullmq:jobs";
const PORT = 3040;
// large enough that command capture must flow through the TCP large-buffer
// path (inline capture is 256B), small enough to fit a 4KB buffer_sizes.tcp
const BIG_PAYLOAD = "x".repeat(3800) + "-tailmarker";

const worker = new Redis({ host: "redis", port: 6379 });
const producer = new Redis({ host: "redis", port: 6379 });

let ready = false;
let jobsDone = 0;

async function workerLoop() {
  for (;;) {
    const job = await worker.bzpopmin(QUEUE, 5);
    if (!job) {
      continue;
    }
    // BullMQ runs its job state machine through Lua scripts; a missing sha
    // reproduces the NOSCRIPT error path
    await worker
      .evalsha("0000000000000000000000000000000000000000", 1, "bullmq:state")
      .catch(() => {});
    await worker.get("bullmq:state");
    await worker.set("bullmq:state", job[1]);
    await worker.set("bullmq:payload", BIG_PAYLOAD);
    await worker.get("bullmq:payload");
    jobsDone++;
  }
}

async function main() {
  await worker.ping();
  await producer.ping();
  ready = true;
  workerLoop();

  http
    .createServer(async (req, res) => {
      if (req.url === "/health") {
        res.writeHead(ready ? 200 : 503);
        res.end(ready ? "ok" : "starting");
        return;
      }
      if (req.url === "/job") {
        await producer.zadd(QUEUE, Date.now(), "job-" + Date.now());
        res.writeHead(200);
        res.end("queued");
        return;
      }
      if (req.url === "/done") {
        res.writeHead(200);
        res.end(String(jobsDone));
        return;
      }
      res.writeHead(404);
      res.end();
    })
    .listen(PORT);
}

main();
