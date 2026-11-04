# Node.js Agent overhead test

This benchmark is an OBI Node.js agent overhead test, designed to test the overhead we introduce into a Node.js application with our OBI agent.
It's based on our Node.js example that tests distributed traces, with asynchronous client calls, which always force the client to be on
a different node event loop async id.

The current state of the benchmark only has versions for the improvement to handling file descriptor correlation.

To eliminate variability and expose the corrent performance issue, the benchmark setup was designed as follows:

```
Load generator -> Service B (the test service) -> Service R (server)
```

We only measure the impact of the agent on Service B, that's our service for analysis. Service R is here just to allow us to
perform the downstream client call on a local service with minimal delay, exposing the overhead the agent will introduce.

The Service B comes in three flavours:

- Basline
- With the OBI fdextractor.js enabled for tracing
- With the OBI fdextractor.js optimized with local FD cache

## Setting up the benchmark

First, install the Node dependencies for the benchmark services:

```
npm ci
```

## Running the benchmark

It's important to separate each service on their own individual cores, to avoid benchmark variability.

I ran this benchmark on the following hardware:

```
AMD Ryzen AI 9 HX PRO 370 with 12 cores and 24 threads, boosting up to approximately 5.16 GHz, running Ubuntu 24.04.5 LTS (Linux 6.17.0-1033-oem) and Node.js v24.14.1.
```

Since I had 12 physical cores, I split the benchmark as follows:

- Core 0 - reserved for Service B which we are testing, so that we can push the overhead to 100% of CPU utilization.
- Cores 1, 2 - reserved for Service R. This was an overkill because Service R doesn't go beyond 20%.
- Cores 3, 4, 5 - reserved for the load generator.

First start the service we are not testing, Service R:

```
taskset -c 1,2 node service-r
```

Next start Service B in the mode you want to test, e.g. baseline:

```
taskset -c 0 node service-b
```

Finally run the load generator:

```
cd loadgen
taskset -c 3,4,5 ./load.sh
```

I used k6 for the load generator with constant workload generation to saturate one CPU for Service B. To run the benchmark as-is, you'll
need to either install k6 or use another load generator that has constant load generation mode, e.g. wrk2 or vegeta.
