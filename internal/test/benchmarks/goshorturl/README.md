# Go url shortener benchmark

This benchmark is designed to test the performance overhead of OBI Go auto instrumentation.
The application itself is designed to expose the overhead by doing very little work and
by triggering as many probes as possible. The response times of the HTTP server are in the tens
of micro seconds, where interrupts and eBPF uprobes overhead will show up.

## Running the benchmark

This is an HTTP application with mock SQL backend, based on a [customer reported issue](https://github.com/jaihindhreddy/go-testebpf).

### Setup

To run the test we need to:

1. Build the Go application with `go build -o shorturl main.go`.
2. Install a load generator. The example application here is provided
   with load generator script for [k6](https://github.com/grafana/k6).
   However the overhead of instrumentation can be reproduced with any
   other constant load generators like `wrk2` or `vegeta`.

### Start the Go HTTP service

We want to ensure our test results as accurate as possible, therefore it's important
to run this benchmark on a quiet machine and to pin the CPUs for the service as well
as the load generator.

```bash
taskset -c 0 ./shorturl
```

By default the application listens on port 8081, but you can change that if you'd
like by setting the `PORT` environment variable. For example `PORT=3000 taskset -c 0 ./shorturl`
will run the service on port 3000.

You can verify if the service works by running a `curl` command, for example:

```bash
curl --data-urlencode "url=https://example.com" http://localhost:8081/shorten
```

### Run the load generator

Run the load generator to establish a baseline for the application performance.

Assuming we are using `k6` we can run the provided example load script:

```bash
taskset -c 1 k6 run traffic.js
```

The example test load generator runs for 30 seconds, while pinned to another core.
We are using core 0 for the HTTP/SQL service and core 1 for the load generator.

The result of the load generator will produce typical web service metrics, like P50 and P90
response times. For example, below is an output of a baseline run on 12th Gen Intel(R) Core(TM) i7-1280P
running at 4GHz.

```
    HTTP
    http_req_duration.......................................................: avg=49.53µs min=32.49µs med=39.64µs max=4.26ms p(90)=64.99µs p(95)=83.76µs 
      { expected_response:true }............................................: avg=49.53µs min=32.49µs med=39.64µs max=4.26ms p(90)=64.99µs p(95)=83.76µs 
    http_req_failed.........................................................: 0.00%  0 out of 15001
    http_reqs...............................................................: 15001  500.019437/s
```

### Run OBI to see the impact of the performance

In another shell run OBI in a non-exporting mode to ensure the measured performance is just the BPF overhead.

```bash
sudo OTEL_EBPF_OPEN_PORT=8081 OTEL_EBPF_TRACE_PRINTER=counter bin/obi
```

Wait a few moments for OBI to instrument the application and launch again the load generation script.

```bash
taskset -c 1 k6 run traffic.js
```

When you terminate OBI, you should see it print something like:

```
Processed 30002 requests
```

Since the load generator generates 15001 requests total, we should see 30,0002 request and perhaps an optional connection
error for the termination.
