# Queue Job Traces

A worker that takes jobs off a Redis queue serves no request, so on its own
every call it makes would start a trace of its own. OBI instead makes the fetch
that took the job the root of the job's trace, and parents the job's calls under
it.

## Fetches

A client request that is one of these commands is a fetch:

| Kind                   | Commands                                                       |
| ---------------------- | -------------------------------------------------------------- |
| List pops and moves    | `BLPOP`, `BRPOP`, `BLMOVE`, `BRPOPLPUSH`, `BLMPOP`, `LPOP`, `RPOP`, `LMOVE`, `RPOPLPUSH`, `LMPOP` |
| Sorted set pops        | `BZPOPMIN`, `BZPOPMAX`, `BZMPOP`, `ZPOPMIN`, `ZPOPMAX`, `ZMPOP` |
| Stream reads           | `XREADGROUP`, `XREAD`, `XCLAIM`, `XAUTOCLAIM`                   |

The fetch takes a job when its reply carries an element: nil, an empty reply or
an error takes none. The recognizer is in `bpf/generictracer/redis_job_fetch.h`.

## When a fetch starts a job

- The fetch is not part of a request: a fetch made while serving one is one of
  its calls.
- The thread waited for the reply: a thread that touches another connection
  while the fetch is pending, such as an event loop or a client library's I/O
  thread, runs several jobs at once, so its calls can't be told apart.
- The thread doesn't run Python asyncio tasks, for the same reason.

The job lasts until the thread's next fetch. The thread's calls are parented
under the fetch unless the thread serves a request of its own, which comes
first; a request served by an ancestor thread comes after the job.

## Threads and processes started by the job

A thread or process that the fetching thread starts while it runs the job runs
that job too, which covers a thread or a process per job. A program it executes
doesn't. Threads those children start don't inherit the job, because helpers
started on demand outlive the job that started them.

A fetching thread that runs a job without starting a thread or process for it,
either running the job itself or handing it to a pool, starts threads that
outlive jobs. From then on the jobs inherited from it are ignored: a pool thread
started during one job would otherwise put the next jobs it runs in that job's
trace.

## Not covered

- Go: goroutines move between threads, so the job would need to follow the
  goroutine.
- Handoffs that only a runtime sees: Java executors, Python asyncio tasks.
- Jobs taken by Lua scripts (`EVAL`, `EVALSHA`, `FCALL`) and pub/sub deliveries.
- A fetch that returns several jobs starts one trace for all of them.
