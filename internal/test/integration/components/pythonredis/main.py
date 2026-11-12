from fastapi import FastAPI
import os
import queue
import threading
import time
import uvicorn
import redis

app = FastAPI()

conn = None
redis_cli = None

@app.get("/redis")
async def query():
    global conn
    global redis_cli
    if conn is None:
        redis_cli = redis.Redis(
            host='redis',
            port=6379,
            decode_responses=True
            )
        conn = redis_cli.ping()

    # Do an HSET
    redis_cli.hset('user-session:123', mapping={
        'name': 'John',
        "surname": 'Smith',
        "company": 'Redis',
        "age": 29
    })

    # GET ALL
    redis_cli.hgetall('user-session:123')

    # Set a key
    redis_cli.set('obi', 'rocks')

    # Get the value of inserted key
    return redis_cli.get('obi')


def try_redis_command(client, *args):
    try:
        return client.execute_command(*args)
    except Exception as e:
        pass


@app.get("/redis-error")
def redis_error_test():
    global conn
    global redis_cli
    if conn is None:
        redis_cli = redis.Redis(
            host='redis',
            port=6379,
            decode_responses=True
        )
        conn = redis_cli.ping()

    # Try invalid command
    try_redis_command(redis_cli, 'INVALID_COMMAND')

    # insert a key
    redis_cli.set('obi-error', 'rocks')

    # try to push to a key that is not a list
    try_redis_command(redis_cli, 'LPUSH', 'obi-error', 'rocks more')

    # try to eval a script with an invalid SHA
    try_redis_command(redis_cli, 'EVALSHA', 'INVALID_SHA', '0')
    return 'done', 200

resp3_conn = None
resp3_cli = None

@app.get("/redis-resp3")
def redis_resp3_test():
    global resp3_conn
    global resp3_cli
    if resp3_conn is None:
        resp3_cli = redis.Redis(
            host='redis',
            port=6379,
            decode_responses=True,
            protocol=3  # RESP3: map/set/boolean/double/null reply frames
        )
        resp3_conn = resp3_cli.ping()

    # each op's reply is a RESP3-only frame type
    resp3_cli.sadd('obi-resp3-set', 'a', 'b')
    resp3_cli.sismember('obi-resp3-set', 'a')   # boolean #
    resp3_cli.smembers('obi-resp3-set')         # set ~
    resp3_cli.hset('obi-resp3-hash', mapping={'name': 'John', 'age': 29})
    resp3_cli.hgetall('obi-resp3-hash')         # map %
    resp3_cli.zadd('obi-resp3-zset', {'m1': 1.5})
    resp3_cli.zscore('obi-resp3-zset', 'm1')    # double ,
    resp3_cli.get('obi-resp3-missing')          # null _
    return 'done', 200

@app.get("/redis-db")
def redis_error_test():
    db1_redis_cli = redis.Redis(
        host='redis',
        port=6379,
        decode_responses=True,
        db=1  # Use a different database
    )

    db1_redis_cli.set('obi-db-1', 'rocks')
    db1_redis_cli.get('obi-db-1')

    return 'done', 200

pipeline_cli = None

@app.get("/redis-pipeline")
def redis_pipeline():
    global pipeline_cli
    if pipeline_cli is None:
        pipeline_cli = redis.Redis(
            host='redis',
            port=6379,
            decode_responses=True
            )

    # One socket write carrying four commands, which OBI parses into four spans
    pipe = pipeline_cli.pipeline(transaction=False)
    pipe.set('obi-pipeline-1', 'rocks')
    pipe.set('obi-pipeline-2', 'rocks')
    pipe.get('obi-pipeline-1')
    pipe.get('obi-pipeline-2')
    pipe.execute()

    return 'done', 200

# A fetch that takes a job while a request is served is one of the request's calls
@app.get("/redis-job-in-request")
def redis_job_in_request():
    cli = redis.Redis(host='redis', port=6379, decode_responses=True)
    cli.lpush('obi-jobs-request', 'request-job')
    job = cli.lpop('obi-jobs-request')
    cli.set('obi-job:' + job, 'running')
    cli.close()
    return 'done'


def background_pipeline_loop():
    while True:
        # A fresh connection each round so the commands are never parsed off a
        # socket that was already open before OBI attached
        bg_cli = redis.Redis(host='redis', port=6379, decode_responses=True)
        pipe = bg_cli.pipeline(transaction=False)
        pipe.sadd('obi-bg-set', 'a')
        pipe.sadd('obi-bg-set', 'b')
        pipe.smembers('obi-bg-set')
        pipe.smembers('obi-bg-set')
        pipe.execute()
        bg_cli.close()
        time.sleep(0.5)


# A pipeline with no inbound request behind it, so its commands have no parent
# span and each has to end up in a trace of its own. Started at import because
# the container runs uvicorn directly, so __main__ never executes.
threading.Thread(target=background_pipeline_loop, daemon=True).start()


def run_job(job):
    cli = redis.Redis(host='redis', port=6379, decode_responses=True)
    cli.set('obi-job:' + job, 'running')
    cli.get('obi-job:' + job)
    cli.close()


def thread_per_job(job):
    threading.Thread(target=run_job, args=(job,), daemon=True).start()


pool_jobs = queue.Queue()
pool_started = []


def pool_worker():
    while True:
        job = pool_jobs.get()
        # a busy pool picks the job up after the fetching thread went back to its queue
        time.sleep(0.3)
        run_job(job)


# the pool's thread starts with the first job and runs the later ones too
def pooled_job(job):
    if not pool_started:
        threading.Thread(target=pool_worker, daemon=True).start()
        pool_started.append(True)
    pool_jobs.put(job)


# a process per job, as RQ and Resque run them
def process_per_job(job):
    pid = os.fork()
    if pid == 0:
        run_job(job)
        os._exit(0)
    os.waitpid(pid, 0)


def job_loop(kind, handle, timeout=1):
    cli = redis.Redis(host='redis', port=6379, decode_responses=True)
    while True:
        item = cli.blpop('obi-jobs-' + kind, timeout=timeout)
        if item:
            handle(item[1])


def poll_loop():
    cli = redis.Redis(host='redis', port=6379, decode_responses=True)
    while True:
        job = cli.lpop('obi-jobs-poll')
        if job:
            run_job(job)
        else:
            time.sleep(0.2)


def stream_loop():
    cli = redis.Redis(host='redis', port=6379, decode_responses=True)
    try:
        cli.xgroup_create('obi-jobs-stream', 'workers', id='0', mkstream=True)
    except redis.ResponseError:
        pass
    while True:
        streams = cli.xreadgroup('workers', 'worker', {'obi-jobs-stream': '>'}, count=1, block=1000)
        for _, entries in streams or []:
            for entry_id, fields in entries:
                run_job(fields['job'])
                cli.xack('obi-jobs-stream', 'workers', entry_id)


# its fetches find nothing, so the call after each one has no job to belong to
def idle_loop():
    cli = redis.Redis(host='redis', port=6379, decode_responses=True)
    while True:
        cli.blpop('obi-jobs-idle', timeout=1)
        cli.incr('obi-idle')


# serves another connection while its fetch is pending, as an event loop does
def busy_loop():
    cli = redis.Redis(host='redis', port=6379, decode_responses=True)
    other = redis.Redis(host='redis', port=6379, decode_responses=True)
    conn = cli.connection_pool.get_connection()
    while True:
        conn.send_command('BLPOP', 'obi-jobs-busy', 1)
        other.ping()
        item = cli.parse_response(conn, 'BLPOP')
        if item:
            run_job(item[1])


precedence_worker = []


# its fetch waits for the job, so it goes out before the event loop thread serves
# the request the job runs during
def precedence_loop():
    # a fetch sent while the request that started this thread is served belongs to it
    time.sleep(0.5)
    job_loop('precedence', run_job, timeout=0)


# started from the event loop thread once OBI instruments the process, so OBI
# knows the worker as a thread that thread started
@app.get("/start-precedence-worker")
async def start_precedence_worker():
    if not precedence_worker:
        worker = threading.Thread(target=precedence_loop, daemon=True)
        worker.start()
        precedence_worker.append(worker)
    return 'started'


# keeps the thread that started the worker inside a request while the worker runs a job
@app.get("/slow")
async def slow():
    time.sleep(2)
    return 'done'


# Workers that take jobs off Redis, each job running on the fetching thread, on
# a thread or process of its own or on a reused pool thread
if os.environ.get('OBI_TEST_JOB_QUEUES'):
    for kind, handle in (('inline', run_job), ('thread', thread_per_job), ('pool', pooled_job),
                         ('process', process_per_job)):
        threading.Thread(target=job_loop, args=(kind, handle), daemon=True).start()
    for loop in (poll_loop, stream_loop, idle_loop, busy_loop):
        threading.Thread(target=loop, daemon=True).start()

if __name__ == "__main__":
    print(f"Server running: port={8080} process_id={os.getpid()}")
    uvicorn.run(app, host="0.0.0.0", port=8080)


# Run redis server as
# docker run --name redis-srv -p 6379:6379 redis    