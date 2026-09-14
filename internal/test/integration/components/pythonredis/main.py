from fastapi import FastAPI
import os
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

if __name__ == "__main__":
    print(f"Server running: port={8080} process_id={os.getpid()}")
    uvicorn.run(app, host="0.0.0.0", port=8080)


# Run redis server as
# docker run --name redis-srv -p 6379:6379 redis    