from fastapi import FastAPI
import os
import uvicorn
import psycopg

app = FastAPI()

DB_CONFIG = {
    "dbname": "sqltest",
    "user": "postgres",
    "password": "postgres",
    "host": "sqlserver",
    "port": "5432",
}

@app.get("/query")
async def query():
    conn = psycopg.connect(**DB_CONFIG)
    cur = conn.cursor()
    cur.execute("SELECT * FROM accounting.contacts WHERE id = 1")
    cur.close()
    conn.close()
    return {"status": "OK"}

@app.get("/argquery")
async def argquery():
    conn = psycopg.connect(**DB_CONFIG)
    cur = conn.cursor()
    cur.execute("SELECT * FROM accounting.contacts WHERE id = %s", (1,))
    cur.close()
    conn.close()
    return {"status": "OK"}

# Use psycopg3 + prepare=True to test prepared statements
#
# https://github.com/psycopg/psycopg/discussions/492
@app.get("/prepquery")
async def prepquery():
    conn = psycopg.connect(**DB_CONFIG)
    cur = conn.cursor()
    cur.execute("SELECT * FROM accounting.contacts WHERE id = %s", (1,), prepare=True)
    cur.close()
    conn.close()
    return {"status": "OK"}

@app.get("/error")
async def error():
    conn = psycopg.connect(**DB_CONFIG)
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM obi.nonexisting")
    except Exception:
        pass
    cur.close()
    conn.close()
    return {"status": "OK"}

# Reproduces https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/1464.
#
# psycopg's pipeline mode batches several extended-protocol statements into the
# same TCP send. Each parameterized statement is a Parse/Bind/Describe/Execute
# group, so a handful of them (plus the trailing Sync) easily exceeds the
# k_pg_messages_in_packet_max (10) messages the eBPF classifier walks in a
# single segment. The classifier used to require message_size == data_len and
# rejected such segments, so the connection was never recognized as Postgres and
# produced no traces. accounting.invoices is queried only here, so a trace for
# it proves this multi-message connection was classified.
@app.get("/pipeline")
async def pipeline():
    conn = psycopg.connect(**DB_CONFIG)
    try:
        with conn.pipeline():
            with conn.cursor() as cur:
                for i in range(1, 6):
                    cur.execute("SELECT * FROM accounting.invoices WHERE id = %s", (i,))
    finally:
        conn.close()
    return {"status": "OK"}

if __name__ == "__main__":
    print(f"Server running: port={8080} process_id={os.getpid()}")
    uvicorn.run(app, host="0.0.0.0", port=8080)
