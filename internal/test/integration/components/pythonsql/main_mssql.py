from fastapi import FastAPI
import os
import uvicorn
import pymssql

app = FastAPI()

conn = None

def get_conn():
    global conn
    if conn is None:
        conn = pymssql.connect(
            server="sqlserver",
            user="sa",
            password="p_ssW0rd",
            database="testdb",
            autocommit=True
        )
    return conn

@app.get("/query")
async def root():
    c = get_conn()
    cur = c.cursor()
    cur.execute("SELECT * FROM actor WHERE actor_id=1")
    row = cur.fetchone()
    cur.close()
    return row

@app.get("/argquery")
async def argquery():
    c = get_conn()
    cur = c.cursor()
    # pymssql uses %s or %d for placeholders
    cur.execute("SELECT * FROM actor WHERE actor_id=%d", (1,))
    row = cur.fetchone()
    cur.close()
    return row

@app.get("/prepquery")
async def prepquery():
    c = get_conn()
    cur = c.cursor()
    # Parameterized query intended to exercise prepared statement handling
    # Uses the same pattern as /argquery
    sql = "SELECT * FROM actor WHERE actor_id = %d"
    cur.execute(sql, (1,))
    row = cur.fetchone()
    cur.close()
    return row

@app.get("/largeresult")
async def largeresult():
    c = get_conn()
    cur = c.cursor()
    # Returns 50 rows with 48-char padded names. The total response exceeds the
    # default 4096-byte TDS packet size, forcing a multi-packet server response.
    cur.execute("SELECT * FROM bulk_actor")
    rows = cur.fetchall()
    cur.close()
    return {"count": len(rows)}

@app.get("/error")
async def error():
    c = get_conn()
    cur = c.cursor()
    try:
        cur.execute("SELECT * FROM obi.nonexisting")
    except Exception as e:
        pass
    finally:
        cur.close()
    return ""

if __name__ == "__main__":
    print(f"Server running: port={8080} process_id={os.getpid()}")
    uvicorn.run(app, host="0.0.0.0", port=8080)
