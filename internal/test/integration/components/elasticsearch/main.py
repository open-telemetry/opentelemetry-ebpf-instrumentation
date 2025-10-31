from fastapi import FastAPI, HTTPException
import os
import uvicorn
import requests
import json
import time
import sys

app = FastAPI()
HEADERS = {'Content-Type': 'application/json'}
ELASTICSEARCH_HOST = "http://elasticsearchserver:9200"

@app.get("/health")
async def health():
    HEALTH_URL = ELASTICSEARCH_HOST + "/_cluster/health"
    
    try:
        response = requests.get(HEALTH_URL, timeout=5)
        response.raise_for_status() 
        status = response.json().get("status", "red")
        
        if status in ("red","yellow"):
            raise HTTPException(
                status_code=503, 
                detail={"status": "red","message": "Elasticsearch cluster unhealthy"})
        return {"status": status, "message": "Elasticsearch cluster healthy"}

    except requests.RequestException as e:
        raise HTTPException(
            status_code=503, 
            detail={"status": "error","message": f"Cannot reach Elasticsearch cluster: {str(e)}"})

@app.get("/doc")
async def doc():
    ELASTICSEARCH_URL = ELASTICSEARCH_HOST + "/test_index/_doc/1"
    
    try:
        response = requests.get(ELASTICSEARCH_URL, headers=HEADERS)

    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)
    return {"status": "OK"}


@app.get("/search")
async def search():
    ELASTICSEARCH_URL = ELASTICSEARCH_HOST + "/test_index/_search"
    query_body = {
        "query": {
            "match": {
                "name": "OBI"
                }
            }
        }
    try:
        response = requests.post(ELASTICSEARCH_URL, json=query_body, headers=HEADERS)

    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)
    return {"status": "OK"}

@app.get("/msearch")
async def msearch():
    ELASTICSEARCH_URL = ELASTICSEARCH_HOST + "/_msearch"
    searches = [
        {},
        {
            "query": {
                "match": {
                    "message": "this is a test"
                }
            }
        },
        {
            "index": "my-index-000002"
        },
        {
            "query": {
                "match_all": {}
            }
        }
    ]
    try:
        response = requests.post(ELASTICSEARCH_URL, json=searches, headers=HEADERS)

    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)
    return {"status": "OK"}


@app.get("/bulk")
async def bulk():
    ELASTICSEARCH_URL = ELASTICSEARCH_HOST + "/_bulk"
    actions=[
        {
            "index": {
                "_index": "test",
                "_id": "1"
            }
        },
        {
            "field1": "value1"
        },
        {
            "delete": {
                "_index": "test",
                "_id": "2"
            }
        },
        {
            "create": {
                "_index": "test",
                "_id": "3"
            }
        },
        {
            "field1": "value3"
        },
        {
            "update": {
                "_id": "1",
                "_index": "test"
            }
        },
        {
            "doc": {
                "field2": "value2"
            }
        }
    ]
    try:
        response = requests.post(ELASTICSEARCH_URL, json=actions, headers=HEADERS)

    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)
    return {"status": "OK"}


if __name__ == "__main__":
    print(f"Server running: port={8080} process_id={os.getpid()}")
    uvicorn.run(app, host="0.0.0.0", port=8080)
