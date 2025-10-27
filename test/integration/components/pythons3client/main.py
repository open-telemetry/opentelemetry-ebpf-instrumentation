from fastapi import FastAPI
import os
import uvicorn
import boto3

ENDPOINT_URL = "http://localstack:4566"
AWS_ACCESS_KEY_ID = "test"
AWS_SECRET_ACCESS_KEY = "test"
REGION = "us-east-1"
BUCKET_NAME = "obi-bucket"

s3 = boto3.client(
    "s3",
    endpoint_url=ENDPOINT_URL,
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=REGION
)

app = FastAPI()

@app.get("/health")
async def health():
    return "ok!"

@app.get("/createbucket")
async def createbucket():
    return s3.create_bucket(Bucket=BUCKET_NAME)

@app.get("/createobject")
async def createobject():
    return s3.put_object(
        Bucket=BUCKET_NAME,
        Key="hello.txt",
        Body="Hello from OBI!"
    )

@app.get("/listobjects")
async def listobjects():
    return s3.list_objects_v2(Bucket=BUCKET_NAME)

@app.get("/deleteobject")
async def deleteobject():
    return s3.delete_object(
        Bucket=BUCKET_NAME,
        Key="hello.txt"
    )

@app.get("/deletebucket")
async def deletebucket():
    return s3.delete_bucket(Bucket=BUCKET_NAME)

if __name__ == "__main__":
    print(f"Server running: port={8080} process_id={os.getpid()}")
    uvicorn.run(app, host="0.0.0.0", port=8080)
