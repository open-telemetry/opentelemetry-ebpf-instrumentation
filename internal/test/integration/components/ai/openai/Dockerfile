FROM python:3.14@sha256:4b827abf32c14b7df9a0dc5199c2f0bc46e2c9862cd5d77eddae8a2cd8460f60
EXPOSE 8080
RUN pip install boto3 fastapi uvicorn
COPY main.py /main.py
CMD ["uvicorn", "--port", "8080", "--host", "0.0.0.0", "main:app"]
