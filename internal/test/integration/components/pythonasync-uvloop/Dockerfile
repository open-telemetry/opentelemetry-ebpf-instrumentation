FROM python:3.14@sha256:6d58c1a9444bc2664f0fa20c43a592fcdb2698eb9a9c32257516538a2746c19a
EXPOSE 8391

WORKDIR /app

COPY internal/test/integration/components/pythonasync-uvloop/requirements.txt .
RUN pip install -r requirements.txt

COPY internal/test/integration/components/pythonasync-uvloop .

CMD ["python3.14", "async_context_test.py"]
