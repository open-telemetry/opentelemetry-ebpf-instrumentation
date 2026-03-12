ARG PYTHON_VERSION=3.14
FROM python:${PYTHON_VERSION}
EXPOSE 8391

WORKDIR /app

COPY internal/test/integration/components/pythonasync-uvloop/requirements.txt .
RUN pip install -r requirements.txt

COPY internal/test/integration/components/pythonasync-uvloop .

CMD ["python", "async_context_test.py"]
