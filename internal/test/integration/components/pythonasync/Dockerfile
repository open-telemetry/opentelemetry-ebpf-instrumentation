FROM python:3.12
EXPOSE 8391

WORKDIR /app

COPY internal/test/integration/components/pythonasync/requirements.txt .
RUN pip install -r requirements.txt

COPY internal/test/integration/components/pythonasync .

CMD ["python", "async_context_test.py"]
