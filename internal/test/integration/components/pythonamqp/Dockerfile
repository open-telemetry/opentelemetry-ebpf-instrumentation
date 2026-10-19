FROM python:3.15@sha256:3c24e0b3ef4c5e2409f918894ccd5e05756eea2015ae6ddd289179b20a049f9b

EXPOSE 8080

COPY internal/test/integration/components/pythonamqp/requirements.txt /requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /requirements.txt

COPY internal/test/integration/components/pythonamqp/main.py /main.py

CMD ["python", "/main.py"]
