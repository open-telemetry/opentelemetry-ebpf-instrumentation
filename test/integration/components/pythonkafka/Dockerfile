# Dockerfile that will build a container that runs python
FROM python:3.11@sha256:3afa472a60099bc640f313807190b16e2cecfadfc8302d9c3fd67e7706db54e5
EXPOSE 8080
RUN apt update
RUN pip install kafka-python
COPY main.py /main.py
CMD ["python", "main.py"]