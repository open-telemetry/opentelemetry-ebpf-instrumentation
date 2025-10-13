# Dockerfile that will build a container that runs python
FROM python:3.11@sha256:993edd4388f0b3929b79fd954c8878ca81ee6bc6def9375b78d06d2af1905ee3
EXPOSE 8080
RUN apt update
RUN pip install kafka-python
COPY main.py /main.py
CMD ["python", "main.py"]