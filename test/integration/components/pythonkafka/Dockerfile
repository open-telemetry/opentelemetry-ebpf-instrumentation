# Dockerfile that will build a container that runs python
FROM python:3.11@sha256:9153baea63f0b65f8cc4f5b2d064162326e25892a8a89bc543e0475c90471211
EXPOSE 8080
RUN apt update
RUN pip install kafka-python
COPY main.py /main.py
CMD ["python", "main.py"]