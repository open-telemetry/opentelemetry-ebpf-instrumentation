# Dockerfile that will build a container that runs python
FROM python:3.11@sha256:8455ff32cbe4c6ad6328c07d845444c01889628549718e448104555e1e631563
EXPOSE 8080
RUN apt update
RUN pip install kafka-python
COPY main.py /main.py
CMD ["python", "main.py"]