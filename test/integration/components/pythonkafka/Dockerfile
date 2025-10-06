# Dockerfile that will build a container that runs python
FROM python:3.11@sha256:d64744243357bfac2d6fa45fb913111ec9ee513f409d505450a4b346498e85df
EXPOSE 8080
RUN apt update
RUN pip install kafka-python
COPY main.py /main.py
CMD ["python", "main.py"]