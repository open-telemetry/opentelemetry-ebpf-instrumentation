# Dockerfile that will build a container that runs python
FROM python:3.11@sha256:bf2d36b8fb1b4a0b590b36736cdd8a6b5175b411bf135c42694ecd68ab8fed02
EXPOSE 8080
RUN apt update
RUN pip install kafka-python
COPY main.py /main.py
CMD ["python", "main.py"]