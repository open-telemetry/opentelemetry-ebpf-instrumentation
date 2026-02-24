# Dockerfile that will build a container that runs python
FROM python:3.14@sha256:151ab3571dad616bb031052e86411e2165295c7f67ef27206852203e854bcd12
EXPOSE 8080
RUN apt update
RUN pip install kafka-python
COPY main.py /main.py
CMD ["python", "main.py"]
