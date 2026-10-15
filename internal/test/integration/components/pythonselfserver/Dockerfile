# Dockerfile that will build a container that runs python flask 7771
FROM python:3.15.0-slim@sha256:ea4f1f290e071bf7d28199cfb3e09f5dbad31b50e9c32fd58f2f2d7be915f3ae
EXPOSE 7771 7772 7773 7774
COPY internal/test/integration/components/pythonselfserver/requirements.txt /requirements.txt
RUN pip install --require-hashes -r /requirements.txt

# Set the working directory to /build
WORKDIR /

# Copy the source code into the image for building
COPY internal/test/integration/components/pythonselfserver .

CMD ["python", "main.py"]
