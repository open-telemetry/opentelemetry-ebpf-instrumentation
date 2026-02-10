# Dockerfile that will build a container that runs python flask 7771
FROM python:3.14.3-slim@sha256:486b8092bfb12997e10d4920897213a06563449c951c5506c2a2cfaf591c599f
EXPOSE 7771 7772 7773 7774
RUN pip install flask gunicorn requests

# Set the working directory to /build
WORKDIR /

# Copy the source code into the image for building
COPY internal/test/integration/components/pythonselfserver .

CMD ["python", "main.py"]
