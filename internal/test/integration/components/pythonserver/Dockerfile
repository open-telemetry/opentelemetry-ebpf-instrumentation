# Dockerfile that will build a container that runs python flask with gunicorn on port 7770
FROM python:3.15.0-slim@sha256:ea4f1f290e071bf7d28199cfb3e09f5dbad31b50e9c32fd58f2f2d7be915f3ae
EXPOSE 7770
COPY internal/test/integration/components/pythonserver/requirements.txt /requirements.txt
RUN pip install --require-hashes -r /requirements.txt
# Alternative: RUN pip install flask uwsgi

# Set the working directory to /build
WORKDIR /

# Copy the source code into the image for building
COPY internal/test/integration/components/pythonserver .

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8380", "main:app", "--timeout", "90"]
# setting largish timeout for the workers so we can test Beyla timeouts
# CMD uwsgi --http 0.0.0.0:7770 --master -p 4 -w main:app
