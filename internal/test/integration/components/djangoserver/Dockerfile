FROM python:3.14.3-slim@sha256:6a27522252aef8432841f224d9baaa6e9fce07b07584154fa0b9a96603af7456

WORKDIR /app
COPY internal/test/integration/components/djangoserver/requirements.txt .
RUN pip install --require-hashes -r requirements.txt
COPY internal/test/integration/components/djangoserver .

ENV DJANGO_SETTINGS_MODULE=settings
EXPOSE 8380
CMD ["sh", "-c", "python -m django migrate --noinput && exec gunicorn --bind 0.0.0.0:8380 --workers 1 wsgi:application"]
