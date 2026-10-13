FROM python:3.15.0-slim@sha256:ea4f1f290e071bf7d28199cfb3e09f5dbad31b50e9c32fd58f2f2d7be915f3ae

WORKDIR /app
COPY internal/test/integration/components/djangoserver/requirements.txt .
RUN pip install --require-hashes -r requirements.txt
COPY internal/test/integration/components/djangoserver .

ENV DJANGO_SETTINGS_MODULE=settings
EXPOSE 8380
CMD ["sh", "-c", "python -m django migrate --noinput && exec gunicorn --bind 0.0.0.0:8380 --workers 1 wsgi:application"]
