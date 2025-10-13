FROM python:3.12@sha256:3466e9a530f0226fc09fbc479bde2387fd773f760749612e94d8696fe1aa5877
EXPOSE 8080
RUN pip install ariadne fastapi uvicorn
COPY main.py /main.py
CMD ["uvicorn", "--port", "8080", "--host", "0.0.0.0", "main:app"]
