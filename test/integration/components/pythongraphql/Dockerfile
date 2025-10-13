FROM python:3.12@sha256:53724a5c8eb133046e0124fc2a623b00699949ecc475eb23daffdb547345bf86
EXPOSE 8080
RUN pip install ariadne fastapi uvicorn
COPY main.py /main.py
CMD ["uvicorn", "--port", "8080", "--host", "0.0.0.0", "main:app"]
