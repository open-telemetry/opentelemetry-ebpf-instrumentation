FROM python:3.14-slim
EXPOSE 8080
RUN pip install fastapi==0.135.2 uvicorn==0.42.0 requests==2.33.0
COPY main.py /main.py
CMD ["python", "main.py"]
