FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi==0.111.0 "uvicorn[standard]==0.30.1"
COPY c2_sink ./c2_sink
EXPOSE 9100
CMD ["uvicorn", "c2_sink.app:app", "--host", "0.0.0.0", "--port", "9100"]
