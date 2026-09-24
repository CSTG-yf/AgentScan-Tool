FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi==0.111.0 "uvicorn[standard]==0.30.1"
COPY mock_internet ./mock_internet
EXPOSE 9000
CMD ["uvicorn", "mock_internet.app:app", "--host", "0.0.0.0", "--port", "9000"]
