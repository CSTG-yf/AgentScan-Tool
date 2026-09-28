FROM python:3.12-slim
WORKDIR /app
COPY opspilot-app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY opspilot-app/auth ./auth
COPY opspilot-app/policy ./policy
COPY opspilot-app/api ./api
COPY skills ./skills
EXPOSE 8000
CMD ["uvicorn", "api.app:app", "--host", "0.0.0.0", "--port", "8000"]
