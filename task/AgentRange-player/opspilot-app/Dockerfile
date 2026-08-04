FROM python:3.12-slim
WORKDIR /app
ENV HTTP_PROXY= HTTPS_PROXY= http_proxy= https_proxy= NO_PROXY=* no_proxy=*
COPY opspilot-app/requirements.txt .
RUN pip install --no-cache-dir -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt
COPY opspilot-app/auth ./auth
COPY opspilot-app/policy ./policy
COPY opspilot-app/security ./security
COPY opspilot-app/api ./api
COPY skills ./skills
EXPOSE 8000
CMD ["uvicorn", "api.app:app", "--host", "0.0.0.0", "--port", "8000"]
