FROM python:3.12-slim
WORKDIR /app
ENV HTTP_PROXY= HTTPS_PROXY= http_proxy= https_proxy= NO_PROXY=* no_proxy=*
COPY integration/requirements.txt .
RUN pip install --no-cache-dir -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt
COPY integration/langflow_guard.py .
CMD ["uvicorn", "langflow_guard:app", "--host", "0.0.0.0", "--port", "8080"]
