ARG LANGFLOW_VERSION=1.8.4
FROM langflowai/langflow:${LANGFLOW_VERSION}
USER root
RUN mkdir -p /etc/cron.d && chgrp 0 /etc/cron.d && chmod g+rwx /etc/cron.d
USER 1000
ENV LANGFLOW_AUTO_LOGIN=true \
    LANGFLOW_SUPERUSER=admin \
    LANGFLOW_SUPERUSER_PASSWORD=admin
EXPOSE 7860
