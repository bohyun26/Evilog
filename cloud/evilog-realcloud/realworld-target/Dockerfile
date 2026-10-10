FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SERVICE_NAME=realworld-api \
    DB_PATH=/tmp/realworld.db \
    DB_POOL_SIZE=5 \
    DB_POOL_TIMEOUT_S=2.0 \
    FEED_PAGE_SIZE=10 \
    ATTACK_SURFACES=a1,a2,a3,a4

WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN useradd -u 10001 -m appuser && chown -R appuser /srv
USER appuser

EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
