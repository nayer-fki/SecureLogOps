FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY syslog_push.py /app/syslog_push.py

CMD ["python", "/app/syslog_push.py"]
