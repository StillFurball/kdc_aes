FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends tcpdump iproute2 iputils-ping \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY *.py /app/

CMD ["sleep", "infinity"]
