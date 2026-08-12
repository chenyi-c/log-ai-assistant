ARG PYTHON_BASE_IMAGE=python:3.11-slim
FROM ${PYTHON_BASE_IMAGE}

ARG PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PIP_INDEX_URL=${PIP_INDEX_URL}

WORKDIR /app

COPY requirements/backend.txt requirements/backend.txt
COPY requirements/test.txt requirements/test.txt
RUN python -m pip install --no-cache-dir --retries 10 --timeout 120 \
    certifi \
    urllib3 \
    pytz \
    lz4 \
    zstandard
RUN python -m pip install --no-cache-dir --no-deps --retries 10 --timeout 120 clickhouse-connect==0.8.9
RUN python -m pip install --no-cache-dir --retries 10 --timeout 120 -r requirements/backend.txt -r requirements/test.txt

COPY src src
COPY tests tests
COPY sql sql
COPY scripts scripts
COPY docs/evidence docs/evidence
COPY docker/tester.Dockerfile docker/tester.Dockerfile
COPY filebeat filebeat
COPY log-generator log-generator

CMD ["pytest", "-q"]
