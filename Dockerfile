ARG PYTHON_VERSION=3.12
FROM python:${PYTHON_VERSION}-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# git: pip installs connectors-sdk and doc-to-stix from their repositories
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

COPY src /opt/opencti-connector-doc-to-stix
WORKDIR /opt/opencti-connector-doc-to-stix
RUN pip3 install --no-cache-dir -r requirements.txt

ENTRYPOINT ["python", "main.py"]
