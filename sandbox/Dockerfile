FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --gid 65532 sandbox \
    && useradd --uid 65532 --gid 65532 --create-home --shell /usr/sbin/nologin sandbox \
    && pip install pytest==8.3.4 pytest-json-report==1.5.0

USER sandbox
WORKDIR /work
