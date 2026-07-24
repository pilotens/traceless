FROM python:3.12-slim AS runtime

ARG UV_VERSION=0.11.28

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH="/app/.venv/bin:${PATH}"

WORKDIR /app

RUN addgroup --system traceless && adduser --system --ingroup traceless traceless

RUN python -m pip install "uv==${UV_VERSION}"

COPY pyproject.toml uv.lock README.md alembic.ini publisher_alembic.ini ./
COPY src ./src
COPY migrations ./migrations
COPY publisher_migrations ./publisher_migrations
RUN uv sync --locked --no-dev --no-editable && uv cache clean

USER traceless
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/ready', timeout=2)"

CMD ["sh", "-c", "exec uvicorn traceless_api.main:app --host 0.0.0.0 --port 8000 --workers \"${TRACELESS_API_WORKERS:-2}\" --no-access-log --proxy-headers --forwarded-allow-ips \"${TRACELESS_FORWARDED_ALLOW_IPS:-127.0.0.1}\""]
