# syntax=docker/dockerfile:1

# Single source image for both the running secure app and the verification tools,
# so local runs and CI exercise the same environment.
FROM python:3.13-slim AS base
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir uv==0.8.17
WORKDIR /app

# ---- runtime dependencies only (cached on pyproject.toml + uv.lock) ----
FROM base AS runtime-deps
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# ---- runtime image: the secure application, running as a non-root user ----
FROM runtime-deps AS runtime
COPY README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev
RUN useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /app /opt/venv
USER appuser
EXPOSE 8000
CMD ["uvicorn", "scriptjack.secure.app:app", "--host", "0.0.0.0", "--port", "8000"]

# ---- dev image: runtime deps + dev tools + sources + tests (Ruff/mypy/pytest) ----
FROM base AS dev
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project
COPY README.md ./
COPY src ./src
COPY tests ./tests
RUN uv sync --frozen
CMD ["pytest"]
