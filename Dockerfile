FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Usuario sin privilegios
RUN useradd --create-home --uid 1000 app \
 && mkdir -p /app/data /home/app/.securechat \
 && chown -R app:app /app /home/app/.securechat

# Dependencias en capa aparte (cache de build)
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY --chown=app:app . .

ENV HOST=0.0.0.0 \
    PORT=8000 \
    SECURECHAT_DB=/app/data/server.db \
    SECURECHAT_HOME=/home/app/.securechat

USER app
EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)" || exit 1

CMD ["python", "-m", "securechat.server"]
