FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY phishir/ phishir/
COPY samples/ samples/

RUN useradd --create-home --uid 10001 appuser && chown -R appuser /app
USER appuser

EXPOSE 8000
HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1
# PHISHIR_API_KEY must be supplied at runtime: docker run -e PHISHIR_API_KEY=... -p 8000:8000 phishir
CMD ["uvicorn", "phishir.api:app", "--host", "0.0.0.0", "--port", "8000"]
