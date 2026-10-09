FROM python:3.12-slim as builder

WORKDIR /app
COPY requirements.txt . 
# actually we use uv, let's just install uv
RUN pip install uv
COPY pyproject.toml .
# Install without dev deps
RUN uv pip install --system --no-cache-dir .

FROM python:3.12-slim

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.12/site-packages/ /usr/local/lib/python3.12/site-packages/
COPY --from=builder /usr/local/bin/ /usr/local/bin/

RUN useradd -u 10001 -m -s /bin/bash appuser
COPY . /app/
RUN chown -R appuser:appuser /app

USER 10001
ENV PYTHONUNBUFFERED=1

# read_only true implies we shouldn't write to the filesystem, /tmp should be tmpfs (handled by docker run --read-only --tmpfs /tmp)

COPY entrypoint.sh /app/entrypoint.sh
ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]
