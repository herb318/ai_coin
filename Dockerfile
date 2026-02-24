FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements-docker.txt /tmp/requirements-docker.txt
RUN python -m pip install --upgrade pip \
    && python -m pip install --no-cache-dir -r /tmp/requirements-docker.txt

COPY . /app

ENTRYPOINT ["python3", "scripts/docker_runner.py"]
CMD ["--mode", "oneshot"]
