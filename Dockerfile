FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends docker.io ca-certificates && rm -rf /var/lib/apt/lists/* \
 && useradd -m -u 10001 fusion
WORKDIR /app
COPY pyproject.toml README.md ./
COPY fusion_os ./fusion_os
COPY docker ./docker
RUN pip install --no-cache-dir .
ENV FUSION_OS_HOME=/data PYTHONUNBUFFERED=1
VOLUME ["/data"]
EXPOSE 8790
CMD ["python", "-m", "fusion_os", "serve", "--host", "0.0.0.0", "--port", "8790"]
