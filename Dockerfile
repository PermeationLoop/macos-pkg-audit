FROM python:3.11-slim

LABEL org.opencontainers.image.title="PKG Security Audit"
LABEL org.opencontainers.image.description="Agentic macOS pkg installer security audit tool"
LABEL org.opencontainers.image.version="1.0"

# System dependencies for pkg extraction
RUN apt-get update && apt-get install -y --no-install-recommends \
    xar \
    cpio \
    binutils \
    file \
    openssl \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install docker-agent CLI binary
RUN ARCH=$(dpkg --print-architecture) \
    && case "$ARCH" in \
         amd64)  BIN_ARCH="linux-amd64" ;; \
         arm64)  BIN_ARCH="linux-arm64" ;; \
         *)      echo "Unsupported architecture: $ARCH"; exit 1 ;; \
       esac \
    && curl -fsSL -o /usr/local/bin/docker-agent \
         "https://github.com/docker/docker-agent/releases/download/v1.101.0/docker-agent-${BIN_ARCH}" \
    && chmod +x /usr/local/bin/docker-agent

# Python dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy application
COPY SKILL.md /app/SKILL.md
COPY cagent.yaml /app/cagent.yaml
COPY tools/ /app/tools/
COPY rules/ /app/rules/
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

WORKDIR /app

ENTRYPOINT ["/entrypoint.sh"]
