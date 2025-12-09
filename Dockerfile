# Minimal container for BBMD Manager CLI
FROM ghcr.io/astral-sh/uv:python3.12-alpine

WORKDIR /app

# Copy package files
COPY pyproject.toml README.md ./
COPY bbmd_manager/ ./bbmd_manager/

# Install the package
RUN uv pip install --system --no-cache .

# Create directory for state files
RUN mkdir -p /data
WORKDIR /data

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Default entrypoint is the CLI
ENTRYPOINT ["bbmd-manager"]

# Default command shows help
CMD ["--help"]
