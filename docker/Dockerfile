FROM python:3.11-slim

WORKDIR /app

# System deps for WeasyPrint (PDF rendering) and nmap
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libgdk-pixbuf2.0-0 \
        libffi-dev \
        shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml requirements.txt ./
RUN pip install --no-cache-dir -e .

COPY src/ src/

# Artifacts directory (mount a volume here to persist results)
RUN mkdir -p artifacts

ENTRYPOINT ["python", "-m", "artasf.ui.cli"]
CMD ["--help"]
