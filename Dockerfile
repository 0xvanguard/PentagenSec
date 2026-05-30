# Stage 1 - Builder con scan
FROM python:3.12-slim-bookworm@sha256:3266bd6e1919bf0af918b9b8b2fc1d0f5e022f462bbbd8c3653d9e8dfb1d6f46 AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

# Stage 2 - Runtime mínimo
FROM python:3.12-slim-bookworm@sha256:3266bd6e1919bf0af918b9b8b2fc1d0f5e022f462bbbd8c3653d9e8dfb1d6f46 AS runtime
WORKDIR /app
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY main.py .

# CM-8: Usuario no root
RUN useradd -m -u 10001 pentagensec
USER 10001

# SA-22: Sin shell en prod
ENTRYPOINT ["python", "main.py"]
