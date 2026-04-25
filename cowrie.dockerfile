# ─────────────────────────────────────────────────────────────
# Cowrie Honeypot — Medical IoT Device Simulation
# Simulates: BD Alaris Infusion Pump running embedded Linux
# ─────────────────────────────────────────────────────────────
FROM python:3.11-slim

LABEL maintainer="security-intern"
LABEL description="Cowrie SSH/Telnet honeypot simulating medical IoT device"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    libssl-dev \
    libffi-dev \
    libpython3-dev \
    python3-pip \
    python3-venv \
    authbind \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Create cowrie user (never run as root)
RUN useradd -r -d /cowrie -s /bin/bash cowrie

# Clone and install Cowrie
WORKDIR /cowrie
RUN git clone https://github.com/cowrie/cowrie.git . \
    && python3 -m venv cowrie-env \
    && cowrie-env/bin/pip install --upgrade pip \
    && cowrie-env/bin/pip install -r requirements.txt

# Copy base config (will be overridden by volume mount)
COPY ../cowrie-config/cowrie.cfg etc/cowrie.cfg
COPY ../cowrie-config/userdb.txt etc/userdb.txt

# Set up directories
RUN mkdir -p var/log/cowrie var/lib/cowrie/downloads \
    && chown -R cowrie:cowrie /cowrie

# Authbind lets cowrie bind to port 22/23 without root
RUN touch /etc/authbind/byport/2222 /etc/authbind/byport/2323 \
    && chmod 777 /etc/authbind/byport/2222 /etc/authbind/byport/2323

USER cowrie

EXPOSE 2222 2323

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s \
    CMD nc -z localhost 2222 || exit 1

CMD ["cowrie-env/bin/python", "bin/cowrie", "start", "-n"]
