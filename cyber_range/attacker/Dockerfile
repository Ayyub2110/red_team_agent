FROM python:3.12-slim

# Install security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    iputils-ping \
    net-tools \
    curl \
    wget \
    dnsutils \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/agent

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

CMD ["/bin/bash"]
