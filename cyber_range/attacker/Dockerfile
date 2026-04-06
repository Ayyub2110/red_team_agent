FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_BREAK_SYSTEM_PACKAGES=1

# Install system dependencies + Metasploit
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    metasploit-framework \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    git \
    iputils-ping \
    net-tools \
    dnsutils \
    tcpdump \
    wget \
    sudo \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash redteam && \
    echo "redteam ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/redteam

WORKDIR /opt/agent

# Copy requirements and install Python packages
COPY requirements.txt ./

RUN pip3 install --no-cache-dir --upgrade pip && \
    pip3 install --no-cache-dir -r requirements.txt

# Switch to non-root user
USER redteam

CMD ["/bin/bash"]