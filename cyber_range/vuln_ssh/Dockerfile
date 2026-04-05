# Vulnerable SSH Server — weak credentials for testing
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    && rm -rf /var/lib/apt/lists/*

# Create test users with weak passwords
RUN useradd -m -s /bin/bash admin && echo "admin:admin123" | chpasswd
RUN useradd -m -s /bin/bash testuser && echo "testuser:password" | chpasswd
RUN useradd -m -s /bin/bash root2 && echo "root2:toor" | chpasswd

# Intentionally weak SSH configuration
RUN mkdir -p /run/sshd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
RUN echo "root:root" | chpasswd

# Create some "sensitive" files for post-exploitation
RUN mkdir -p /opt/secrets
RUN echo "DATABASE_URL=postgres://admin:supersecret@db:5432/production" > /opt/secrets/config.env
RUN echo "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" >> /opt/secrets/config.env
RUN echo "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" >> /opt/secrets/config.env
RUN chmod 644 /opt/secrets/config.env

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
