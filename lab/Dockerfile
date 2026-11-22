# "Fresh VPS" with the misconfigurations I see most often on small servers.
# Used only by lab/run-before-after.sh to demonstrate audit -> harden -> audit.
# Do not deploy this image anywhere.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      openssh-server openssh-client sudo python3 iproute2 procps \
      nftables fail2ban unattended-upgrades auditd \
 && rm -rf /var/lib/apt/lists/*

# --- the mistakes -------------------------------------------------------
# SSH: root login and passwords allowed, generous retries and timeouts.
RUN mkdir -p /run/sshd \
 && printf '%s\n' \
      'PermitRootLogin yes' \
      'PasswordAuthentication yes' \
      'X11Forwarding yes' \
      'MaxAuthTries 10' \
      'LoginGraceTime 120' > /etc/ssh/sshd_config.d/10-provider-defaults.conf \
 && echo 'root:lab-only-insecure' | chpasswd
# A deploy user with passwordless sudo, and a forgotten test account with no password.
RUN useradd -m -s /bin/bash deploy \
 && echo 'deploy ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/90-deploy \
 && chmod 0440 /etc/sudoers.d/90-deploy \
 && useradd -m -s /bin/bash test && passwd -d test
# Loose permissions.
RUN chmod 0644 /etc/shadow \
 && echo 'db_password=changeme' > /etc/app.conf && chmod 0666 /etc/app.conf \
 && chmod 0777 /tmp
# Unattended upgrades installed but switched off.
RUN printf 'APT::Periodic::Update-Package-Lists "0";\nAPT::Periodic::Unattended-Upgrade "0";\n' > /etc/apt/apt.conf.d/20auto-upgrades
# An admin's key, so the hardening script may safely turn passwords off.
RUN mkdir -p /home/deploy/.ssh && ssh-keygen -q -t ed25519 -N '' -f /root/lab_admin_key \
 && cp /root/lab_admin_key.pub /home/deploy/.ssh/authorized_keys \
 && chown -R deploy:deploy /home/deploy/.ssh && chmod 700 /home/deploy/.ssh && chmod 600 /home/deploy/.ssh/authorized_keys

COPY --chmod=0755 lab-init.sh /usr/local/bin/lab-init
CMD ["/usr/local/bin/lab-init"]
