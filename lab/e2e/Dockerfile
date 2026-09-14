# End-to-end lab: real OpenSSH server + rsyslog + the Linux whotyped binary +
# real SSH clients (OpenSSH and paramiko) in one container. It exercises the
# whole pipeline on real log lines and real /proc, not fixtures.
#
# Limits (documented in lab/e2e/README.md): no auditd inside a container, so
# style and flag clues for remote sessions are not available; outbound AI API
# connections are not exercised.
FROM ubuntu:24.04

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      openssh-server openssh-client rsyslog python3 python3-paramiko \
      procps iproute2 ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd /var/lib/whotyped /etc/whotyped \
 # imklog needs /proc/kmsg, which a container does not have.
 && sed -i 's/^module(load="imklog"/#&/' /etc/rsyslog.conf \
 # pam_loginuid needs CAP_AUDIT_CONTROL; keep it but do not fail the login without it.
 && sed -i 's/^session\s\+required\s\+pam_loginuid.so/session optional pam_loginuid.so/' /etc/pam.d/sshd \
 && for u in alice bob carol dave erin frank grace; do useradd -m -s /bin/bash "$u"; done

COPY lab/e2e/config.yaml /etc/whotyped/config.yaml
COPY lab/e2e/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY lab/e2e/scenarios.sh /usr/local/bin/scenarios.sh
COPY lab/e2e/paramiko_client.py /usr/local/bin/paramiko_client.py
COPY lab/e2e/fake-claude /usr/local/share/whotyped-lab/claude
COPY dist/whotyped-linux-amd64 /usr/bin/whotyped
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/scenarios.sh /usr/bin/whotyped \
      /usr/local/bin/paramiko_client.py /usr/local/share/whotyped-lab/claude

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
