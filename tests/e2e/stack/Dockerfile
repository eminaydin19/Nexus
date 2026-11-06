FROM python:3.12-slim AS base
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_ROOT_USER_ACTION=ignore PIP_DISABLE_PIP_VERSION_CHECK=1

FROM base AS target
RUN apt-get update \
    && apt-get install -y --no-install-recommends nginx openssh-server nftables rsyslog iproute2 procps \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir psutil requests \
    && useradd -m -s /bin/bash customer \
    && echo 'customer:customer-pass' | chpasswd \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/^module(load="imklog".*/# imklog would consume \/proc\/kmsg for the whole VM/' /etc/rsyslog.conf
COPY --from=repo nexus_agent /opt/nexus/nexus_agent
RUN python -c "import json; p='/opt/nexus/nexus_agent/data/cdn_ranges.json'; d=json.load(open(p)); d['ranges']['test']=['203.0.113.33/32']; json.dump(d, open(p,'w'))"
COPY nginx.conf /etc/nginx/nginx.conf
COPY rsyslog-kmsg.conf /etc/rsyslog.d/00-kmsg.conf
COPY target-entry.sh /usr/local/bin/target-entry.sh
WORKDIR /opt/nexus
ENTRYPOINT ["/usr/local/bin/target-entry.sh"]

FROM base AS tools
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client sshpass nmap hping3 curl iproute2 procps \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir scapy
COPY load.py /usr/local/bin/load.py
ENTRYPOINT ["sleep", "infinity"]

FROM base AS runner
RUN apt-get update \
    && apt-get install -y --no-install-recommends docker-cli \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir pytest requests
ENTRYPOINT ["sleep", "infinity"]
