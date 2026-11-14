# Một image dùng chung cho mọi node của lab (switch, gateway, host, attacker, sniffer)
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      iproute2 iputils-ping tcpdump nmap hping3 dsniff dnsmasq isc-dhcp-client \
      netcat-openbsd curl python3 python3-scapy net-tools ethtool procps ca-certificates \
    && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
