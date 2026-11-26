FROM mirror.gcr.io/library/debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    snmpd \
    snmp \
  && rm -rf /var/lib/apt/lists/*

# Main daemon config
COPY snmpd.conf /etc/snmp/snmpd.conf

# SNMPv3 user — processed once on first start, converted to usmUser entry.
# Must be in the persistent state file location.
RUN mkdir -p /var/lib/snmp
COPY snmpv3.conf /var/lib/snmp/snmpd.conf

EXPOSE 1161/udp

CMD ["snmpd", "-f", "-Lo", "-c", "/etc/snmp/snmpd.conf", "udp:0.0.0.0:1161"]
