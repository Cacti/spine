FROM mirror.gcr.io/library/debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f

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
