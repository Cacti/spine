FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
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
