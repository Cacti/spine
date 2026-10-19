#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The Cacti Group
# SPDX-License-Identifier: LGPL-2.1-or-later
# Disposable certificates and databases; no production endpoints or credentials.
set -euo pipefail
tls_binary="${SPINE_TLS_TEST_BINARY:-./test_spine_regressions}"
tls_image="${SPINE_TLS_DATABASE_IMAGE:-mirror.gcr.io/library/mariadb:10.11}"
tls_evidence="${SPINE_TLS_EVIDENCE_DIR:-tls-evidence}"
mkdir -p "$tls_evidence"
tls_directory="$(mktemp -d "${TMPDIR:-/tmp}/spine-database-tls.XXXXXX")"
tls_names=("spine-tls-trusted-$$" "spine-tls-wrong-name-$$" "spine-tls-plaintext-$$")
cleanup_tls() {
    status=$?
    for name in "${tls_names[@]}"; do
        docker logs "$name" > "$tls_evidence/$name.log" 2>&1 || true
        docker rm -f "$name" >/dev/null 2>&1 || true
    done
    rm -rf -- "$tls_directory"
    exit "$status"
}
trap cleanup_tls EXIT
# These keys are generated solely for the isolated test, never checked in.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=Spine-Test-CA \
    -keyout "$tls_directory/ca.key" -out "$tls_directory/ca.pem" > "$tls_evidence/certificates.log" 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=Spine-Untrusted-CA \
    -keyout "$tls_directory/untrusted.key" -out "$tls_directory/untrusted.pem" >> "$tls_evidence/certificates.log" 2>&1
for identity in trusted wrong-name; do
    openssl req -new -newkey rsa:2048 -nodes -subj /CN=spine-test.invalid \
        -keyout "$tls_directory/$identity.key" -out "$tls_directory/$identity.csr" >> "$tls_evidence/certificates.log" 2>&1
    if [[ "$identity" == trusted ]]; then
        printf 'subjectAltName=IP:127.0.0.1\n' > "$tls_directory/extensions"
    else
        printf 'subjectAltName=DNS:wrong-name.invalid\n' > "$tls_directory/extensions"
    fi
    openssl x509 -req -days 1 -in "$tls_directory/$identity.csr" \
        -CA "$tls_directory/ca.pem" -CAkey "$tls_directory/ca.key" -CAcreateserial \
        -extfile "$tls_directory/extensions" -out "$tls_directory/$identity.pem" >> "$tls_evidence/certificates.log" 2>&1
done
# The database image drops privileges; expose only disposable server material.
chmod 755 "$tls_directory"
chmod 644 "$tls_directory/trusted.key" "$tls_directory/wrong-name.key"
ports=()
for index in 0 1 2; do
    options=(--skip-ssl)
    if [[ "$index" -lt 2 ]]; then
        identity=trusted
        [[ "$index" == 0 ]] || identity=wrong-name
        options=(--ssl-ca=/certs/ca.pem "--ssl-cert=/certs/$identity.pem"
            "--ssl-key=/certs/$identity.key" --tls-version=TLSv1.2
            --ssl-cipher=ECDHE-RSA-AES128-GCM-SHA256)
    fi
    docker run -d --name "${tls_names[index]}" -p 127.0.0.1::3306 \
        -e MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=1 -e MARIADB_DATABASE=spine_regressions \
        -v "$tls_directory:/certs:ro" "$tls_image" "${options[@]}" >/dev/null
done
for index in 0 1 2; do
    ready=0
    for attempt in {1..60}; do
        if docker exec "${tls_names[index]}" mariadb --protocol=TCP -h127.0.0.1 -uroot -e 'SELECT 1' >/dev/null 2>&1; then
            ready=1
            break
        fi
        if [[ "$attempt" == 60 ]]; then
            printf 'TLS fixture did not become ready: %s\n' "${tls_names[index]}" >&2
        fi
        sleep 1
    done
    [[ "$ready" == 1 ]]
    mapping="$(docker port "${tls_names[index]}" 3306/tcp)"
    ports+=("${mapping##*:}")
done
SPINE_TEST_TLS_CA="$tls_directory/ca.pem" \
SPINE_TEST_TLS_UNTRUSTED_CA="$tls_directory/untrusted.pem" \
SPINE_TEST_TLS_PORT="${ports[0]}" \
SPINE_TEST_TLS_WRONG_NAME_PORT="${ports[1]}" \
SPINE_TEST_TLS_PLAINTEXT_PORT="${ports[2]}" \
    "$tls_binary" --database-tls | tee "$tls_evidence/contracts.log"
grep -Fq 'production database TLS trust, identity, protocol, cipher and downgrade contracts passed' "$tls_evidence/contracts.log"
