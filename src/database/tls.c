/*
 * SPDX-FileCopyrightText: 2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#include "internal/common.h"
#include "app/spine.h"
#ifdef HAVE_MARIADB_TLS_VERIFICATION_CALLBACK
/* The callback's opaque TLS type is declared in Connector/C's ma_tls.h.
 * Some distributions install that header without its private ma_hash.h
 * dependency. Probe the exported callback API without inspecting its layout. */
struct st_ma_pvio_tls;
extern int ma_pvio_tls_verify_server_cert(struct st_ma_pvio_tls *, unsigned int);

/* Connector/C 3.4 omits hostname checks for local addresses by default.
 * Explicit verify-full requires identity checks even on those addresses. */
static int verify_database_identity(struct st_ma_pvio_tls *tls, unsigned int flags) {
	return ma_pvio_tls_verify_server_cert(tls,
		flags | MARIADB_TLS_VERIFY_HOST | MARIADB_TLS_VERIFY_TRUST);
}

static int verify_database_chain(struct st_ma_pvio_tls *tls, unsigned int flags) {
	return ma_pvio_tls_verify_server_cert(tls,
		(flags & ~MARIADB_TLS_VERIFY_HOST) | MARIADB_TLS_VERIFY_TRUST);
}

/* Explicit 'required' matches MySQL's encryption-only mode. The connector's
 * mandatory-TLS flag stays enabled; this callback omits peer authentication. */
static int encryption_only(struct st_ma_pvio_tls *tls, unsigned int flags) {
	(void) tls;
	(void) flags;
	return 0;
}
#endif

static bool tls_option(MYSQL *mysql, enum mysql_option option, const void *value, const char *description) {
	if (mysql_options(mysql, option, value) == 0) return TRUE;
	SPINE_LOG(("ERROR: Database client could not apply TLS %s policy", description));
	return FALSE;
}

bool db_apply_tls_policy(MYSQL *mysql, const spine_database_config_t *configuration) {
	spine_tls_mode_t mode;
	bool constrained;
	const char *versions;

	if (mysql == NULL || configuration == NULL) return FALSE;
	mode = configuration->tls_mode;
	constrained = configuration->tls_min_version != 0 ||
		configuration->tls_cipher[0] != '\0' || configuration->tls_ciphersuites[0] != '\0';
	/* A protocol/cipher restriction cannot silently permit plaintext fallback. */
	if (constrained && mode < SPINE_TLS_REQUIRED) return FALSE;
	if (configuration->tls_min_version != 0 && configuration->tls_min_version != 12 &&
		configuration->tls_min_version != 13) return FALSE;
	if (mode < SPINE_TLS_LEGACY || mode > SPINE_TLS_VERIFY_FULL) return FALSE;
	if (mode == SPINE_TLS_LEGACY) return TRUE;
	if ((mode == SPINE_TLS_VERIFY_CA || mode == SPINE_TLS_VERIFY_FULL) &&
		configuration->ssl_ca[0] == '\0') return FALSE;

#if HAVE_DECL_MYSQL_OPT_SSL_MODE
	{
		unsigned int native_mode;
		switch (mode) {
			case SPINE_TLS_DISABLED: native_mode = SSL_MODE_DISABLED; break;
			case SPINE_TLS_PREFERRED: native_mode = SSL_MODE_PREFERRED; break;
			case SPINE_TLS_REQUIRED: native_mode = SSL_MODE_REQUIRED; break;
			case SPINE_TLS_VERIFY_CA: native_mode = SSL_MODE_VERIFY_CA; break;
			case SPINE_TLS_VERIFY_FULL: native_mode = SSL_MODE_VERIFY_IDENTITY; break;
			default: return FALSE;
		}
		if (!tls_option(mysql, MYSQL_OPT_SSL_MODE, &native_mode, "mode")) return FALSE;
	}
#elif HAVE_DECL_MYSQL_OPT_SSL_ENFORCE && HAVE_DECL_MYSQL_OPT_SSL_VERIFY_SERVER_CERT
	{
		unsigned char enforce = mode >= SPINE_TLS_REQUIRED;
		unsigned char verify = mode != SPINE_TLS_PREFERRED;
		if (mode == SPINE_TLS_DISABLED) return FALSE;
		if (mode != SPINE_TLS_PREFERRED) {
#ifdef HAVE_MARIADB_TLS_VERIFICATION_CALLBACK
			int (*callback)(struct st_ma_pvio_tls *, unsigned int) = mode == SPINE_TLS_REQUIRED ? encryption_only : mode == SPINE_TLS_VERIFY_CA ? verify_database_chain
																																				: verify_database_identity;
			if (!tls_option(mysql, MARIADB_OPT_TLS_VERIFICATION_CALLBACK,
					(const void *) callback, "verification callback")) return FALSE;
#elif HAVE_DECL_MARIADB_OPT_TLS_VERIFICATION_CALLBACK
			/* A connector exposing this newer policy must offer its complete
			 * verification API; do not silently accept its local-address bypass. */
			return FALSE;
#else
			/* Older connectors cannot require encryption independently of
			 * peer verification. Their native verify-full remains supported. */
			if (mode != SPINE_TLS_VERIFY_FULL) return FALSE;
#endif
		}
		if (!tls_option(mysql, MYSQL_OPT_SSL_ENFORCE, &enforce, "enforcement") ||
			!tls_option(mysql, MYSQL_OPT_SSL_VERIFY_SERVER_CERT, &verify, "verification")) return FALSE;
	}
#else
	return FALSE;
#endif
	if (configuration->tls_min_version != 0) {
		versions = configuration->tls_min_version == 12 ? "TLSv1.2,TLSv1.3" : "TLSv1.3";
#if HAVE_DECL_MYSQL_OPT_TLS_VERSION
		if (!tls_option(mysql, MYSQL_OPT_TLS_VERSION, versions, "minimum version")) return FALSE;
#else
		(void) versions;
		return FALSE;
#endif
	}
	if (configuration->tls_cipher[0] != '\0') {
#if HAVE_DECL_MYSQL_OPT_SSL_CIPHER
		if (!tls_option(mysql, MYSQL_OPT_SSL_CIPHER, configuration->tls_cipher, "cipher")) return FALSE;
#else
		return FALSE;
#endif
	}
	if (configuration->tls_ciphersuites[0] != '\0') {
#if HAVE_DECL_MYSQL_OPT_TLS_CIPHERSUITES
		if (!tls_option(mysql, MYSQL_OPT_TLS_CIPHERSUITES, configuration->tls_ciphersuites, "TLS 1.3 ciphersuite")) return FALSE;
#else
		return FALSE;
#endif
	}
	return TRUE;
}
