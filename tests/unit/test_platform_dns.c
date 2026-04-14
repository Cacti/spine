#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netdb.h>
#endif

#include "test_platform_helpers.h"

static void test_dns_lookup_localhost_unspec(void) {
	struct addrinfo hints;
	struct addrinfo *result = NULL;
	int rc;
	int count = 0;
	struct addrinfo *cursor;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_ADDRCONFIG;

	rc = getaddrinfo("localhost", "80", &hints, &result);
	ASSERT_INT_EQ(rc, 0);
	if (rc == 0 && result != NULL) {
		for (cursor = result; cursor != NULL; cursor = cursor->ai_next) {
			count++;
		}
		ASSERT_TRUE(count > 0);
	}

	if (result != NULL) {
		freeaddrinfo(result);
	}
}

static void test_dns_lookup_numeric_ipv4_loopback(void) {
	struct addrinfo hints;
	struct addrinfo *result = NULL;
	int rc;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST;

	rc = getaddrinfo("127.0.0.1", "80", &hints, &result);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_TRUE(result != NULL);

	if (result != NULL) {
		freeaddrinfo(result);
	}
}

static void test_dns_lookup_numeric_ipv6_loopback(void) {
	struct addrinfo hints;
	struct addrinfo *result = NULL;
	int rc;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST;

	rc = getaddrinfo("::1", "80", &hints, &result);
	if (rc == EAI_FAMILY
#ifdef EAI_ADDRFAMILY
		|| rc == EAI_ADDRFAMILY
#endif
		) {
		/* Environment may have IPv6 disabled; skip instead of failing. */
		return;
	}

	ASSERT_INT_EQ(rc, 0);
	ASSERT_TRUE(result != NULL);

	if (result != NULL) {
		freeaddrinfo(result);
	}
}

static void test_dns_reject_ipv4_literal_when_forced_ipv6(void) {
	struct addrinfo hints;
	struct addrinfo *result = NULL;
	int rc;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST;

	rc = getaddrinfo("127.0.0.1", "80", &hints, &result);
	ASSERT_TRUE(rc != 0);

	if (result != NULL) {
		freeaddrinfo(result);
	}
}

static void test_dns_ipv4_mapped_ipv6_if_supported(void) {
#if defined(AI_V4MAPPED) && defined(AI_ALL)
	struct addrinfo hints;
	struct addrinfo *result = NULL;
	struct addrinfo *cursor;
	int rc;
	int saw_ipv6 = 0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST | AI_V4MAPPED | AI_ALL;

	rc = getaddrinfo("127.0.0.1", "80", &hints, &result);
	if (rc != 0) {
		/* Some stacks intentionally do not expose mapped addresses. */
		return;
	}

	for (cursor = result; cursor != NULL; cursor = cursor->ai_next) {
		if (cursor->ai_family == AF_INET6) {
			saw_ipv6 = 1;
			break;
		}
	}
	ASSERT_TRUE(saw_ipv6 == 1);

	if (result != NULL) {
		freeaddrinfo(result);
	}
#endif
}

static void test_dns_ipv6_numeric_scope_id_parse_best_effort(void) {
	struct addrinfo hints;
	struct addrinfo *result = NULL;
	int rc;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICHOST;

	rc = getaddrinfo("fe80::1%1", "161", &hints, &result);
	if (rc != 0) {
		/* Scope-id support varies by OS and libc. */
		return;
	}

	ASSERT_TRUE(result != NULL);
	if (result != NULL) {
		ASSERT_INT_EQ(result->ai_family, AF_INET6);
		freeaddrinfo(result);
	}
}

int main(void) {
#ifdef _WIN32
	WSADATA wsa_data;
	int wsa_rc;

	wsa_rc = WSAStartup(MAKEWORD(2, 2), &wsa_data);
	ASSERT_INT_EQ(wsa_rc, 0);
#endif

	test_dns_lookup_localhost_unspec();
	test_dns_lookup_numeric_ipv4_loopback();
	test_dns_lookup_numeric_ipv6_loopback();
	test_dns_reject_ipv4_literal_when_forced_ipv6();
	test_dns_ipv4_mapped_ipv6_if_supported();
	test_dns_ipv6_numeric_scope_id_parse_best_effort();

#ifdef _WIN32
	WSACleanup();
#endif

	return finish_tests("platform dns tests");
}
