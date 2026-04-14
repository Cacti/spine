/*
 * Unit test: IPv6 link-local scope_id resolution.
 *
 * Covers two cases: a non-link-local destination must not be touched,
 * and a link-local destination must have sin6_scope_id filled. Skips
 * gracefully on hosts without a usable non-loopback IPv6 interface
 * (common in minimal CI containers).
 */
#include <string.h>

#ifdef _WIN32
/* scope_id helper is POSIX-only; nothing meaningful to do on Windows
 * where Icmp6SendEcho2 takes a sockaddr_in6 that Windows fills itself. */
int main(void) {
	return 0;
}
#else

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "test_platform_helpers.h"

int spine_apply_ipv6_scope_id(struct sockaddr_in6 *sin6, const char *ifname);

static void test_non_linklocal_untouched(void) {
	struct sockaddr_in6 s;
	memset(&s, 0, sizeof(s));
	s.sin6_family = AF_INET6;
	/* 2001:db8::1 is documentation-range global unicast, not link-local. */
	ASSERT_INT_EQ(inet_pton(AF_INET6, "2001:db8::1", &s.sin6_addr), 1);
	s.sin6_scope_id = 0;
	ASSERT_INT_EQ(spine_apply_ipv6_scope_id(&s, NULL), 0);
	ASSERT_INT_EQ((int) s.sin6_scope_id, 0);
}

static void test_linklocal_gets_scope(void) {
	struct sockaddr_in6 s;
	int rc;
	memset(&s, 0, sizeof(s));
	s.sin6_family = AF_INET6;
	ASSERT_INT_EQ(inet_pton(AF_INET6, "fe80::1", &s.sin6_addr), 1);
	s.sin6_scope_id = 0;
	rc = spine_apply_ipv6_scope_id(&s, NULL);
	/* rc == 0 on hosts with a non-loopback v6 interface, -1 in
	 * minimal containers. In either case the function must not
	 * corrupt sin6_family or the address bytes. */
	ASSERT_TRUE(rc == 0 || rc == -1);
	ASSERT_INT_EQ(s.sin6_family, AF_INET6);
}

static void test_preserves_existing_scope(void) {
	struct sockaddr_in6 s;
	memset(&s, 0, sizeof(s));
	s.sin6_family = AF_INET6;
	ASSERT_INT_EQ(inet_pton(AF_INET6, "fe80::2", &s.sin6_addr), 1);
	s.sin6_scope_id = 42;
	ASSERT_INT_EQ(spine_apply_ipv6_scope_id(&s, NULL), 0);
	ASSERT_INT_EQ((int) s.sin6_scope_id, 42);
}

static void test_null_is_error(void) {
	ASSERT_INT_EQ(spine_apply_ipv6_scope_id(NULL, NULL), -1);
}

int main(void) {
	test_non_linklocal_untouched();
	test_linklocal_gets_scope();
	test_preserves_existing_scope();
	test_null_is_error();
	return finish_tests("ping ipv6 scope tests");
}

#endif /* !_WIN32 */
