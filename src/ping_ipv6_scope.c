/*
 * Standalone IPv6 link-local scope_id resolver.
 *
 * Called from the IPv6 raw-socket ping path and from the numeric
 * oneshot helpers. Kept in its own TU so the unit test can link
 * directly against just this object without dragging in mysql /
 * net-snmp / poller deps through ping.c.
 */
#include <stddef.h>
#include <string.h>

#ifdef _WIN32
/* No-op stub: Windows paths construct sockaddr_in6 through IP Helper
 * APIs that manage scope internally. */
struct sockaddr_in6;
int spine_apply_ipv6_scope_id(struct sockaddr_in6 *sin6, const char *ifname) {
	(void) sin6; (void) ifname;
	return 0;
}
#else

#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>

int spine_apply_ipv6_scope_id(struct sockaddr_in6 *sin6, const char *ifname) {
	if (sin6 == NULL) {
		return -1;
	}
	if (!IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
		return 0;
	}
	if (sin6->sin6_scope_id != 0) {
		return 0;
	}

	if (ifname != NULL && ifname[0] != '\0') {
		unsigned int idx = if_nametoindex(ifname);
		if (idx != 0) {
			sin6->sin6_scope_id = idx;
			return 0;
		}
	}

	{
		struct ifaddrs *ifa_list = NULL;
		struct ifaddrs *ifa;
		int found = 0;
		if (getifaddrs(&ifa_list) == 0) {
			for (ifa = ifa_list; ifa != NULL; ifa = ifa->ifa_next) {
				if (ifa->ifa_addr == NULL) continue;
				if (ifa->ifa_addr->sa_family != AF_INET6) continue;
				if (ifa->ifa_flags & IFF_LOOPBACK) continue;
				sin6->sin6_scope_id = if_nametoindex(ifa->ifa_name);
				if (sin6->sin6_scope_id != 0) {
					found = 1;
					break;
				}
			}
			freeifaddrs(ifa_list);
		}
		return found ? 0 : -1;
	}
}

#endif /* !_WIN32 */
