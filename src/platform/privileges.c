/*
 * SPDX-FileCopyrightText: 2004-2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Fork maintenance: Thomas Vincent.
 * Project contributor history: CONTRIBUTORS.md.
 *
 * Original credits:
 * - Larry Adams (current development and enhancements)
 * - Rivo Nurges (rrd support, mysql poller cache, misc functions)
 * - RTG (core poller code, pthreads, snmp, autoconf examples)
 * - Brady Alleman/Doug Warner (threading ideas, implementation details)
 * - Cacti - http://www.cacti.net/
 */

#include "internal/common.h"
#include "app/spine.h"

/* Returns TRUE if CAP_NET_RAW was kept.  Exits if the ids cannot be changed. */
#ifdef HAVE_LCAP
/* This patch is adapted (copied) patch for ntpd from Jarno Huuskonen and
 * Pekka Savola that was adapted (copied) from a patch by Chris Wings to drop
 * root for xntpd.
 */
static int drop_root(uid_t server_uid, gid_t server_gid) {
	cap_t caps;
	int kept;

	/* Runs before logging is configured, so failures go to stderr via die(). */
	if (prctl(PR_SET_KEEPCAPS, 1)) {
		die("ERROR: prctl(PR_SET_KEEPCAPS, 1) failed; refusing to run");
	}

	if (setgroups(0, NULL) == -1) {
		die("ERROR: setgroups failed; refusing to run");
	}

	if (setegid(server_gid) == -1 || seteuid(server_uid) == -1) {
		die("ERROR: setegid/seteuid to uid=%d/gid=%d failed; refusing to run", server_uid, server_gid);
	}

	caps = cap_from_text("cap_net_raw=eip");
	kept = caps != NULL && cap_set_proc(caps) == 0;

	if (caps != NULL) {
		cap_free(caps);
	}

	/* Without the narrowed set, PR_SET_KEEPCAPS would carry every one of
	 * root's permitted capabilities across the uid change below.  Clearing
	 * it lets the kernel empty the set, and spine continues without ICMP
	 * unless datagram ICMP is allowed. */
	if (!kept && prctl(PR_SET_KEEPCAPS, 0)) {
		die("ERROR: prctl(PR_SET_KEEPCAPS, 0) failed; refusing to run");
	}

	if (setregid(server_gid, server_gid) == -1 ||
		setreuid(server_uid, server_uid) == -1) {
		die("ERROR: setregid/setreuid to uid=%d/gid=%d failed; refusing to run",
			server_uid, server_gid);
	}

	SPINE_LOG_LOW(("running as uid(%d)/gid(%d) euid(%d)/egid(%d)%s.",
		getuid(), getgid(), geteuid(), getegid(), kept ? " with cap_net_raw=eip" : ""));

	return kept;
}
#endif /* HAVE_LCAP */

/* Set when a setuid root start could not get raw ICMP before dropping root,
 * so checkAsRoot() can say so once logging is configured. */
static int setuid_icmp_lost = FALSE;

/*! \fn int privileges_dropped(uid_t uid, gid_t gid)
 *  \brief confirms root is gone for good rather than set aside
 *
 *  seteuid(0) succeeds while the real or saved uid is still 0, and setegid(0)
 *  while a group id is, so a failed attempt is the proof.
 *
 *  \return TRUE if every id is the invoking user's and root cannot come back
 */
int privileges_dropped(uid_t uid, gid_t gid) {
#ifdef HAVE_LCAP
	cap_t caps;
	cap_flag_value_t flag;
	cap_value_t value;
	int only_net_raw = TRUE;
#endif

	if (uid == 0 || getuid() != uid || geteuid() != uid || getgid() != gid || getegid() != gid) {
		return FALSE;
	}

#ifdef HAVE_LCAP
	/* A permitted capability could be raised again without any uid change,
	 * so anything beyond CAP_NET_RAW means root was not given up. */
	caps = cap_get_proc();
	if (caps == NULL) {
		return FALSE;
	}

	for (value = 0; value < 64; value++) {
		if (cap_get_flag(caps, value, CAP_PERMITTED, &flag) == 0 && flag == CAP_SET && value != CAP_NET_RAW) {
			only_net_raw = FALSE;
		}
	}

	cap_free(caps);

	if (!only_net_raw) {
		return FALSE;
	}
#endif

	if (seteuid(0) == 0) {
		return FALSE;
	}

	if (gid != 0 && setegid(0) == 0) {
		return FALSE;
	}

	return TRUE;
}

/*! \fn void drop_privileges(void)
 *  \brief gives up setuid root before spine reads any input
 *
 *  Spine is installed setuid root only to open raw ICMP sockets.  Options and
 *  the config file can name files that spine then creates or writes, so all
 *  input is handled as the invoking user.  This runs first in main(), opens
 *  what ICMP needs while still root, then drops root permanently.  A real root user
 *  (uid 0, for example from cron) keeps running as root, as before; with
 *  libcap it is narrowed to CAP_NET_RAW, also as before.
 *
 *  Never returns while spine is setuid root: it drops or exits.
 */
void drop_privileges(void) {
	uid_t uid = getuid();
	gid_t gid = getgid();
	int icmp_ready;

	if (geteuid() != 0 || uid == 0) {
#ifdef HAVE_LCAP
		/* --enable-lcap confines a root run to CAP_NET_RAW.  Running on with
		 * all of root's capabilities would silently undo that, so refuse. */
		if (geteuid() == 0 && !drop_root(uid, gid)) {
			die("ERROR: Spine runs as root but could not confine itself to CAP_NET_RAW; refusing to run");
		}
#endif
		return;
	}

#ifdef HAVE_LCAP
	icmp_ready = drop_root(uid, gid);
#else
	icmp_ready = ping_icmp_open_shared();

	/* With an effective uid of 0, POSIX setgid() and setuid() replace the
	 * real, effective and saved ids; seteuid() would keep root in reserve.
	 * Unlike drop_root(), this keeps the supplementary groups: a setuid exec
	 * does not change them, so they are the caller's own. */
	if (setgid(gid) != 0 || setuid(uid) != 0) {
		die("ERROR: Spine is setuid root and could not drop to uid %d/gid %d; refusing to run", (int) uid, (int) gid);
	}
#endif

	/* The one case that stops spine: running on with root still reachable. */
	if (!privileges_dropped(uid, gid)) {
		die("ERROR: Spine is setuid root and could not drop root permanently; refusing to run");
	}

	/* Missing ICMP is not a reason to stop polling: checkAsRoot() tries
	 * datagram ICMP and otherwise warns, and ICMP pings fall back to UDP. */
	setuid_icmp_lost = !icmp_ready;
}

int hasCaps(void) {
#ifdef HAVE_LCAP
	cap_t caps;
	cap_flag_value_t capflag;

	/* Recommended caps: cap_net_raw=eip */
	caps = cap_get_proc();
	if (caps == NULL) {
		SPINE_LOG(("ERROR: cap_get_proc failed."));
		return FALSE;
	}

	/* check if cap_net_raw is in effective set */
	if (cap_get_flag(caps, CAP_NET_RAW, CAP_EFFECTIVE, &capflag)) {
		SPINE_LOG(("ERROR: cap_get_flag for CAP_NET_RAW failed. Falling back to unprivileged ICMP where available."));
		cap_free(caps);
		return FALSE;
	}

	if (capflag != CAP_SET) {
		SPINE_LOG_MEDIUM(("WARNING: Capability CAP_NET_RAW is not set. Falling back to unprivileged ICMP where available."));
		cap_free(caps);
		return FALSE;
	}

	SPINE_LOG_DEBUG(("DEBUG: Capability CAP_NET_RAW is set."));
	cap_free(caps);

	return TRUE;
#else
	return FALSE;
#endif
}

void checkAsRoot(void) {
	set.availability.icmp_uses_caps = FALSE;
#ifndef __CYGWIN__
#ifdef SOLAR_PRIV
	priv_set_t *privset;
	char *p;

	/* Get the basic set */
	privset = priv_str_to_set("basic", ",", NULL);
	if (privset == NULL) {
		die("ERROR: Could not get basic privset from priv_str_to_set().");
	} else {
		p = priv_set_to_str(privset, ',', 0);
		SPINE_LOG_DEBUG(("DEBUG: Basic privset is: '%s'.", p != NULL ? p : "Unknown"));
	}

	/* Add privilege to send/receive ICMP packets */
	if (priv_addset(privset, PRIV_NET_ICMPACCESS) < 0) {
		SPINE_LOG_DEBUG(("WARNING: Addition of PRIV_NET_ICMPACCESS to privset failed: '%s'.", strerror(errno)));
	}

	/* Compute the set of privileges that are never needed */
	priv_inverse(privset);

	/* Remove the set of unneeded privs from Permitted (and by
	 * implication from Effective) */
	if (setppriv(PRIV_OFF, PRIV_PERMITTED, privset) < 0) {
		SPINE_LOG_DEBUG(("WARNING: Dropping privileges from PRIV_PERMITTED failed: '%s'.", strerror(errno)));
	}

	/* Remove unneeded priv set from Limit to be safe */
	if (setppriv(PRIV_OFF, PRIV_LIMIT, privset) < 0) {
		SPINE_LOG_DEBUG(("WARNING: Dropping privileges from PRIV_LIMIT failed: '%s'.", strerror(errno)));
	}

	boolean_t pe = priv_ineffect(PRIV_NET_ICMPACCESS);
	SPINE_LOG_DEBUG(("DEBUG: Privilege PRIV_NET_ICMPACCESS is: '%s'.", pe != 0 ? "Enabled" : "Disabled"));

	set.availability.icmp_avail = pe || ping_icmp_shared_available();

	/* Free the privset */
	priv_freeset(privset);
	free(p);
#else
	/* Never regains root here: a setuid install gave it up in drop_privileges(). */
	if (hasCaps() != TRUE) {
		SPINE_LOG_DEBUG(("DEBUG: Spine running as %d UID, %d EUID", getuid(), geteuid()));

		if (ping_icmp_shared_available()) {
			SPINE_LOG_DEBUG(("DEBUG: Spine uses the raw ICMP sockets it opened before dropping root."));
			set.availability.icmp_avail = TRUE;
		} else if (geteuid() != 0) {
			int probe;

			/* A file capability (setcap cap_net_raw+ep) works without libcap
			 * support too, so ask the kernel rather than hasCaps().  Root is
			 * not the only way in either: net.ipv4.ping_group_range lists the
			 * groups allowed to open datagram ICMP sockets. */
			probe = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

			if (probe != -1) {
				close(probe);
				SPINE_LOG_DEBUG(("DEBUG: Spine may open raw ICMP sockets."));
				set.availability.icmp_avail = TRUE;
			} else if ((probe = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)) != -1) {
				close(probe);
				SPINE_LOG_DEBUG(("DEBUG: Spine may use unprivileged ICMP sockets."));
				set.availability.icmp_avail = TRUE;
			} else if (setuid_icmp_lost) {
				SPINE_LOG(("WARNING: Spine is setuid root but could not get raw ICMP access before dropping root, and net.ipv4.ping_group_range does not cover this user.  ICMP pings fall back to UDP; SNMP polling continues."));
				set.availability.icmp_avail = FALSE;
			} else {
				SPINE_LOG_DEBUG(("WARNING: Spine has no ICMP access.  Install it setuid root (chown root:root spine; chmod u+s spine), grant it CAP_NET_RAW (setcap cap_net_raw+ep spine), or widen net.ipv4.ping_group_range to cover this user."));
				set.availability.icmp_avail = FALSE;
			}
		} else {
			SPINE_LOG_DEBUG(("DEBUG: Spine is running as root."));
			set.availability.icmp_avail = TRUE;
		}
	} else {
		SPINE_LOG_DEBUG(("DEBUG: Spine has cap_net_raw capability."));
		set.availability.icmp_avail = TRUE;
		set.availability.icmp_uses_caps = TRUE;
	}
	SPINE_LOG_DEBUG(("DEBUG: Spine has %sgot ICMP", set.availability.icmp_avail ? "" : "not "));
#endif
#endif
}
