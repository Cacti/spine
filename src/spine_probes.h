/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | USDT (user statically defined tracing) probes. On Linux with systemtap
 | headers these expand into <sys/sdt.h> DTRACE_PROBE macros; on every
 | other platform they compile to nothing so probe sites never branch at
 | runtime. bpftrace and perf can attach against the resulting ELF notes.
 +-------------------------------------------------------------------------+
*/

#ifndef SPINE_PROBES_H
#define SPINE_PROBES_H

#if defined(__linux__) && defined(HAVE_SYS_SDT_H)
#include <sys/sdt.h>
#define SPINE_PROBE0(name)           DTRACE_PROBE(spine, name)
#define SPINE_PROBE1(name, a)        DTRACE_PROBE1(spine, name, a)
#define SPINE_PROBE2(name, a, b)     DTRACE_PROBE2(spine, name, a, b)
#define SPINE_PROBE3(name, a, b, c)  DTRACE_PROBE3(spine, name, a, b, c)
#else
/* macOS and FreeBSD ship native DTrace but expect probes declared in a .d
 * provider script and compiled through `dtrace -h`. Spine does not ship
 * that script yet, so probes compile out on those platforms. */
#define SPINE_PROBE0(name)           ((void)0)
#define SPINE_PROBE1(name, a)        ((void)(a))
#define SPINE_PROBE2(name, a, b)     do { (void)(a); (void)(b); } while (0)
#define SPINE_PROBE3(name, a, b, c)  do { (void)(a); (void)(b); (void)(c); } while (0)
#endif

#endif /* SPINE_PROBES_H */
