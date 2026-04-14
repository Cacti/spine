#include "platform.h"

#ifdef _WIN32

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <winsock2.h>
#include <windows.h>
#include <process.h>
#include <io.h>

int spine_platform_init_once(void) {
	WSADATA wsa_data;

	return WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0 ? 0 : -1;
}

void spine_platform_cleanup_once(void) {
	WSACleanup();
}

int spine_platform_setenv(const char *name, const char *value, int overwrite) {
	if (!overwrite && getenv(name) != NULL) {
		return 0;
	}

	return _putenv_s(name, value);
}

int spine_platform_localtime(const time_t *when, struct tm *out) {
	return localtime_s(out, when);
}

void spine_platform_sleep_ms(unsigned int milliseconds) {
	Sleep(milliseconds);
}

void spine_platform_sleep_us(unsigned int microseconds) {
	LARGE_INTEGER freq;
	LARGE_INTEGER start;
	LARGE_INTEGER now;
	LONGLONG target_ticks;
	unsigned long iterations;
	unsigned long iteration_cap;

	if (microseconds == 0) {
		return;
	}

	/* Sleep() has millisecond granularity; for >= 1 ms just defer to the scheduler. */
	if (microseconds >= 1000U) {
		Sleep((DWORD)(microseconds / 1000U));
		return;
	}

	/* Sub-millisecond busy-wait via QPC. Spine retries tight SNMP/PHP loops with
	 * 1..999 us waits; rounding up to 1 ms (Sleep's minimum) stretches those loops
	 * by 500x or more and visibly slows polling under load. */
	if (!QueryPerformanceFrequency(&freq) || freq.QuadPart <= 0) {
		Sleep(1);
		return;
	}

	/* Overflow guard: microseconds <= 999, so the multiplication is safe whenever
	 * freq.QuadPart stays below LLONG_MAX / 1000000. Any frequency outside that
	 * envelope (pathological or future hardware) falls back to Sleep(1). */
	if (freq.QuadPart > LLONG_MAX / 1000000LL) {
		Sleep(1);
		return;
	}

	QueryPerformanceCounter(&start);
	target_ticks = start.QuadPart + (((LONGLONG)microseconds * freq.QuadPart) / 1000000LL);

	/* Bound the spin so a non-monotonic or stalled QPC reading can't peg a core.
	 * 4096 * microseconds gives thousands of retries for a 1 us wait yet still
	 * exits in tens of ms under worst-case scheduler pressure. SwitchToThread()
	 * every 64 iterations lets the scheduler run other runnable threads on the
	 * same processor rather than starving them behind YieldProcessor hints. */
	iterations = 0;
	iteration_cap = 4096UL * (unsigned long)microseconds;
	do {
		YieldProcessor();
		if ((++iterations & 0x3FUL) == 0) {
			SwitchToThread();
		}
		if (iterations >= iteration_cap) {
			Sleep(1);
			return;
		}
		QueryPerformanceCounter(&now);
	} while (now.QuadPart < target_ticks);
}

void spine_platform_sleep_s(unsigned int seconds) {
	Sleep(seconds * 1000U);
}

unsigned long spine_platform_process_id(void) {
	return (unsigned long) _getpid();
}

int spine_platform_stdout_is_terminal(void) {
	return _isatty(_fileno(stdout));
}

int spine_platform_stderr_is_terminal(void) {
	return _isatty(_fileno(stderr));
}

#endif
