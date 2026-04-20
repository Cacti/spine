#include "platform.h"

#ifdef _WIN32

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <winsock2.h>
#include <windows.h>
#include <process.h>
#include <io.h>

typedef struct {
	INIT_ONCE job_once;
	HANDLE job_object;
} spine_win_runtime_t;

static spine_win_runtime_t g_win_runtime = {
	INIT_ONCE_STATIC_INIT,
	NULL
};

static BOOL CALLBACK spine_win_job_init_once(PINIT_ONCE init_once, PVOID param, PVOID *context) {
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
	HANDLE job_object;

	(void)init_once;
	(void)param;
	(void)context;

	job_object = CreateJobObjectW(NULL, NULL);
	if (job_object == NULL) {
		return TRUE; /* best-effort; keep runtime functional without a job */
	}

	memset(&limits, 0, sizeof(limits));
	limits.BasicLimitInformation.LimitFlags =
		JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
		JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION |
		JOB_OBJECT_LIMIT_BREAKAWAY_OK;
	if (!SetInformationJobObject(job_object, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
		CloseHandle(job_object);
		return TRUE;
	}

	g_win_runtime.job_object = job_object;
	return TRUE;
}

int spine_platform_init_once(void) {
	WSADATA wsa_data;

	if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
		return -1;
	}

	/* Job Object creation is best-effort -- a missing job still lets spine
	 * run, it just loses KILL_ON_JOB_CLOSE cleanup for orphaned children. */
	spine_win_init_job();
	return 0;
}

void spine_platform_cleanup_once(void) {
	if (g_win_runtime.job_object != NULL) {
		CloseHandle(g_win_runtime.job_object);
		g_win_runtime.job_object = NULL;
	}
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

void spine_platform_set_thread_name(const char *name) {
	/* SetThreadDescription arrived in Windows 10 1607. Resolving it through
	 * GetProcAddress keeps the binary runnable on older SKUs -- older Windows
	 * just returns silently. */
	typedef HRESULT (WINAPI *set_thread_description_fn)(HANDLE, PCWSTR);
	static set_thread_description_fn resolved = NULL;
	static int resolve_attempted = 0;
	wchar_t wide_name[64];
	int converted;

	if (name == NULL) {
		return;
	}

	if (!resolve_attempted) {
		HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
		if (kernel32 != NULL) {
			resolved = (set_thread_description_fn) GetProcAddress(kernel32, "SetThreadDescription");
		}
		resolve_attempted = 1;
	}
	if (resolved == NULL) {
		return;
	}

	converted = MultiByteToWideChar(CP_UTF8, 0, name, -1, wide_name,
		(int) (sizeof(wide_name) / sizeof(wide_name[0])));
	if (converted <= 0) {
		return;
	}

	(void) resolved(GetCurrentThread(), wide_name);
}

/* Job Object confinement for child processes spawned via CreateProcessW.
 * KILL_ON_JOB_CLOSE guarantees orphaned poll scripts die with spine;
 * DIE_ON_UNHANDLED_EXCEPTION suppresses the Windows Error Reporting modal
 * that would otherwise stall a headless poller. BREAKAWAY_OK leaves an
 * escape hatch for operator-launched helpers that must outlive spine. */
void spine_win_init_job(void) {
	(void)InitOnceExecuteOnce(&g_win_runtime.job_once, spine_win_job_init_once, NULL, NULL);
}

void *spine_win_job_object(void) {
	return (void *) g_win_runtime.job_object;
}

#endif
