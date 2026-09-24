# GitHub Copilot Instructions for spine

## Script and process execution design principles (do not regress)

These constraints exist because they were each violated once and caused a
measurable poller slowdown (develop PR #614, and this branch's own
long-standing `nft_pclose()`). Any change touching script or PHP Script
Server execution must preserve all three:

- **One shot, no EOF wait.** A script or PHP Script Server command gets
  exactly one read attempt within `script_timeout`. Never loop reading
  until EOF or read a second response after the first read (or timeout)
  completes. See `exec_poll()` in `poller.c` and `php_read_result()` in
  `php.c`.
- **Never block the polling thread on `waitpid()`.** After a script's
  pipe is closed, reap with a single non-blocking `waitpid(..., WNOHANG)`
  and stop there. Do not spin/`usleep()`/retry waiting for the child to
  exit, and do not escalate SIGTERM/SIGKILL synchronously in the calling
  thread — hand off anything not immediately reaped to an async sweep.
  This applies to both `nft_pclose()` (in `nft_popen.c`) and
  `php_close()` (in `php.c`).
- **Script timeouts must go through `nft_popen()`/`nft_pchild()`.**
  Killing a timed-out script requires the real child pid, which is only
  tracked by `nft_popen()`. Do not reintroduce or expand the native
  `popen()`/`pclose()` code path (`USING_TPOPEN`/`--enable-popen`) — it
  cannot expose a pid to kill on timeout and abandons the
  process/descriptor instead of terminating it.
