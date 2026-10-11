<!-- SPDX-FileCopyrightText: 2026 The Cacti Group -->
<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# External script execution limits

External data-source and reindex scripts can opt into a stricter per-command
policy through `spine.conf`. All six settings default to zero. With all settings
unset or zero, Spine preserves the existing configured script timeout and
single-read result contract. Persistent PHP script servers use their existing
lifecycle policy and are not subject to these per-command resource caps.

| Setting | Unit and valid range | Meaning when nonzero |
| --- | --- | --- |
| `Script_DeadlineSeconds` | seconds, 1–86400 | Tightens the configured `script_timeout`; the smaller timeout applies. |
| `Script_OutputBytes` | bytes, 1–`RESULTS_BUFFER - 1` | Maximum complete stdout response, including whitespace and line endings. |
| `Script_CPUSeconds` | seconds, 1–86400 | Inherited per-process soft and hard CPU limit. |
| `Script_MemoryKiB` | KiB, 1–2147483647 | Inherited per-process soft and hard virtual-address-space limit. |
| `Script_FileKiB` | KiB, 1–2147483647 | Inherited per-file soft and hard size limit. |
| `Script_OpenFiles` | descriptors, 1–2147483647 | Inherited per-process soft and hard open-file limit. |

Zero disables an individual setting. Negative values, signs, nonnumeric values,
overflow and missing policy values fail configuration loading. Output limits
cannot exceed Spine's compiled result-buffer capacity. CPU, memory, file-size
and descriptor caps currently require the Linux `/bin/sh` backend. Explicit
resource caps on other platforms fail before spawning the command. Failure to
apply a shell limit returns a failed child status rather than running uncapped.

For example, this limits each command to five seconds, 1,024 output bytes, two
CPU seconds, 128 MiB of virtual address space, 1 MiB per file and 64 descriptors:

```text
Script_DeadlineSeconds 5
Script_OutputBytes 1024
Script_CPUSeconds 2
Script_MemoryKiB 131072
Script_FileKiB 1024
Script_OpenFiles 64
```

Enabling any setting requires a complete response ending at stdout EOF within
the deadline and a successful child exit. If no output size is specified, the
complete-response maximum is `RESULTS_BUFFER - 1`. A result followed by more
output, a lingering child, nonzero exit, resource signal, read failure or limit
breach produces `U`; excessive output is never silently accepted as a truncated
value. On output or deadline failure, Spine kills the command's process group,
closes its descriptor and uses its existing bounded reap and deferred-reap
registry. Cancellation owns the same cleanup and releases only the permit that
the cancelled call acquired. Cancellation while waiting cannot return another
thread's permit.

Policy code is fixed; numeric limits and the trusted Cacti command are supplied
as separate positional shell arguments. They are not concatenated into policy
code. Linux shell file-size units are converted from KiB to 512-byte blocks;
the production-linked tests check the resulting kernel soft and hard limits.
See the [Debian dash manual](https://manpages.debian.org/bullseye/dash/dash.1.en.html)
for the shell limit interface.

Spine logs the host and breach reason. Failed child exit diagnostics also name
the data-source/query ID and executable, without printing its arguments. The
command still comes from the trusted Cacti database and intentionally runs as a
shell command. This is resource management, not an isolation sandbox: limits
apply per process, not to aggregate descendant memory/CPU, and a trusted script
that deliberately creates a new process group can leave the original group.
Linux process limits also do not bound network traffic or total disk writes
across multiple files. Use operating-system service/container controls when
those aggregate guarantees are needed.

`bash tests/tools/run_script_limits.sh` exercises real children against CPU,
memory, file-size and descriptor limits, plus complete-output, delayed-output,
deadline, failed-exit and deferred/asynchronous cancellation cases. Its small C
workload is deliberately compiled without sanitizer instrumentation: ASan's
reserved virtual address space would prevent a low-memory workload from
starting. The production parent remains instrumented in sanitizer builds.
