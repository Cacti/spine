# Golden capture for poll_host() query construction

`poll_host()` is the largest function in the tree and builds its SQL inline, so
the construction cannot be reached from `make check`. Before changing it, pin
what it currently emits.

`poll_host_queries.golden` is the output of every query `poll_host()` builds,
across the input vectors it branches on: `total_snmp_ports` 1 and 2,
`dbonupdate` 0 and 1, and a main poller and a remote poller.

To recapture, lift the query-building body out of `poller.c` into a standalone
`main()` that declares the handful of inputs it reads (`host_id`, `regex_col`,
`limits`, and `set.poller_id`, `set.total_snmp_ports`, `set.dbonupdate`,
`set.poller_interval`, `set.active_profiles`), print each buffer, and diff the
result against this file. The body compiles standalone: that closed input set is
what makes the extraction safe.

Use it the same way for the next piece of `poll_host()` that gets extracted.
Capture first, refactor second, and require the diff to be empty or to contain
only changes you can name in advance.
