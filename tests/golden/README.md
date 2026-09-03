# Golden capture for poll_host() query construction

`poll_host_queries.golden` holds every query `poll_host()` builds for one
device, across the inputs it branches on: `total_snmp_ports` 1 and 2,
`dbonupdate` 0 and 1, a main poller and a remote poller.

`test_build_queries_matches_the_golden_capture` in `tests/unit/test_linked.c`
regenerates that output from `poll_host_build_queries()` and diffs it line by
line, so `make check` fails on any change to the SQL. It reports the first
differing line and prints both sides.

Point it at another file with `SPINE_GOLDEN=path ./tests/unit/test_linked`.

## Changing the queries

A deliberate change makes the test fail. That is the point: update the fixture
in the same commit as the code, and say in the commit message what moved. Do
not regenerate it without reading the diff first, and never regenerate it to
make a red build green.

## Extending it

The fixture only covers what `poll_host_build_queries()` produces. The rest of
`poll_host()` still builds and mutates state inline and is not reachable from a
test. When the next piece comes out, capture what it emits before moving it,
extract, then require the diff to be empty or to contain only changes named in
advance. That is how #590 was found: the two branches of the old code disagreed
about `dbonupdate`, and the capture showed it.
