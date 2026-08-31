#!/bin/sh
# Stands in for a Cacti data-input script: echoes the value it was handed, so
# the integration check can assert the poller stored exactly what the script
# printed.
echo "$1"
