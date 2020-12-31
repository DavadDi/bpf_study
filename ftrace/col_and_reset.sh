#!/bin/bash

debugfs=/sys/kernel/debug

cat $debugfs/tracing/trace > /tmp/trace.log

# reset again
echo nop > $debugfs/tracing/current_tracer
echo 0 > $debugfs/tracing/tracing_on
