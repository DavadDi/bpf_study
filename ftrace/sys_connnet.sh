#!/bin/bash

debugfs=/sys/kernel/debug

# clear
echo nop > $debugfs/tracing/current_tracer
echo 0 > $debugfs/tracing/tracing_on

# start
echo $$ > $debugfs/tracing/set_ftrace_pid
echo function_graph > $debugfs/tracing/current_tracer

#replace test_proc_show by your function name
echo __sys_connect > $debugfs/tracing/set_graph_function
echo 1 > $debugfs/tracing/tracing_on
exec "$@"
