#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# cpudist   Summarize on- and off-CPU time per task as a histogram.
#
# USAGE: cpudist [-h] [-O] [-T] [-m] [-P] [-L] [-p PID] [interval] [count]
#
# This measures the time a task spends on or off the CPU, and shows this time
# as a histogram, optionally per-process.
#
# Copyright 2016 Sasha Goldshtein
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
from cStringIO import StringIO
import sys

pid = ""
section = ""
label = ""

debug = 0

def init_bpf(in_offcpu, in_pid, in_ms, in_pids, in_tids):
	global label
	global section
	global pid

	bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
ONCPU_HEADER

typedef struct pid_key {
    u64 id;
    u64 slot;
} pid_key_t;


BPF_HASH(start, u32, u64);
STORAGE

static inline void store_start(u32 tgid, u32 pid, u64 ts)
{
    if (FILTER)
        return;

    start.update(&pid, &ts);
}

static inline void update_hist(u32 tgid, u32 pid, u64 ts)
{
    if (FILTER)
        return;

    u64 *tsp = start.lookup(&pid);
    if (tsp == 0)
        return;

    if (ts < *tsp) {
        // Probably a clock issue where the recorded on-CPU event had a
        // timestamp later than the recorded off-CPU event, or vice versa.
        return;
    }
    u64 delta = ts - *tsp;
    FACTOR
    STORE
}

int sched_switch(struct pt_regs *ctx, struct task_struct *prev)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32, pid = pid_tgid;

#ifdef ONCPU
    if (prev->state == TASK_RUNNING) {
#else
    if (1) {
#endif
        u32 prev_pid = prev->pid;
        u32 prev_tgid = prev->tgid;
#ifdef ONCPU
        update_hist(prev_tgid, prev_pid, ts);
#else
        store_start(prev_tgid, prev_pid, ts);
#endif
    }

BAIL:
#ifdef ONCPU
    store_start(tgid, pid, ts);
#else
    update_hist(tgid, pid, ts);
#endif

    return 0;
}
	"""

	if not in_offcpu:
		bpf_text = bpf_text.replace('ONCPU_HEADER', "#define ONCPU\n")
	else:
		bpf_text = bpf_text.replace('ONCPU_HEADER', "")
	if in_pid:
		bpf_text = bpf_text.replace('FILTER', 'tgid != %s' % in_pid)
	else:
		bpf_text = bpf_text.replace('FILTER', '0')
	if in_ms:
		bpf_text = bpf_text.replace('FACTOR', 'delta /= 1000000;')
		label = "msecs"
	else:
		bpf_text = bpf_text.replace('FACTOR', 'delta /= 1000;')
		label = "usecs"
	if in_pids or in_tids:
		section = "pid"
		pid = "tgid"
		if in_tids:
			pid = "pid"
			section = "tid"
		bpf_text = bpf_text.replace('STORAGE',
			'BPF_HISTOGRAM(dist, pid_key_t);')
		bpf_text = bpf_text.replace('STORE',
			'pid_key_t key = {.id = ' + pid + ', .slot = bpf_log2l(delta)}; ' +
			'dist.increment(key);')
	else:
		section = ""
		bpf_text = bpf_text.replace('STORAGE', 'BPF_HISTOGRAM(dist);')
		bpf_text = bpf_text.replace('STORE',
			'dist.increment(bpf_log2l(delta));')
	if debug:
		print(bpf_text)

	b = BPF(text=bpf_text)
	b.attach_kprobe(event="finish_task_switch", fn_name="sched_switch")
	return b

def cpudistUtil(in_offcpu=False, in_pid=None, in_ms=False, in_pids=False, in_tids=False, in_interval=10, in_count=1):
	countdown = abs(int(in_count))
	interval = abs(int(in_interval))
	if in_pid:	
		in_pid = int(in_pid)

	old_stdout = sys.stdout
	sys.stdout = output = StringIO()

	b = init_bpf(in_offcpu, in_pid, in_ms, in_pids, in_tids)

	print("Tracing %s-CPU time... Hit Ctrl-C to end." %
		("off" if in_offcpu else "on"), file=output)

	dist = b.get_table("dist")
	while (1):
		sleep(interval)

		print(file=output)
		print("%-8s\n" % strftime("%H:%M:%S"), file=output, end="")

		def pid_to_comm(pid):
	    	   try:
			comm = open("/proc/%d/comm" % pid, "r").read()
			return "%d %s" % (pid, comm)
		   except IOError:
			return str(pid)

		dist.print_log2_hist(label, section, section_print_fn=pid_to_comm)
		dist.clear()

		countdown -= 1
		if countdown == 0:
		    b.detach_kprobe(event="finish_task_switch")
		    sys.stdout = old_stdout
		    return output.getvalue()

