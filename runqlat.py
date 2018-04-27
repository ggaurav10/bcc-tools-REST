#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# runqlat   Run queue (scheduler) latency as a histogram.
#           For Linux, uses BCC, eBPF.
#
# USAGE: runqlat [-h] [-T] [-m] [-P] [-L] [-p PID] [interval] [count]
#
# This measures the time a task spends waiting on a run queue for a turn
# on-CPU, and shows this time as a histogram. This time should be small, but a
# task may need to wait its turn due to CPU load.
#
# This measures two types of run queue latency:
# 1. The time from a task being enqueued on a run queue to its context switch
#    and execution. This traces enqueue_task_*() -> finish_task_switch(),
#    and instruments the run queue latency after a voluntary context switch.
# 2. The time from when a task was involuntary context switched and still
#    in the runnable state, to when it next executed. This is instrumented
#    from finish_task_switch() alone.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 07-Feb-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import sys
from cStringIO import StringIO

debug = 0
section = ""
label = ""

def init_bpf(in_ms, in_pids, in_tids, in_pid):
	# define BPF program
	bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

typedef struct pid_key {
    u64 id;    // work around
    u64 slot;
} pid_key_t;
BPF_HASH(start, u32);
STORAGE

struct rq;

// record enqueue timestamp
int trace_enqueue(struct pt_regs *ctx, struct rq *rq, struct task_struct *p,
    int flags)
{
    u32 tgid = p->tgid;
    u32 pid = p->pid;
    if (FILTER)
        return 0;
    u64 ts = bpf_ktime_get_ns();
    start.update(&pid, &ts);
    return 0;
}

// calculate latency
int trace_run(struct pt_regs *ctx, struct task_struct *prev)
{
    u32 pid, tgid;

    // ivcsw: treat like an enqueue event and store timestamp
    if (prev->state == TASK_RUNNING) {
        tgid = prev->tgid;
        pid = prev->pid;
        if (!(FILTER)) {
            u64 ts = bpf_ktime_get_ns();
            start.update(&pid, &ts);
        }
    }

    tgid = bpf_get_current_pid_tgid() >> 32;
    pid = bpf_get_current_pid_tgid();
    if (FILTER)
        return 0;
    u64 *tsp, delta;

    // fetch timestamp and calculate delta
    tsp = start.lookup(&pid);
    if (tsp == 0) {
        return 0;   // missed enqueue
    }
    delta = bpf_ktime_get_ns() - *tsp;
    FACTOR

    // store as histogram
    STORE

    start.delete(&pid);
    return 0;
}
	"""

	global label
	global section
	# code substitutions
	if in_pid:
		# pid from userspace point of view is thread group from kernel pov
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

	# load BPF program
	b = BPF(text=bpf_text)
	b.attach_kprobe(event="enqueue_task_fair", fn_name="trace_enqueue")
	b.attach_kprobe(event="enqueue_task_rt", fn_name="trace_enqueue")
	b.attach_kprobe(event="enqueue_task_dl", fn_name="trace_enqueue")
	b.attach_kprobe(event="enqueue_task_stop", fn_name="trace_enqueue")
	b.attach_kprobe(event="finish_task_switch", fn_name="trace_run")

	return b

def detach(b):
	b.detach_kprobe(event="enqueue_task_fair")
	b.detach_kprobe(event="enqueue_task_rt")
	b.detach_kprobe(event="enqueue_task_dl")
	b.detach_kprobe(event="enqueue_task_stop")
	b.detach_kprobe(event="finish_task_switch")

def runqlatUtil(in_ms, in_pids, in_tids, in_pid, in_interval, in_count):
	countdown = abs(int(in_count))
	old_stdout = sys.stdout
	sys.stdout = output = StringIO()
	b = init_bpf(in_ms, in_pids, in_tids, in_pid)
	print("Tracing run queue latency...", file = output)
	# output
	dist = b.get_table("dist")
	while (1):
		sleep(int(in_interval))

		print(file=output)
		print("%-8s\n" % strftime("%H:%M:%S"), file = output, end="")

		dist.print_log2_hist(label, section, section_print_fn=int)
		dist.clear()

	    	countdown -= 1
		if countdown == 0:
			detach(b)
			sys.stdout = old_stdout
			return output.getvalue()
