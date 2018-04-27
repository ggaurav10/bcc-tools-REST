#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# mdflush  Trace md flush events.
#          For Linux, uses BCC, eBPF.
#
# Todo: add more details of the flush (latency, I/O count).
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 13-Feb-2015   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
import ctypes as ct

from cStringIO import StringIO
import time

def init_bpf():
  # load BPF program
  b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/genhd.h>

struct data_t {
    u64 pid;
    char comm[TASK_COMM_LEN];
    char disk[DISK_NAME_LEN];
};
BPF_PERF_OUTPUT(events);

int trace_flush_request(struct pt_regs *ctx, void *mddev, struct bio *bio)
{
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid();
    data.pid = pid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read(&data.disk, sizeof(data.disk),
        bio->bi_bdev->bd_disk->disk_name);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
  """)
  return b

# event data
TASK_COMM_LEN = 16  # linux/sched.h
DISK_NAME_LEN = 32  # linux/genhd.h
class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_ulonglong),
        ("comm", ct.c_char * TASK_COMM_LEN),
        ("disk", ct.c_char * DISK_NAME_LEN)
    ]

def mdflushUtil(duration):
	b = init_bpf()
	# header
        b.attach_kprobe(event="md_flush_request", fn_name="trace_flush_request")

	output = StringIO()

	print("Tracing md flush requests... Hit Ctrl-C to end.", file=output)
	print("%-8s %-6s %-16s %s" % ("TIME", "PID", "COMM", "DEVICE"), file=output)

	# process event
	def print_event(cpu, data, size):
		event = ct.cast(data, ct.POINTER(Data)).contents
		print("%-8s %-6d %-16s %s" % (strftime("%H:%M:%S"), event.pid, event.comm,
			event.disk), file=output)

	# read events
	b["events"].open_perf_buffer(print_event)

	to = time.time() + duration

	while 1:
            if time.time() > to:
                b.detach_kprobe(event="md_flush_request")
                return output.getvalue()

            b.kprobe_poll(2000)
