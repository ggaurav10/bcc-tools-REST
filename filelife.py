#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# filelife    Trace the lifespan of short-lived files.
#             For Linux, uses BCC, eBPF. Embedded C.
#
# This traces the creation and deletion of files, providing information
# on who deleted the file, the file age, and the file name. The intent is to
# provide information on short-lived files, for debugging or performance
# analysis.
#
# USAGE: filelife [-h] [-p PID]
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 08-Feb-2015   Brendan Gregg   Created this.
# 17-Feb-2016   Allan McAleavy updated for BPF_PERF_OUTPUT

from __future__ import print_function
from bcc import BPF
import time
import ctypes as ct
from cStringIO import StringIO

debug = 0

def bpf_init():
	# define BPF program
	bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u64 delta;
    char comm[TASK_COMM_LEN];
    char fname[DNAME_INLINE_LEN];
};

BPF_HASH(birth, struct dentry *);
BPF_PERF_OUTPUT(events);

// trace file creation time
int trace_create(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry)
{
    u32 pid = bpf_get_current_pid_tgid();
    FILTER

    u64 ts = bpf_ktime_get_ns();
    birth.update(&dentry, &ts);

    return 0;
};

// trace file deletion and output details
int trace_unlink(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry)
{
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid();

    FILTER

    u64 *tsp, delta;
    tsp = birth.lookup(&dentry);
    if (tsp == 0) {
        return 0;   // missed create
    }

    delta = (bpf_ktime_get_ns() - *tsp) / 1000000;
    birth.delete(&dentry);

    if (dentry->d_iname[0] == 0)
        return 0;

    if (bpf_get_current_comm(&data.comm, sizeof(data.comm)) == 0) {
        data.pid = pid;
        data.delta = delta;
        bpf_probe_read(&data.fname, sizeof(data.fname), dentry->d_iname);
    }

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
	"""
        return bpf_text

TASK_COMM_LEN = 16            # linux/sched.h
DNAME_INLINE_LEN = 255        # linux/dcache.h

class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_ulonglong),
        ("delta", ct.c_ulonglong),
        ("comm", ct.c_char * TASK_COMM_LEN),
        ("fname", ct.c_char * DNAME_INLINE_LEN)
    ]


def filelifeUtil(duration, pid):
	bpf_text = bpf_init()
	if pid:
            bpf_text = bpf_text.replace('FILTER',
                'if (pid != %s) { return 0; }' % pid)
        else:
            bpf_text = bpf_text.replace('FILTER', '')
        if debug:
            print(bpf_text)

        # initialize BPF
        b = BPF(text=bpf_text)
        b.attach_kprobe(event="vfs_create", fn_name="trace_create")
        b.attach_kprobe(event="vfs_unlink", fn_name="trace_unlink")

	output = StringIO()

        # header
        print("%-8s %-6s %-16s %-7s %s" % ("TIME", "PID", "COMM", "AGE(s)", "FILE"), file=output)

        # process event
        def print_event(cpu, data, size):
            event = ct.cast(data, ct.POINTER(Data)).contents
            print("%-8s %-6d %-16s %-7.2f %s" % (time.strftime("%H:%M:%S"), event.pid,
                event.comm, float(event.delta) / 1000, event.fname), file=output)

        b["events"].open_perf_buffer(print_event)

        to = time.time() + duration

        while 1:
	    if time.time() > to:
                b.detach_kprobe(event="vfs_create")
                b.detach_kprobe(event="vfs_unlink")
	        return output.getvalue()

            b.kprobe_poll(2000)
