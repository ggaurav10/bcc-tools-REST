#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# ext4slower  Trace slow ext4 operations.
#             For Linux, uses BCC, eBPF.
#
# USAGE: ext4slower [-h] [-j] [-p PID] [min_ms]
#
# This script traces common ext4 file operations: reads, writes, opens, and
# syncs. It measures the time spent in these operations, and prints details
# for each that exceeded a threshold.
#
# WARNING: This adds low-overhead instrumentation to these ext4 operations,
# including reads and writes from the file system cache. Such reads and writes
# can be very frequent (depending on the workload; eg, 1M/sec), at which
# point the overhead of this tool (even if it prints no "slower" events) can
# begin to become significant.
#
# By default, a minimum millisecond threshold of 10 is used.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 11-Feb-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
from time import strftime
import ctypes as ct
import cStringIO
import time

# symbols
kallsyms = "/proc/kallsyms"
output = cStringIO.StringIO()

csv = 0
debug = 0

# kernel->user event data: struct data_t
DNAME_INLINE_LEN = 32   # linux/dcache.h
TASK_COMM_LEN = 16      # linux/sched.h
class Data(ct.Structure):
    _fields_ = [
        ("ts_us", ct.c_ulonglong),
        ("type", ct.c_ulonglong),
        ("size", ct.c_ulonglong),
        ("offset", ct.c_ulonglong),
        ("delta_us", ct.c_ulonglong),
        ("pid", ct.c_ulonglong),
        ("task", ct.c_char * TASK_COMM_LEN),
        ("file", ct.c_char * DNAME_INLINE_LEN)
    ]

# process event
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents

    type = 'R'
    if event.type == 1:
        type = 'W'
    elif event.type == 2:
        type = 'O'
    elif event.type == 3:
        type = 'S'

    if (csv):
        print("%d,%s,%d,%s,%d,%d,%d,%s" % (
            event.ts_us, event.task, event.pid, type, event.size,
            event.offset, event.delta_us, event.file), file=output)
        return
    print("%-8s %-14.14s %-6s %1s %-7s %-8d %7.2f %s" % (strftime("%H:%M:%S"),
        event.task, event.pid, type, event.size, event.offset / 1024,
        float(event.delta_us) / 1000, event.file), file=output)

def detach(b):
        b.detach_kprobe(event="generic_file_read_iter")
        b.detach_kprobe(event="ext4_file_write_iter")
        b.detach_kprobe(event="ext4_file_open")
        b.detach_kprobe(event="ext4_sync_file")
        b.detach_kretprobe(event="generic_file_read_iter")
        b.detach_kretprobe(event="ext4_file_write_iter")
        b.detach_kretprobe(event="ext4_file_open")
        b.detach_kretprobe(event="ext4_sync_file")

def init_bpf(pid, min_ms):
	# define BPF program
	bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/dcache.h>

// XXX: switch these to char's when supported
#define TRACE_READ      0
#define TRACE_WRITE     1
#define TRACE_OPEN      2
#define TRACE_FSYNC     3

struct val_t {
    u64 ts;
    u64 offset;
    struct file *fp;
};

struct data_t {
    // XXX: switch some to u32's when supported
    u64 ts_us;
    u64 type;
    u64 size;
    u64 offset;
    u64 delta_us;
    u64 pid;
    char task[TASK_COMM_LEN];
    char file[DNAME_INLINE_LEN];
};

BPF_HASH(entryinfo, pid_t, struct val_t);
BPF_PERF_OUTPUT(events);

//
// Store timestamp and size on entry
//

// The current ext4 (Linux 4.5) uses generic_file_read_iter(), instead of it's
// own function, for reads. So we need to trace that and then filter on ext4,
// which I do by checking file->f_op.
int trace_read_entry(struct pt_regs *ctx, struct kiocb *iocb)
{
    u32 pid;
    pid = bpf_get_current_pid_tgid();
    if (FILTER_PID)
        return 0;

    // ext4 filter on file->f_op == ext4_file_operations
    struct file *fp = iocb->ki_filp;
    if ((u64)fp->f_op != EXT4_FILE_OPERATIONS)
        return 0;

    // store filep and timestamp by pid
    struct val_t val = {};
    val.ts = bpf_ktime_get_ns();
    val.fp = fp;
    val.offset = iocb->ki_pos;
    if (val.fp)
        entryinfo.update(&pid, &val);

    return 0;
}

// ext4_file_write_iter():
int trace_write_entry(struct pt_regs *ctx, struct kiocb *iocb)
{
    u32 pid;
    pid = bpf_get_current_pid_tgid();
    if (FILTER_PID)
        return 0;

    // store filep and timestamp by pid
    struct val_t val = {};
    val.ts = bpf_ktime_get_ns();
    val.fp = iocb->ki_filp;
    val.offset = iocb->ki_pos;
    if (val.fp)
        entryinfo.update(&pid, &val);

    return 0;
}

// ext4_file_open():
int trace_open_entry(struct pt_regs *ctx, struct inode *inode,
    struct file *file)
{
    u32 pid;
    pid = bpf_get_current_pid_tgid();
    if (FILTER_PID)
        return 0;

    // store filep and timestamp by pid
    struct val_t val = {};
    val.ts = bpf_ktime_get_ns();
    val.fp = file;
    val.offset = 0;
    if (val.fp)
        entryinfo.update(&pid, &val);

    return 0;
}

// ext4_sync_file():
int trace_fsync_entry(struct pt_regs *ctx, struct file *file)
{
    u32 pid;
    pid = bpf_get_current_pid_tgid();
    if (FILTER_PID)
        return 0;

    // store filep and timestamp by pid
    struct val_t val = {};
    val.ts = bpf_ktime_get_ns();
    val.fp = file;
    val.offset = 0;
    if (val.fp)
        entryinfo.update(&pid, &val);

    return 0;
}

//
// Output
//

static int trace_return(struct pt_regs *ctx, int type)
{
    struct val_t *valp;
    u32 pid = bpf_get_current_pid_tgid();

    valp = entryinfo.lookup(&pid);
    if (valp == 0) {
        // missed tracing issue or filtered
        return 0;
    }

    // calculate delta
    u64 ts = bpf_ktime_get_ns();
    u64 delta_us = (ts - valp->ts) / 1000;
    entryinfo.delete(&pid);
    if (FILTER_US)
        return 0;

    // workaround (rewriter should handle file to d_iname in one step):
    struct dentry *de = NULL;
    bpf_probe_read(&de, sizeof(de), &valp->fp->f_path.dentry);

    // populate output struct
    u32 size = PT_REGS_RC(ctx);
    struct data_t data = {.type = type, .size = size, .delta_us = delta_us,
        .pid = pid};
    data.ts_us = ts / 1000;
    data.offset = valp->offset;
    bpf_probe_read(&data.file, sizeof(data.file), de->d_iname);
    bpf_get_current_comm(&data.task, sizeof(data.task));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

int trace_read_return(struct pt_regs *ctx)
{
    return trace_return(ctx, TRACE_READ);
}

int trace_write_return(struct pt_regs *ctx)
{
    return trace_return(ctx, TRACE_WRITE);
}

int trace_open_return(struct pt_regs *ctx)
{
    return trace_return(ctx, TRACE_OPEN);
}

int trace_fsync_return(struct pt_regs *ctx)
{
    return trace_return(ctx, TRACE_FSYNC);
}

	"""

	# code replacements
	with open(kallsyms) as syms:
            ops = ''
            for line in syms:
                (addr, size, name) = line.rstrip().split(" ", 2)
                name = name.split("\t")[0]
                if name == "ext4_file_operations":
                    ops = "0x" + addr
                    break
            if ops == '':
                print("ERROR: no ext4_file_operations in /proc/kallsyms. Exiting.")
                exit()
            bpf_text = bpf_text.replace('EXT4_FILE_OPERATIONS', ops)
        if min_ms == 0:
            bpf_text = bpf_text.replace('FILTER_US', '0')
        else:
            bpf_text = bpf_text.replace('FILTER_US',
                'delta_us <= %s' % str(min_ms * 1000))
        if pid:
            bpf_text = bpf_text.replace('FILTER_PID', 'pid != %s' % pid)
        else:
            bpf_text = bpf_text.replace('FILTER_PID', '0')
        if debug:
            print(bpf_text)

	# initialize BPF
	b = BPF(text=bpf_text)
	return b

def ext4slowerUtil(duration, p_id, t_hold, j):
	global csv
	global bpf_text

	output.truncate(0)
	output.seek(0)
	csv = j
        min_ms = t_hold
	pid = p_id

	b = init_bpf(pid, min_ms)

	# Common file functions. See earlier comment about generic_file_read_iter().
	b.attach_kprobe(event="generic_file_read_iter", fn_name="trace_read_entry")
	b.attach_kprobe(event="ext4_file_write_iter", fn_name="trace_write_entry")
	b.attach_kprobe(event="ext4_file_open", fn_name="trace_open_entry")
	b.attach_kprobe(event="ext4_sync_file", fn_name="trace_fsync_entry")
	b.attach_kretprobe(event="generic_file_read_iter", fn_name="trace_read_return")
	b.attach_kretprobe(event="ext4_file_write_iter", fn_name="trace_write_return")
	b.attach_kretprobe(event="ext4_file_open", fn_name="trace_open_return")
	b.attach_kretprobe(event="ext4_sync_file", fn_name="trace_fsync_return")

	# header
	if (csv):
            print("ENDTIME_us,TASK,PID,TYPE,BYTES,OFFSET_b,LATENCY_us,FILE", file=output)
        else:
            if min_ms == 0:
                print("Tracing ext4 operations", file=output)
            else:
                print("Tracing ext4 operations slower than %d ms" % min_ms, file=output)
            print("%-8s %-14s %-6s %1s %-7s %-8s %7s %s" % ("TIME", "COMM", "PID", "T",
                "BYTES", "OFF_KB", "LAT(ms)", "FILENAME"), file=output)

        # read events
        b["events"].open_perf_buffer(print_event)

        to = time.time() + duration

        while 1:
            if time.time() > to:
                detach(b)
                return output.getvalue()

            b.kprobe_poll(4000)
