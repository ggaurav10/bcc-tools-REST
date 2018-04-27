#!/usr/bin/python
#
# cachestat     Count cache kernel function calls.
#               For Linux, uses BCC, eBPF. See .c file.
#
# USAGE: cachestat
# Taken from funccount by Brendan Gregg
# This is a rewrite of cachestat from perf to bcc
# https://github.com/brendangregg/perf-tools/blob/master/fs/cachestat
#
# Copyright (c) 2016 Allan McAleavy.
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 09-Sep-2015   Brendan Gregg   Created this.
# 06-Nov-2015   Allan McAleavy
# 13-Jan-2016   Allan McAleavy  run pep8 against program

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
from cStringIO import StringIO
import signal
import re

debug = 0

# Function to gather data from /proc/meminfo
# return dictionary for quicker lookup of both values
def get_meminfo():
    result = dict()

    for line in open('/proc/meminfo'):
        k = line.split(':', 3)
        v = k[1].split()
        result[k[0]] = int(v[0])
    return result

def init_bpf():
	# load BPF program
	bpf_text = """
#include <uapi/linux/ptrace.h>
struct key_t {
    u64 ip;
};

BPF_HASH(counts, struct key_t);

int do_count(struct pt_regs *ctx) {
    struct key_t key = {};
    u64 zero = 0, *val;
    u64 ip;

    key.ip = PT_REGS_IP(ctx);
    val = counts.lookup_or_init(&key, &zero);  // update counter
    (*val)++;
    return 0;
}

	"""
	b = BPF(text=bpf_text)
	b.attach_kprobe(event="add_to_page_cache_lru", fn_name="do_count")
	b.attach_kprobe(event="mark_page_accessed", fn_name="do_count")
	b.attach_kprobe(event="account_page_dirtied", fn_name="do_count")
	b.attach_kprobe(event="mark_buffer_dirty", fn_name="do_count")

	return b

def detach(b):
	b.detach_kprobe(event="add_to_page_cache_lru")
	b.detach_kprobe(event="mark_page_accessed")
	b.detach_kprobe(event="account_page_dirtied")
	b.detach_kprobe(event="mark_buffer_dirty")

def cachestatUtil(interval, count):
  interval = abs(int(interval))
  count = abs(int(count))

  rtaccess = 0
  wtaccess = 0
  mpa = 0
  mbd = 0
  apcl = 0
  apd = 0
  access = 0
  misses = 0
  rhits = 0
  whits = 0

  output= StringIO()
  b = init_bpf()

  # header
  print("%-8s " % "TIME", file=output, end="")
  print("%8s %8s %8s %10s %10s %12s %10s" %
     ("HITS", "MISSES", "DIRTIES",
     "READ_HIT%", "WRITE_HIT%", "BUFFERS_MB", "CACHED_MB"), file=output)

  loop = 0
  exiting = 0
  while 1:
    if count > 0:
        loop += 1
        if loop > count:
	    detach(b)
            return output.getvalue()

    sleep(interval)

    counts = b.get_table("counts")
    for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):

        if re.match('mark_page_accessed', b.ksym(k.ip)) is not None:
            mpa = max(0, v.value)

        if re.match('mark_buffer_dirty', b.ksym(k.ip)) is not None:
            mbd = max(0, v.value)

        if re.match('add_to_page_cache_lru', b.ksym(k.ip)) is not None:
            apcl = max(0, v.value)

        if re.match('account_page_dirtied', b.ksym(k.ip)) is not None:
            apd = max(0, v.value)

        # access = total cache access incl. reads(mpa) and writes(mbd)
        # misses = total of add to lru which we do when we write(mbd)
        # and also the mark the page dirty(same as mbd)
        access = (mpa + mbd)
        misses = (apcl + apd)

        # rtaccess is the read hit % during the sample period.
        # wtaccess is the write hit % during the smaple period.
        if mpa > 0:
            rtaccess = float(mpa) / (access + misses)
        if apcl > 0:
            wtaccess = float(apcl) / (access + misses)

        if wtaccess != 0:
            whits = 100 * wtaccess
        if rtaccess != 0:
            rhits = 100 * rtaccess

    if debug:
        print("%d %d %d %d %d %d %f %f %d %d\n" %
        (mpa, mbd, apcl, apd, access, misses,
        rtaccess, wtaccess, rhits, whits), file=output)

    counts.clear()

    # Get memory info
    mem = get_meminfo()
    cached = int(mem["Cached"]) / 1024
    buff = int(mem["Buffers"]) / 1024

    print("%-8s " % strftime("%H:%M:%S"), file=output, end="")
    print("%8d %8d %8d %9.1f%% %9.1f%% %12.0f %10.0f" %
    (access, misses, mbd, rhits, whits, buff, cached), file=output)

    mpa = 0
    mbd = 0
    apcl = 0
    apd = 0
    access = 0
    misses = 0
    rhits = 0
    cached = 0
    buff = 0
    whits = 0
    rtaccess = 0
    wtaccess = 0
