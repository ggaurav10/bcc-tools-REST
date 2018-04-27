#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# dcstat   Directory entry cache (dcache) stats.
#          For Linux, uses BCC, eBPF.
#
# USAGE: dcstat [interval [count]]
#
# This uses kernel dynamic tracing of kernel functions, lookup_fast() and
# d_lookup(), which will need to be modified to match kernel changes. See
# code comments.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 09-Feb-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
from ctypes import c_int
from time import sleep, strftime
from sys import argv
import cStringIO

def detach(b):
    b.detach_kprobe(event="lookup_fast")
    b.detach_kretprobe(event="d_lookup")

def dcstatUtil(interval, count):
    # define BPF program
    bpf_text = """
    #include <uapi/linux/ptrace.h>

    enum stats {
        S_REFS = 1,
        S_SLOW,
        S_MISS,
        S_MAXSTAT
    };

    BPF_TABLE("array", int, u64, stats, S_MAXSTAT + 1);

/*
 * How this is instrumented, and how to interpret the statistics, is very much
 * tied to the current kernel implementation (this was written on Linux 4.4).
 * This will need maintenance to keep working as the implementation changes. To
 * aid future adventurers, this is is what the current code does, and why.
 *
 * First problem: the current implementation takes a path and then does a
 * lookup of each component. So how do we count a reference? Once for the path
 * lookup, or once for every component lookup? I've chosen the latter
 * since it seems to map more closely to actual dcache lookups (via
 * __d_lookup_rcu()). It's counted via calls to lookup_fast().
 *
 * The implementation tries different, progressively slower, approaches to
 * lookup a file. At what point do we call it a dcache miss? I've choosen when
 * a d_lookup() (which is called during lookup_slow()) returns zero.
 *
 * I've also included a "SLOW" statistic to show how often the fast lookup
 * failed. Whether this exists or is interesting is an implementation detail,
 * and the "SLOW" statistic may be removed in future versions.
 */
    void count_fast(struct pt_regs *ctx) {
        int key = S_REFS;
        u64 *leaf = stats.lookup(&key);
        if (leaf) (*leaf)++;
    }

    void count_lookup(struct pt_regs *ctx) {
        int key = S_SLOW;
        u64 *leaf = stats.lookup(&key);
        if (leaf) (*leaf)++;
        if (PT_REGS_RC(ctx) == 0) {
            key = S_MISS;
            leaf = stats.lookup(&key);
            if (leaf) (*leaf)++;
        }
    }
    """

    # load BPF program
    b = BPF(text=bpf_text)
    b.attach_kprobe(event="lookup_fast", fn_name="count_fast")
    b.attach_kretprobe(event="d_lookup", fn_name="count_lookup")

    # stat column labels and indexes
    stats = {
        "REFS": 1,
        "SLOW": 2,
        "MISS": 3
    }

    output = cStringIO.StringIO()

    # header
    print("%-8s  " % "TIME", file=output, end="")
    for stype, idx in sorted(stats.items(), key=lambda k_v: (k_v[1], k_v[0])):
        print(" %8s" % (stype + "/s"), file=output, end="")
    print(" %8s" % "HIT%", file=output)

    # output
    i = 0
    while (1):
        if count > 0:
            i += 1
            if i > count:
                detach(b)
    	        return output.getvalue()

        sleep(interval)

        print("%-8s: " % strftime("%H:%M:%S"), file=output, end="")

        # print each statistic as a column
        for stype, idx in sorted(stats.items(), key=lambda k_v: (k_v[1], k_v[0])):
            try:
                val = b["stats"][c_int(idx)].value / interval
                print(" %8d" % val, file=output, end="")
            except:
                print(" %8d" % 0, file=output, end="")

        # print hit ratio percentage
        try:
            ref = b["stats"][c_int(stats["REFS"])].value
            miss = b["stats"][c_int(stats["MISS"])].value
            hit = ref - miss
            pct = float(100) * hit / ref
            print(" %8.2f" % pct, file=output)
        except:
            print(" %7s%%" % "-", file=output)

        b["stats"].clear()
