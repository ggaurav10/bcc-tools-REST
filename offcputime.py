#!/usr/bin/python
#
# offcputime    Summarize off-CPU time by kernel stack trace
#               For Linux, uses BCC, eBPF.
#
# USAGE: offcputime [-h] [-u] [-p PID] [-v] [-f] [duration]
#
# The current implementation uses an unrolled loop for x86_64, and was written
# as a proof of concept. This implementation should be replaced in the future
# with an appropriate bpf_ call, when available.
#
# Currently limited to a stack trace depth of 21 (maxdepth + 1).
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 13-Jan-2016	Brendan Gregg	Created this.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
from cStringIO import StringIO
import signal

# arguments
examples = """examples:
    ./offcputime             # trace off-CPU stack time until Ctrl-C
    ./offcputime 5           # trace for 5 seconds only
    ./offcputime -f 5        # 5 seconds, and output in folded format
    ./offcputime -u          # don't include kernel threads (user only)
    ./offcputime -p 185      # trace fo PID 185 only
"""
debug = 0
maxdepth = 20    # and MAXDEPTH

def bpf_init(pid, useronly):
  # define BPF program
  bpf_text = """
  #include <uapi/linux/ptrace.h>
  #include <linux/sched.h>
  #define MAXDEPTH	20
  #define MINBLOCK_US	1
  struct key_t {
    char name[TASK_COMM_LEN];
    // Skip saving the ip
    u64 ret[MAXDEPTH];
  };
  BPF_HASH(counts, struct key_t);
  BPF_HASH(start, u32);
  static u64 get_frame(u64 *bp) {
    if (*bp) {
        // The following stack walker is x86_64 specific
        u64 ret = 0;
        if (bpf_probe_read(&ret, sizeof(ret), (void *)(*bp+8)))
            return 0;
        if (bpf_probe_read(bp, sizeof(*bp), (void *)*bp))
            *bp = 0;
        if (ret < __START_KERNEL_map)
            return 0;
        return ret;
    }
    return 0;
  }
  int oncpu(struct pt_regs *ctx, struct task_struct *prev) {
    u32 pid = prev->pid;
    u64 ts, *tsp;
    // record previous thread sleep time
    if (FILTER) {
        ts = bpf_ktime_get_ns();
        start.update(&pid, &ts);
    }
    // calculate current thread's delta time
    pid = bpf_get_current_pid_tgid();
    tsp = start.lookup(&pid);
    if (tsp == 0)
        return 0;        // missed start or filtered
    u64 delta = bpf_ktime_get_ns() - *tsp;
    start.delete(&pid);
    delta = delta / 1000;
    if (delta < MINBLOCK_US)
        return 0;
    // create map key
    u64 zero = 0, *val, bp = 0;
    int depth = 0;
    struct key_t key = {};
    bpf_get_current_comm(&key.name, sizeof(key.name));
    bp = ctx->bp;
    // unrolled loop (MAXDEPTH):
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
    if (!(key.ret[depth++] = get_frame(&bp))) goto out;
  out:
    val = counts.lookup_or_init(&key, &zero);
    (*val) += delta;
    return 0;
  }
  """
  if pid:
    filter = 'pid == %s' % pid
  elif useronly:
    filter = '!(prev->flags & PF_KTHREAD)'
  else:
    filter = '1'
  bpf_text = bpf_text.replace('FILTER', filter)
  if debug:
    print(bpf_text)

  # initialize BPF
  b = BPF(text=bpf_text)
  b.attach_kprobe(event="finish_task_switch", fn_name="oncpu")
  return b


def offcputimeUtil(pid, useronly, folded, duration):
  output = StringIO()

  if pid and useronly:
    print("ERROR: use either -p or -u.", file=output)
    return output.getvalue()

  b = bpf_init(pid, useronly)

  matched = b.num_open_kprobes()
  if matched == 0:
    print("0 functions traced. Exiting.", file=output)
    return output.getvalue()

  # header
  if not folded:
    print("off-CPU time (us) by kernel stack for %d secs." % duration, file=output)

  # output
  while (1):
    sleep(duration)

    if not folded:
        print("", file=output)
    counts = b.get_table("counts")
    for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
        if folded:
            # print folded stack output
            line = k.name.decode() + ";"
            for i in reversed(range(0, maxdepth)):
                if k.ret[i] == 0:
                    continue
                line = line + b.ksym(k.ret[i])
                if i != 0:
                    line = line + ";"
            print("%s %d" % (line, v.value), file=output)
        else:
            # print default multi-line stack output
            for i in range(0, maxdepth):
                if k.ret[i] == 0:
                    break
                print("    %-16x %s" % (k.ret[i],
                    b.ksym(k.ret[i])), file=output)
            print("    %-16s %s" % ("-", k.name), file=output)
            print("        %d\n" % v.value, file=output)
    counts.clear()

    if not folded:
        print("Detaching...", file=output)
    b.detach_kprobe(event="finish_task_switch")
    return output.getvalue()
