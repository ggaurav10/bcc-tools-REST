#!/usr/bin/python
#
# offcputime    Summarize off-CPU time by stack trace
#               For Linux, uses BCC, eBPF.
#
# USAGE: offcputime [-h] [-p PID | -u | -k] [-U | -K] [-f] [duration]
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 13-Jan-2016	Brendan Gregg	Created this.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import errno
from cStringIO import StringIO

debug = 0

def init_bpf():
  # define BPF program
  bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MINBLOCK_US    MINBLOCK_US_VALUEULL
#define MAXBLOCK_US    MAXBLOCK_US_VALUEULL

struct key_t {
    u32 pid;
    u32 tgid;
    int user_stack_id;
    int kernel_stack_id;
    char name[TASK_COMM_LEN];
};
BPF_HASH(counts, struct key_t);
BPF_HASH(start, u32);
BPF_STACK_TRACE(stack_traces, STACK_STORAGE_SIZE)

int oncpu(struct pt_regs *ctx, struct task_struct *prev) {
    u32 pid = prev->pid;
    u32 tgid = prev->tgid;
    u64 ts, *tsp;

    // record previous thread sleep time
    if ((THREAD_FILTER) && (STATE_FILTER)) {
        ts = bpf_ktime_get_ns();
        start.update(&pid, &ts);
    }

    // get the current thread's start time
    pid = bpf_get_current_pid_tgid();
    tgid = bpf_get_current_pid_tgid() >> 32;
    tsp = start.lookup(&pid);
    if (tsp == 0) {
        return 0;        // missed start or filtered
    }

    // calculate current thread's delta time
    u64 delta = bpf_ktime_get_ns() - *tsp;
    start.delete(&pid);
    delta = delta / 1000;
    if ((delta < MINBLOCK_US) || (delta > MAXBLOCK_US)) {
        return 0;
    }

    // create map key
    u64 zero = 0, *val;
    struct key_t key = {};

    key.pid = pid;
    key.tgid = tgid;
    key.user_stack_id = USER_STACK_GET;
    key.kernel_stack_id = KERNEL_STACK_GET;
    bpf_get_current_comm(&key.name, sizeof(key.name));

    val = counts.lookup_or_init(&key, &zero);
    (*val) += delta;
    return 0;
}
  """

  return bpf_text

def offcputimenewUtil(folded, duration, in_user_threads_only, in_kernel_threads_only, in_user_stacks_only, in_kernel_stacks_only, in_tgid, in_pid, in_state, in_stack_storage_size, in_min_block_time, in_max_block_time):
  output = StringIO()

  bpf_text = init_bpf()

  # set thread filter
  thread_context = ""
  if in_tgid is not None:
    thread_context = "PID %d" % in_tgid
    thread_filter = 'tgid == %d' % in_tgid
  elif in_pid is not None:
    thread_context = "TID %d" % in_pid
    thread_filter = 'pid == %d' % in_pid
  elif in_user_threads_only:
    thread_context = "user threads"
    thread_filter = '!(prev->flags & PF_KTHREAD)'
  elif in_kernel_threads_only:
    thread_context = "kernel threads"
    thread_filter = 'prev->flags & PF_KTHREAD'
  else:
    thread_context = "all threads"
    thread_filter = '1'
  if in_state == 0:
    state_filter = 'prev->state == 0'
  elif in_state:
    # these states are sometimes bitmask checked
    state_filter = 'prev->state & %d' % in_state
  else:
    state_filter = '1'
  bpf_text = bpf_text.replace('THREAD_FILTER', thread_filter)
  bpf_text = bpf_text.replace('STATE_FILTER', state_filter)

  # set stack storage size
  bpf_text = bpf_text.replace('STACK_STORAGE_SIZE', str(in_stack_storage_size))
  bpf_text = bpf_text.replace('MINBLOCK_US_VALUE', str(in_min_block_time))
  bpf_text = bpf_text.replace('MAXBLOCK_US_VALUE', str(in_max_block_time))

  # handle stack args
  kernel_stack_get = "stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID)"
  user_stack_get = \
    "stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID | BPF_F_USER_STACK)"
  stack_context = ""
  if in_user_stacks_only:
    stack_context = "user"
    kernel_stack_get = "-1"
  elif in_kernel_stacks_only:
    stack_context = "kernel"
    user_stack_get = "-1"
  else:
    stack_context = "user + kernel"
  bpf_text = bpf_text.replace('USER_STACK_GET', user_stack_get)
  bpf_text = bpf_text.replace('KERNEL_STACK_GET', kernel_stack_get)

# check for an edge case; the code below will handle this case correctly
# but ultimately nothing will be displayed
  if in_kernel_threads_only and in_user_stacks_only:
    print("ERROR: Displaying user stacks for kernel threads " +
          "doesn't make sense.", file=output)
    exit(1)

  if (debug):
    print(bpf_text)

# initialize BPF
  b = BPF(text=bpf_text)
  b.attach_kprobe(event="finish_task_switch", fn_name="oncpu")

  # header
  if not folded:
    print("Tracing off-CPU time (us) of %s by %s stack" %
        (thread_context, stack_context), end="", file=output)
    print(" for %d secs." % duration, file=output)

  sleep(duration)

  if not folded:
    print(file=output)

  need_delimiter = not (in_kernel_stacks_only or
                                         in_user_stacks_only)

  missing_stacks = 0
  has_enomem = False
  counts = b.get_table("counts")
  stack_traces = b.get_table("stack_traces")
  for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
    # handle get_stackid erorrs
    if (not in_user_stacks_only and k.kernel_stack_id < 0) or \
            (not in_kernel_stacks_only and k.user_stack_id < 0 and
                 k.user_stack_id != -errno.EFAULT):
        missing_stacks += 1
        # check for an ENOMEM error
        if k.kernel_stack_id == -errno.ENOMEM or \
           k.user_stack_id == -errno.ENOMEM:
            has_enomem = True
        continue

    # user stacks will be symbolized by tgid, not pid, to avoid the overhead
    # of one symbol resolver per thread
    user_stack = [] if k.user_stack_id < 0 else \
        stack_traces.walk(k.user_stack_id)
    kernel_stack = [] if k.kernel_stack_id < 0 else \
        stack_traces.walk(k.kernel_stack_id)

    if folded:
        # print folded stack output
        user_stack = list(user_stack)
        kernel_stack = list(kernel_stack)
        line = [k.name.decode()] + \
            [b.sym(addr, k.tgid) for addr in reversed(user_stack)] + \
            (need_delimiter and ["-"] or []) + \
            [b.ksym(addr) for addr in reversed(kernel_stack)]
        print("%s %d" % (";".join(line), v.value), file=output)
    else:
        # print default multi-line stack output
        for addr in kernel_stack:
            print("    %s" % b.ksym(addr), file=output)
        if need_delimiter:
            print("    --", file=output)
        for addr in user_stack:
            print("    %s" % b.sym(addr, k.tgid), file=output)
        print("    %-16s %s (%d)" % ("-", k.name.decode(), k.pid), file=output)
        print("        %d\n" % v.value, file=output)

  if missing_stacks > 0:
    enomem_str = "" if not has_enomem else \
        " Consider increasing --stack-storage-size."
    print("WARNING: %d stack traces could not be displayed.%s" %
        (missing_stacks, enomem_str),
        file=output)

  b.detach_kprobe(event="finish_task_switch")
  return output.getvalue()
