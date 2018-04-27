#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# vfsstat   Count some VFS calls.
#           For Linux, uses BCC, eBPF. See .c file.
#
# Written as a basic example of counting multiple events as a stat tool.
#
# USAGE: vfsstat [interval [count]]
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 14-Aug-2015   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
from ctypes import c_int
from time import sleep, strftime
import cStringIO

def detach(b):
   b.detach_kprobe(event="vfs_read")
   b.detach_kprobe(event="vfs_write")
   b.detach_kprobe(event="vfs_fsync")
   b.detach_kprobe(event="vfs_open")
   b.detach_kprobe(event="vfs_create")

def vfsstatUtil(interval, count):
   # load BPF program
   b = BPF(text="""
   #include <uapi/linux/ptrace.h>

   enum stat_types {
       S_READ = 1,
       S_WRITE,
       S_FSYNC,
       S_OPEN,
       S_CREATE,
       S_MAXSTAT
   };

   BPF_TABLE("array", int, u64, stats, S_MAXSTAT + 1);

   static void stats_increment(int key) {
       u64 *leaf = stats.lookup(&key);
       if (leaf) (*leaf)++;
   }

   void do_read(struct pt_regs *ctx) { stats_increment(S_READ); }
   void do_write(struct pt_regs *ctx) { stats_increment(S_WRITE); }
   void do_fsync(struct pt_regs *ctx) { stats_increment(S_FSYNC); }
   void do_open(struct pt_regs *ctx) { stats_increment(S_OPEN); }
   void do_create(struct pt_regs *ctx) { stats_increment(S_CREATE); }
   """)
   b.attach_kprobe(event="vfs_read", fn_name="do_read")
   b.attach_kprobe(event="vfs_write", fn_name="do_write")
   b.attach_kprobe(event="vfs_fsync", fn_name="do_fsync")
   b.attach_kprobe(event="vfs_open", fn_name="do_open")
   b.attach_kprobe(event="vfs_create", fn_name="do_create")

   # stat column labels and indexes
   stat_types = {
       "READ": 1,
       "WRITE": 2,
       "FSYNC": 3,
       "OPEN": 4,
       "CREATE": 5
   }

   output = cStringIO.StringIO()
   #output = open('/tmp/fileout', 'w+')

   # header
   print("%-8s  " % "TIME", file=output, end="")
   for stype in stat_types.keys():
       print(" %8s" % (stype + "/s"), file=output, end="")
       idx = stat_types[stype]
   print("", file=output)

   # output
   i = 0
   while (1):
       if count > 0:
           i += 1
           if i > count:
               detach(b)
	       return output.getvalue()
	       #output.close()
	       #return output

       sleep(interval)

       print("%-8s: " % strftime("%H:%M:%S"), file=output, end="")
       # print each statistic as a column
       for stype in stat_types.keys():
           idx = stat_types[stype]
           try:
               val = b["stats"][c_int(idx)].value / interval
               print(" %8d" % val, file=output, end="")
           except:
               print(" %8d" % 0, file=output, end="")
       b["stats"].clear()
       print("", file=output)
