#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# tcpaccept Trace TCP accept()s.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpaccept [-h] [-t] [-p PID]
#
# This uses dynamic tracing of the kernel inet_csk_accept() socket function
# (from tcp_prot.accept), and will need to be modified to match kernel changes.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 13-Oct-2015   Brendan Gregg   Created this.
# 14-Feb-2016      "      "     Switch to bpf_perf_output.

from __future__ import print_function
from bcc import BPF
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
import ctypes as ct
from time import time
from cStringIO import StringIO

output = StringIO()
debug = 0

def init_bpf(pid=None):
	# define BPF program
	bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    // XXX: switch some to u32's when supported
    u64 ts_us;
    u64 pid;
    u64 saddr;
    u64 daddr;
    u64 ip;
    u64 lport;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u64 ts_us;
    u64 pid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 ip;
    u64 lport;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv6_events);

int kretprobe__inet_csk_accept(struct pt_regs *ctx)
{
    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid();

    if (newsk == NULL)
        return 0;

    // check this is TCP
    u8 protocol = 0;
    // workaround for reading the sk_protocol bitfield:
    bpf_probe_read(&protocol, 1, (void *)((long)&newsk->sk_wmem_queued) - 3);
    if (protocol != IPPROTO_TCP)
        return 0;

    // pull in details
    u16 family = 0, lport = 0;
    bpf_probe_read(&family, sizeof(family), &newsk->__sk_common.skc_family);
    bpf_probe_read(&lport, sizeof(lport), &newsk->__sk_common.skc_num);

    if (family == AF_INET) {
        struct ipv4_data_t data4 = {.pid = pid, .ip = 4};
        data4.ts_us = bpf_ktime_get_ns() / 1000;
        bpf_probe_read(&data4.saddr, sizeof(u32),
            &newsk->__sk_common.skc_rcv_saddr);
        bpf_probe_read(&data4.daddr, sizeof(u32),
            &newsk->__sk_common.skc_daddr);
        data4.lport = lport;
        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));

    } else if (family == AF_INET6) {
        struct ipv6_data_t data6 = {.pid = pid, .ip = 6};
        data6.ts_us = bpf_ktime_get_ns() / 1000;
        bpf_probe_read(&data6.saddr, sizeof(data6.saddr),
            &newsk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read(&data6.daddr, sizeof(data6.daddr),
            &newsk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        data6.lport = lport;
        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }
    // else drop

    return 0;
}
	"""

	# code substitutions
	if pid:
		bpf_text = bpf_text.replace('FILTER',
		'if (pid != %s) { return 0; }' % pid)
	else:
		bpf_text = bpf_text.replace('FILTER', '')
	if debug:
		print(bpf_text)

	return bpf_text

# event data
TASK_COMM_LEN = 16      # linux/sched.h

class Data_ipv4(ct.Structure):
    _fields_ = [
        ("ts_us", ct.c_ulonglong),
        ("pid", ct.c_ulonglong),
        ("saddr", ct.c_ulonglong),
        ("daddr", ct.c_ulonglong),
        ("ip", ct.c_ulonglong),
        ("lport", ct.c_ulonglong),
        ("task", ct.c_char * TASK_COMM_LEN)
    ]

class Data_ipv6(ct.Structure):
    _fields_ = [
        ("ts_us", ct.c_ulonglong),
        ("pid", ct.c_ulonglong),
        ("saddr", (ct.c_ulonglong * 2)),
        ("daddr", (ct.c_ulonglong * 2)),
        ("ip", ct.c_ulonglong),
        ("lport", ct.c_ulonglong),
        ("task", ct.c_char * TASK_COMM_LEN)
    ]

start_ts = 0

# process event
def print_ipv4_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data_ipv4)).contents
    global start_ts
    if start_ts == 0:
        start_ts = event.ts_us
    print("%-9.3f" % ((float(event.ts_us) - start_ts) / 1000000), file=output, end="")
    print("%-6d %-12.12s %-2d %-16s %-16s %-4d" % (event.pid, event.task,
        event.ip, inet_ntop(AF_INET, pack("I", event.daddr)),
        inet_ntop(AF_INET, pack("I", event.saddr)), event.lport), file=output)

def print_ipv6_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data_ipv6)).contents
    global start_ts
    if start_ts == 0:
        start_ts = event.ts_us
    print("%-9.3f" % ((float(event.ts_us) - start_ts) / 1000000), file=output, end="")
    print("%-6d %-12.12s %-2d %-16s %-16s %-4d" % (event.pid, event.task,
        event.ip, inet_ntop(AF_INET6, event.daddr),
        inet_ntop(AF_INET6, event.saddr), event.lport), file=output)

def tcpacceptUtil(duration, pid=None):
	output.truncate(0)
	output.seek(0)

	bpf_text = init_bpf(pid)
	# initialize BPF
	b = BPF(text=bpf_text)

	# header
	print("%-9s" % ("TIME(s)"), file=output, end="")
	print("%-6s %-12s %-2s %-16s %-16s %-4s" % ("PID", "COMM", "IP", "RADDR",
             "LADDR", "LPORT"), file=output)

	# read events
	b["ipv4_events"].open_perf_buffer(print_ipv4_event)
	b["ipv6_events"].open_perf_buffer(print_ipv6_event)

	to = time() + duration

	while time() < to:
		b.kprobe_poll(2000)

	b.detach_kretprobe(event="inet_csk_accept")
	return output.getvalue()
