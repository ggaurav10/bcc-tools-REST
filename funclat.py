#!/usr/bin/python
#
# funclat        Display a cummulative histogram of functions' latencies.
#
# USAGE: funclat [-v] [-p PID [PID ...]] [-m THRESHOLD] [-u]
#                [-i INTERVAL] PATH_TO_LIBRARY FUNC1,FUNC2,...
#
# Written as a basic example of getting cummulative latency of functions in a program

from bcc import BPF
import argparse
from time import sleep, strftime
from ctypes import c_int

examples = """
    dbstat /usr/local/pgsql/bin/postgres LockRelationForExtension       # display a histogram of PostgreSQL function latencies
    dbstat /usr/local/pgsql/bin/postgres LockRelationForExtension -v    # display latencies and print the BPF program
    dbstat /usr/local/pgsql/bin/postgres LockRelationForExtension -u    # display latencies in microseconds (default: ms)
    dbstat /usr/local/pgsql/bin/postgres LockRelationForExtension -m 5  # trace only latencies slower than 5ms
    dbstat /usr/local/pgsql/bin/postgres LockRelationForExtension -i 1  # trace latencies and print every 1 second
"""
parser = argparse.ArgumentParser(
    description="",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-v", "--verbose", action="store_true",
    help="print the BPF program")
parser.add_argument("-m", "--threshold", type=int, default=0,
    help="trace queries slower than this threshold (ms)")
parser.add_argument("-u", "--microseconds", action="store_true",
    help="display functions' latencies in microseconds (default: milliseconds)")
parser.add_argument("path",
    help="path to binary")
parser.add_argument("func",
    help="path to binary")
parser.add_argument("-i", "--interval", type=int, default=99999999999,
    help="print summary at this interval (seconds)")
args = parser.parse_args()

program = """
#include <uapi/linux/ptrace.h>

BPF_HASH(temp, u64, u64);
BPF_HISTOGRAM(latency);
int probe_start(struct pt_regs *ctx) {
    u64 timestamp = bpf_ktime_get_ns();
    u64 pid = bpf_get_current_pid_tgid();
    temp.update(&pid, &timestamp);
    return 0;
}
int probe_end(struct pt_regs *ctx) {
    u64 *timestampp;
    u64 pid = bpf_get_current_pid_tgid();
    timestampp = temp.lookup(&pid);
    if (!timestampp)
        return 0;
    u64 delta = bpf_ktime_get_ns() - *timestampp;
    FILTER
    delta /= SCALE;
    latency.increment(bpf_log2l(delta));
    temp.delete(&pid);
    return 0;
}
"""
program = program.replace("SCALE", str(1000 if args.microseconds else 1000000))
program = program.replace("FILTER", "" if args.threshold == 0 else
        "if (delta / 1000000 < %d) { return 0; }" % args.threshold)

bpf = BPF(text=program)

flist = args.func
for function in flist.split(","):
	bpf.attach_uprobe(name=args.path, sym=function, fn_name="probe_start")
	bpf.attach_uretprobe(name=args.path, sym=function, fn_name="probe_end")

print("Tracing latencies slower than %d ms..." % args.threshold)

latencies = bpf["latency"]

def print_hist():
    print("[%s]" % strftime("%H:%M:%S"))
    latencies.print_log2_hist("functions' latency (%s)" %
                              ("us" if args.microseconds else "ms"))
    print("")
    latencies.clear()

while True:
    try:
        sleep(args.interval)
        print_hist()
    except KeyboardInterrupt:
        print_hist()
        break

