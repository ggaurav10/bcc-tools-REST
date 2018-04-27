#!/usr/bin/python
#
# stats        Display histograms of functions' latencies.
#
# USAGE: stats [-v] [-m THRESHOLD] [-u]
#              [-i INTERVAL] PATH_TO_LIBRARY FUNCTION1,FUNCTION2,...
#
# Written as a basic example of getting latency of functions in a program

from bcc import BPF
import argparse
from time import sleep, strftime
from ctypes import c_int

examples = """
    ./stats.py /usr/local/pgsql/bin/postgres LockRelationForExtension       # display a histogram of PostgreSQL function latencies
    ./stats.py kernel tcp_v4_connect,inet_csk_accept -i 1                   # trace latencies of kernel functions and print every 1 second
    ./stats.py /usr/local/pgsql/bin/postgres LockRelationForExtension -v    # display latencies and print the BPF program
    ./stats.py /usr/local/pgsql/bin/postgres LockRelationForExtension -u    # display latencies in microseconds (default: ms)
    ./stats.py /usr/local/pgsql/bin/postgres LockRelationForExtension -m 5  # trace only latencies slower than 5ms
    ./stats.py /usr/local/pgsql/bin/postgres LockRelationForExtension -i 1  # trace latencies and print every 1 second
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
    help="display query latencies in microseconds (default: milliseconds)")
parser.add_argument("path",
    help="path to binary")
parser.add_argument("func",
    help="function name")
parser.add_argument("-i", "--interval", type=int, default=99999999999,
    help="print summary at this interval (seconds)")
args = parser.parse_args()

prog_head = """
#include <uapi/linux/ptrace.h>
#include <linux/string.h>

typedef struct func_key {
	char func[100];
	u64 slot;
} func_key_t;

BPF_HASH(temp, func_key_t, u64);
BPF_HISTOGRAM(latency, func_key_t);
"""
prog_body = """
int PROBE_ENTRY(struct pt_regs *ctx) {
    u64 timestamp = bpf_ktime_get_ns();
    GET_HKEY
    temp.update(&hkey, &timestamp);
    return 0;
}
int PROBE_EXIT(struct pt_regs *ctx) {
    u64 *timestampp;
    GET_HKEY
    timestampp = temp.lookup(&hkey);
    if (!timestampp){
        return 0;}
    u64 delta = bpf_ktime_get_ns() - *timestampp;
    FILTER
    delta /= SCALE;
    STORE
    temp.delete(&hkey);
    return 0;
}
"""
prog_body = prog_body.replace("SCALE", str(1000 if args.microseconds else 1000000))
prog_body = prog_body.replace("FILTER", "" if args.threshold == 0 else
        "if (delta / 1000000 < %d) { return 0; }" % args.threshold)

final_prog = prog_head

flist = args.func
for function in flist.split(","):
	program = prog_body
	entry_probe = function + "_entry"
	exit_probe = function + "_exit"
	program = program.replace("PROBE_ENTRY", entry_probe)
	program = program.replace("PROBE_EXIT", exit_probe)

	program = program.replace("GET_HKEY",
		'char fun[] = \"%s\";\n' % function +
		'func_key_t hkey = { };\n' +
		'hkey.slot = bpf_get_current_pid_tgid();\n' +
		'strcpy(hkey.func, \"%s\");' % function
		#'bpf_probe_read(&(hkey.func), sizeof(hkey.func), &fun);'
		)

	program = program.replace("STORE",
		'func_key_t key = {.func = \"%s\", ' % function +
		'.slot = bpf_log2l(delta)} ; latency.increment(key);'
		)

	final_prog = final_prog + program

if (args.verbose):
	print(final_prog)

bpf = BPF(text=final_prog)
for function in flist.split(","):
	entry_probe = function + "_entry"
	exit_probe = function + "_exit"
	if (args.path == "kernel"):
		bpf.attach_kprobe(event=function, fn_name=entry_probe)
		bpf.attach_kretprobe(event=function, fn_name=exit_probe)
	else:
		bpf.attach_uprobe(name=args.path, sym=function, fn_name=entry_probe)
		bpf.attach_uretprobe(name=args.path, sym=function, fn_name=exit_probe)

print("Tracing function latencies slower than %d ms..." %
      (args.threshold))
latencies = bpf["latency"]

def print_hist():
    print("[%s]" % strftime("%H:%M:%S"))
    latencies.print_log2_hist("query latency (%s)" %
                              ("us" if args.microseconds else "ms"), "func")
    print("")
    latencies.clear()

while True:
    try:
        sleep(args.interval)
        print_hist()
    except KeyboardInterrupt:
        print_hist()
        break

