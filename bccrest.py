from flask import Flask, request
from os import remove
from time import sleep
import subprocess, sys
#from flask import send_file
from flask_restful import reqparse, abort, Api, Resource
from cachetop import cachetopUtil
from vfsstat import vfsstatUtil
from dcstat import dcstatUtil
from ext4slower import ext4slowerUtil
from bitesize import bitesizeUtil
from mdflush import mdflushUtil
from filelife import filelifeUtil
from biosnoop import biosnoopUtil
from fileslower import fileslowerUtil
from tcpconnlat import tcpconnlatUtil
from tcpretrans import tcpretransUtil
from tcpaccept import tcpacceptUtil
from cpudist import cpudistUtil
from cachestat import cachestatUtil
from runqlat import runqlatUtil
from runqlatnew import runqlatnewUtil
from tcp4connect import tcp4connectUtil
from offcputime import offcputimeUtil
from offcputimenew import offcputimenewUtil
from ttysnoop import ttysnoopUtil
from offwaketime import offwaketimeUtil

app = Flask(__name__)
api = Api(app)

class vfsstat(Resource):
    def get(self, ival, cnt):
	proc = vfsstatUtil(ival, cnt)
	return {"out" : proc}
	#return send_file(proc, mimetype='text/plain',attachment_filename='log.txt',as_attachment=True)

class cachetop(Resource):
    def get(self, ival, cnt):
	proc = cachetopUtil(ival, cnt)
	return {"out" : proc}

class dcstat(Resource):
    def get(self, ival, cnt):
        proc = dcstatUtil(ival, cnt)
        return {"out" : proc}

class ext4slower(Resource):
    def get(self):
	obj_duration = int(request.args.get('duration', 10))
	obj_pid = request.args.get('pid', "")
	obj_t_hold = int(request.args.get('threshold', 10))
	obj_j = request.args.get('csv', False)
        proc = ext4slowerUtil(obj_duration, obj_pid, obj_t_hold, obj_j)
        return {"out" : proc}

class bitesize(Resource):
    def get(self, duration):
        proc = bitesizeUtil(duration)
	return {"out" : proc}

class mdflush(Resource):
    def get(self, duration):
        proc = mdflushUtil(duration)
	return {"out" : proc}

class filelife(Resource):
    #def get(self, duration, pid=None):
    def get(self):
        obj_duration = int(request.args.get('duration', 10))
        obj_pid = request.args.get('p', "")
        if obj_pid:
		obj_pid = int(obj_pid)
	print(obj_duration, "and " ,obj_pid)
        proc = filelifeUtil(duration=obj_duration, pid=obj_pid)
        #proc = filelifeUtil(duration, pid)
	return {"out" : proc}

class biosnoop(Resource):
    def get(self):
        obj_duration = int(request.args.get('duration', 10))
        proc = biosnoopUtil(obj_duration)
	return {"out" : proc}

class fileslower(Resource):
    def get(self):
        obj_duration = int(request.args.get('duration', 10))
        obj_min_ms = int(request.args.get('min_ms', 10))
        obj_pid = request.args.get('pid', "")
        if obj_pid:
		obj_pid = int(obj_pid)
        obj_files = request.args.get('files', "")
        proc = fileslowerUtil(obj_duration, obj_min_ms, obj_pid, obj_files)
	return {"out" : proc}

class tcpconnlat(Resource):
    def get(self):
        obj_duration = int(request.args.get('duration', 10))
        obj_pid = request.args.get('pid', "")
        if obj_pid:
		obj_pid = int(obj_pid)
        proc = tcpconnlatUtil(obj_duration, obj_pid)
	return {"out" : proc}

class tcpretrans(Resource):
    def get(self):
        obj_duration = int(request.args.get('duration', 10))
        obj_lp = request.args.get('lossprobe', False)
        proc = tcpretransUtil(obj_duration, obj_lp)
	return {"out" : proc}

class tcpaccept(Resource):
    def get(self):
        obj_duration = int(request.args.get('duration', 10))
        obj_pid = request.args.get('pid', "")
        if obj_pid:
		obj_pid = int(obj_pid)
        proc = tcpacceptUtil(obj_duration, obj_pid)
	return {"out" : proc}

class cpudist(Resource):
    def get(self):
        obj_offcpu = request.args.get('offcpu', False)
        obj_ms     = request.args.get('ms', False)
        obj_pids   = request.args.get('pids', False)
        obj_tids   = request.args.get('tids', False)
        obj_ival   = int(request.args.get('interval', 1))
        obj_count  = int(request.args.get('count', 10))
        obj_pid    = request.args.get('pid', "")
        if obj_pid:
		obj_pid = int(obj_pid)
        proc = cpudistUtil(obj_offcpu, obj_pid, obj_ms, obj_pids, obj_tids, obj_ival, obj_count)
	return {"out" : proc}

class cachestat(Resource):
    def get(self):
        obj_ival = int(request.args.get('interval', 10))
        obj_count = int(request.args.get('count', 1))
        proc = cachestatUtil(obj_ival, obj_count)
	return {"out" : proc}

class runqlat(Resource):
    def get(self):
        obj_ms     = request.args.get('ms', False)
        obj_pids   = request.args.get('pids', False)
        obj_tids   = request.args.get('tids', False)
        obj_pid    = request.args.get('pid', "")
        if obj_pid:
		obj_pid = int(obj_pid)
        obj_ival   = int(request.args.get('interval', 1))
        obj_count  = int(request.args.get('count', 10))
        proc = runqlatUtil(obj_ms, obj_pids, obj_tids, obj_pid, obj_ival, obj_count)
        return {"out" : proc}

class runqlatnew(Resource):
    def get(self):
        obj_ms     = request.args.get('ms', False)
        obj_pids   = request.args.get('pids', False)
        obj_tids   = request.args.get('tids', False)
        obj_pid    = request.args.get('pid', "")
        obj_pidnss = request.args.get('pidnss', False)
        if obj_pid:
		obj_pid = int(obj_pid)
        obj_ival   = int(request.args.get('interval', 1))
        obj_count  = int(request.args.get('count', 10))
        proc = runqlatnewUtil(obj_ms, obj_pids, obj_tids, obj_pid, obj_pidnss, obj_ival, obj_count)
        return {"out" : proc}

class tcp4connect(Resource):
    def get(self):
        obj_duration = int(request.args.get('duration', 10))
        proc = tcp4connectUtil(obj_duration)
	return {"out" : proc}

class offcputime(Resource):
    def get(self):
        obj_pid        = request.args.get('pid', "")
        if obj_pid:
		obj_pid = int(obj_pid)
        obj_useronly   = request.args.get('useronly', False)
	obj_flame      = request.args.get('flame', False)
        obj_folded     = request.args.get('folded', False)
        obj_duration   = int(request.args.get('duration', 30))

	if obj_flame is not False:
		obj_folded = True

        proc = offcputimeUtil(obj_pid, obj_useronly, obj_folded, obj_duration)

	if obj_flame is not False:
		file = open("flameout", "w")
		file.write(proc)
		file.close()
		# Cannot use ---'echo', proc--- in below command because of limitation of ARG_MAX of 131072; so save response in file
		folded_out = subprocess.Popen(('cat', 'flameout'), stdout=subprocess.PIPE)
		output = subprocess.check_output(('FlameGraph/flamegraph.pl'), stdin=folded_out.stdout)
		folded_out.wait()
	        remove("flameout")
		return {"out" : output}

        return {"out" : proc}

# This will call newer offcputime tool; to be used in kernel versions 4.5+ which have stack trace support for eBPF
class offcputimenew(Resource):
    def get(self):
        obj_pid        = request.args.get('pid', None)
        if obj_pid is not None:
		obj_pid = int(obj_pid)
        obj_tgid       = request.args.get('tgid', None)
        if obj_tgid is not None:
		obj_tgid = int(obj_tgid)
        obj_useronly   = request.args.get('useronly', False)
        obj_kernelonly = request.args.get('kernelonly', False)
        obj_folded     = request.args.get('folded', False)
	obj_flame      = request.args.get('flame', False)
        obj_duration   = int(request.args.get('duration', 30))
        obj_stack_size = int(request.args.get('stack_size', 1024))

	if obj_flame is not False:
		obj_folded = True

        proc = offcputimenewUtil(obj_folded, obj_duration, False, False, obj_useronly, obj_kernelonly, obj_tgid, obj_pid, in_state=0, in_stack_storage_size=obj_stack_size, in_min_block_time=1, in_max_block_time=(1 << 64) - 1)

	if obj_flame is not False:
		file = open("flameout", "w")
		file.write(proc)
		file.close()
		# Cannot use ---'echo', proc--- in below command because of limitation of ARG_MAX of 131072; so save response in file
		folded_out = subprocess.Popen(('cat', 'flameout'), stdout=subprocess.PIPE)
		output = subprocess.check_output(('FlameGraph/flamegraph.pl'), stdin=folded_out.stdout)
		folded_out.wait()
	        remove("flameout")
		return {"out" : output}

        return {"out" : proc}

# This will call newer offcputime tool; to be used in kernel versions 4.5+ which have stack trace support for eBPF
class offwaketime(Resource):
    def get(self):
        obj_flame      = request.args.get('flame', False)
        obj_duration   = int(request.args.get('duration', 30))

        proc = offwaketimeUtil(obj_duration)

        if obj_flame is not False:
                file = open("flameout", "w")
                file.write(proc)
                file.close()
                # Cannot use ---'echo', proc--- in below command because of limitation of ARG_MAX of 131072; so save response in file
                folded_out = subprocess.Popen(('cat', 'flameout'), stdout=subprocess.PIPE)
                output = subprocess.check_output(('FlameGraph/flamegraph.pl'), stdin=folded_out.stdout)
                folded_out.wait()
	        remove("flameout")
                return {"out" : output}

        return {"out" : proc}


class perf(Resource):
    def get(self):
        obj_pid        = request.args.get('pid', None)
        if obj_pid is not None:
                obj_pid = int(obj_pid)
        obj_duration   = int(request.args.get('duration', 30))

	proc = subprocess.Popen(("perf", "record", "-ag", "-o", "perf.out"))
	sleep(obj_duration)
	proc.terminate()
	sleep(3)

        folded_out = subprocess.Popen(('perf', 'script', '-i', 'perf.out'), stdout=subprocess.PIPE)
        output = subprocess.check_output(('FlameGraph/stackcollapse-perf.pl'), stdin=folded_out.stdout)
        folded_out.wait()

        file = open("flameout", "w")
        file.write(output)
        file.close()
        # Cannot use ---'echo', proc--- in below command because of limitation of ARG_MAX of 131072; so save response in file
        folded_out = subprocess.Popen(('cat', 'flameout'), stdout=subprocess.PIPE)
        output = subprocess.check_output(('FlameGraph/flamegraph.pl'), stdin=folded_out.stdout)
        folded_out.wait()

	remove("flameout")
	remove("perf.out")
        return {"out" : output}

def goproUtil(duration, fmt, port, ip, secure, endpoint):
   if secure is not False:
	url = "https+insecure://%s:%s/debug/pprof/%s" % (ip, port, endpoint)
   else:
	url = "http://%s:%s/debug/pprof/%s" % (ip, port, endpoint)
   file = open("goproOut", "w+")
   output = subprocess.check_output(["/usr/local/go/bin/go", "tool", "pprof", "-%s" % fmt, "-seconds", "%s" % duration, url], stderr=file)
   file.close()
   return output, file

class gopro(Resource):
    def get(self):
        obj_duration = int(request.args.get('duration', 10))
        obj_fmt = request.args.get('fmt', "svg")
        obj_port = request.args.get('port', 4243)
        obj_ip   = request.args.get('ip', 'localhost')
        obj_secure   = request.args.get('secure', False)
        obj_endpoint   = request.args.get('endpoint', "profile")
        proc, file = goproUtil(obj_duration, obj_fmt, obj_port, obj_ip, obj_secure, obj_endpoint)
        profile = open("goproOut", "r").read()
        remove("goproOut")
        return {"out" : proc,
                "info" : profile}
        #return send_file('goproOut', attachment_filename='goproOutrr.txt', as_attachment=True)

class ttysnoop(Resource):
    def get(self):
        obj_duration = int(request.args.get('duration', 10))
        obj_device = request.args.get('device', "-1")
        proc = ttysnoopUtil(obj_duration, obj_device)
	return {"out" : proc}

##
##
##
## Actually setup the Api resource routing here
##
api.add_resource(vfsstat, '/stat/<int:ival>/<int:cnt>')
api.add_resource(cachetop, '/cache/<int:ival>/<int:cnt>')
api.add_resource(dcstat, '/dc/<int:ival>/<int:cnt>')
api.add_resource(ext4slower, '/ext4slower')
api.add_resource(bitesize, '/bitesize/<int:duration>')
api.add_resource(mdflush, '/mdflush/<int:duration>')
api.add_resource(filelife, '/filelife')
api.add_resource(biosnoop, '/biosnoop')
api.add_resource(fileslower, '/fileslower')
api.add_resource(tcpconnlat, '/tcpconnlat')
api.add_resource(tcpretrans, '/tcpretrans')
api.add_resource(tcpaccept, '/tcpaccept')
api.add_resource(cpudist, '/cpudist')
api.add_resource(cachestat, '/cachestat')
api.add_resource(runqlat, '/runqlat')
api.add_resource(runqlatnew, '/runqlatnew')
api.add_resource(tcp4connect, '/tcp4connect')
api.add_resource(offcputime, '/offcputime')
api.add_resource(offcputimenew, '/offcputimenew')
api.add_resource(perf, '/perf')
api.add_resource(gopro, '/gopro')
api.add_resource(ttysnoop, '/ttysnoop')
api.add_resource(offwaketime, '/offwaketime')


if __name__ == '__main__':
    app.run(host="0.0.0.0", port="5000")
