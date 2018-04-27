#
# Profile processes that are written in Go.
# Eg: for Swarm:     curl "http://10.11.252.10:5000/gopro?fmt=svg&duration=10&port=2376"
#  or use geturl.py: ./geturl.py "http://10.11.252.10:5000/gopro?fmt=svg&duration=10&port=2376"
#
# Swarm/Docker needs to be running with debug=true and tlsverify=false options
#
#from flask import send_file
from flask import Flask, request
from flask_restful import reqparse, abort, Api, Resource
from subprocess import check_output
from os import remove

app = Flask(__name__)
api = Api(app)

def goproUtil(duration, fmt, port):
   url = "https+insecure://localhost:%s/debug/pprof/profile" % port
   file = open("goproOut", "w+")
   output = check_output(["/usr/local/go/bin/go", "tool", "pprof", "-%s" % fmt, "-seconds", "%s" % duration, url], stderr=file)
   file.close()
   return output, file

class gopro(Resource):
    def get(self):
        obj_duration = int(request.args.get('duration', 10))
        obj_fmt = request.args.get('fmt', "svg")
        obj_port = request.args.get('port', 4243)
        proc, file = goproUtil(obj_duration, obj_fmt, obj_port)
        profile = open("goproOut", "r").read()
        remove("goproOut")
	return {"out" : proc,
                "info" : profile}
	#return send_file('goproOut', attachment_filename='goproOutrr.txt', as_attachment=True)


##
##
##
## Actually setup the Api resource routing here
##
api.add_resource(gopro, '/gopro')

if __name__ == '__main__':
    app.run(host="0.0.0.0", port="5000")
