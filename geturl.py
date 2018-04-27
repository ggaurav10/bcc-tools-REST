#!/usr/bin/python
import requests
from sys import argv

def usage():
    print("USAGE: %s URL")
    exit()

if len(argv) != 2:
	usage()
	exit()

cmd = argv[1]

url = cmd

try:
	res = requests.get(url)
except KeyboardInterrupt:
	print " Exitting"
	exit()

print res.json()["out"]
