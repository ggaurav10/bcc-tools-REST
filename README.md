# monitor
RESTified BCC tools.

BCC: https://github.com/iovisor/bcc

Usage:

vfsstat, cachetop, dcstat:
`curl -v http://localhost:5000/CMD/<ival>/<count>`

ext4slower:
`curl -v "http://localhost:5000/ext4slower?duration=4&pid=2130&threshold=2&csv=True"`

bitesize, mdflush:
`curl -v http://localhost:5000/CMD/<duration>`

filelife:
`curl -v "http://localhost:5000/CMD?duration=<duration>&p=<pid>"`

biosnoop:
`curl -v http://localhost:5000/CMD?duration=<duration>`

offcputime:
`./geturl.py "http://localhost:5000/offcputime?flame=true&duration=10"`

gopro: `go tool pprof`

`./geturl.py "http://localhost:5000/gopro?port=<port>&duration=<duration>" > profile.svg`

# To run in container:

```
docker build -t bccrest:latest .
docker run -d \
    --privileged \
    -v /lib/modules:/lib/modules:ro \
    -v /usr/src:/usr/src:ro \
    -v /etc/localtime:/etc/localtime:ro \
    -p 5000:5000 --name bccrest \
    bccrest:latest
```

# To run in Kubernetes:
```
kubectl apply -f observer.yaml
```
