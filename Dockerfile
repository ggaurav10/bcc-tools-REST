FROM ubuntu:16.04

ENV PATH            "$PATH:/usr/share/bcc/tools/"

RUN apt-get update -y
RUN apt-get install -y python-pip python-dev linux-tools-common linux-tools-4.4.0-96-generic git apt-transport-https
RUN ln -s /usr/lib/linux-tools/4.4.0-96-generic /usr/lib/linux-tools/4.12.10-coreos
RUN ln -s /usr/lib/linux-tools/4.4.0-96-generic /usr/lib/linux-tools/4.13.16-coreos-r1
RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys D4284CDD
RUN echo "deb https://repo.iovisor.org/apt/xenial xenial main" | tee /etc/apt/sources.list.d/iovisor.list
RUN apt-get -y update
RUN apt-get -y install bcc-tools libbcc-examples
COPY ./requirements.txt /app/requirements.txt

RUN git clone https://github.com/brendangregg/FlameGraph.git
WORKDIR /app

RUN pip install -r requirements.txt

RUN apt-get update && \
    apt-get install wget
RUN wget https://redirector.gvt1.com/edgedl/go/go1.9.2.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go1.9.2.linux-amd64.tar.gz
RUN rm -f go1.9.2.linux-amd64.tar.gz

RUN ln -s /usr/lib/linux-tools/4.4.0-96-generic /usr/lib/linux-tools/4.14.32-coreos

ENV PATH     "$PATH:/usr/local/go/bin"

COPY . /app

ENTRYPOINT [ "sh", "-c", "mount -t debugfs nodev /sys/kernel/debug; cd /app; python bccrest.py" ]
