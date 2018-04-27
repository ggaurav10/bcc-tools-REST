#!/bin/bash

TAG=latest
IMG=ggaurav10/bccrest

default:	install

install:
	docker build -t "${IMG}:${TAG}" .

release:	install
	docker login --username=ggaurav10
	docker push "${IMG}:${TAG}"	
	docker logout
