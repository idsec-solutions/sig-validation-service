#!/usr/bin/env bash

docker build -f Dockerfile-softhsm -t docker.eidastest.se:5000/sigval-service:softhsm . && \
 docker push docker.eidastest.se:5000/sigval-service:softhsm