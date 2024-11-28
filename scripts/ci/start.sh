#!/bin/bash

cd /home/docker/actions-runner/
echo "begin to configure"
./config.sh --url https://github.com/scroll-tech/ceno --token $TOKEN

./run.sh
