#!/bin/bash
set -x
echo "hello"
PROJECT_ROOT=/root/sgx/Heatmap
set +e

pkill heatmap-app
rm $E/bin/*.sealed

set -e

cd $PROJECT_ROOT/enclave/bin

./heatmap-app > log &

hm=$!

set +e

cd $PROJECT_ROOT/app
python3 demo.py $1

kill $hm
