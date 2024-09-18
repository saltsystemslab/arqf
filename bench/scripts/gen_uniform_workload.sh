#!/bin/bash

#set -x 

if [[ $1 == "small" ]]; then
  echo "SMALL"
N_ELEMS=1000000 # 2 Million
Q_UNIVERSE_SIZE=10000000 # 10 Million
N_QUERY=2000000 # 0.1 Million
WORKLOAD_PATH=$2/adversarial_small
fi

if [[ $1 == "medium" ]]; then
  echo "MEDIUM"
N_ELEMS=10000000 # 20 Million
Q_UNIVERSE_SIZE=10000000 # 10 Million
N_QUERY=20000000 # 10 Million
WORKLOAD_PATH=$2/adversarial_medium
fi

if [[ $1 == "large" ]]; then
  echo "LARGE"
N_ELEMS=100000000 # 200 Million
Q_UNIVERSE_SIZE=10000000 # 10 Million
N_QUERY=200000000 # 100 Million
WORKLOAD_PATH=$2/adversarial
fi

echo $N_ELEMS $UNIVERSE_SIZE $N_QUERY

BUILD_PATH=./release
WORKLOAD_GEN_PATH=$(realpath $BUILD_PATH/bench/workload_gen)

mkdir -p $2
mkdir -p ${WORKLOAD_PATH}
 
cd ${WORKLOAD_PATH}

$WORKLOAD_GEN_PATH -n ${N_ELEMS} -q ${N_QUERY} --kdist kuniform --qdist quniform -u $Q_UNIVERSE_SIZE -t 1 --allow-true
