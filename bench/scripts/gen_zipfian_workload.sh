#!/bin/bash

#set -x 

if [[ $1 == "small" ]]; then
  echo "SMALL"
N_ELEMS=2000000 # 2 Million
Q_UNIVERSE_SIZE=10000000 # 40 Million
N_QUERY=100000 # 0.1 Million
WORKLOAD_PATH=$2/workload_adaptivity_small
fi

if [[ $1 == "medium" ]]; then
  echo "SMALL"
N_ELEMS=20000000 # 20 Million
Q_UNIVERSE_SIZE=10000000 # 40 Million
N_QUERY=1000000 # 10 Million
WORKLOAD_PATH=$2/workload_adaptivity_medium
fi

if [[ $1 == "large" ]]; then
  echo "LARGE"
N_ELEMS=200000000 # 200 Million
Q_UNIVERSE_SIZE=10000000 # 4 Billion
N_QUERY=10000000 # 10 Million
WORKLOAD_PATH=$2/workload_adaptivity
fi

echo $N_ELEMS $UNIVERSE_SIZE $N_QUERY

BUILD_PATH=./release
WORKLOAD_GEN_PATH=$(realpath $BUILD_PATH/bench/workload_gen)

mkdir -p $2
mkdir -p ${WORKLOAD_PATH}
 
cd ${WORKLOAD_PATH}

$WORKLOAD_GEN_PATH -n ${N_ELEMS} -q ${N_QUERY} --kdist kuniform --qdist qzipfian -u $Q_UNIVERSE_SIZE -t 1
