#!/bin/bash

#set -x 
Q_UNIVERSE_SIZE=10000000 # 10 Million

if [[ $1 == "small" ]]; then
N_ELEMS=2000000 # 2 Million
N_QUERY=2000000 # 2 Million
WORKLOAD_PATH=$2/mixed_small
fi

if [[ $1 == "medium" ]]; then
N_ELEMS=20000000 # 2 Million
N_QUERY=20000000 # 2 Million
WORKLOAD_PATH=$2/mixed_medium
fi


if [[ $1 == "large" ]]; then
N_ELEMS=200000000 # 2 Million
N_QUERY=200000000 # 2 Million
WORKLOAD_PATH=$2/mixed_large
fi

BUILD_PATH=./release
WORKLOAD_GEN_PATH=$(realpath $BUILD_PATH/bench/workload_gen)

mkdir -p $2
mkdir -p ${WORKLOAD_PATH}
 
cd ${WORKLOAD_PATH}

$WORKLOAD_GEN_PATH -n ${N_ELEMS} -q ${N_QUERY} --kdist kuniform --qdist qzipfian quniform -u $Q_UNIVERSE_SIZE -t 1
