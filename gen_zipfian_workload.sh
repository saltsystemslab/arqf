#!/bin/bash

set -x 

N_ELEMS=1000000
N_QUERY=1000000
UNIVERSE_SIZE=100000000

BUILD_PATH=./release
WORKLOAD_GEN_PATH=$(realpath $BUILD_PATH/bench/workload_gen)
WORKLOAD_PATH=workload_adaptivity

echo $WORKLOAD_GEN_PATH

mkdir -p ${WORKLOAD_PATH}
 
cd ${WORKLOAD_PATH}

$WORKLOAD_GEN_PATH -n ${N_ELEMS} -q ${N_QUERY} --kdist kuniform --qdist qzipfian -u $UNIVERSE_SIZE -t 5
