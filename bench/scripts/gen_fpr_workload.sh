#!/bin/bash

# $1 - small/medium/large
# $2 - directory

Q_UNIVERSE_SIZE=10000000 # 10 Million
BUILD_PATH=./release
WORKLOAD_GEN_PATH=$(realpath $BUILD_PATH/bench/workload_gen)

if [[ $1 == "small" ]]; then
N_ELEMS=1000000 # 1 Million
N_QUERY=2000000 # 2 Million
WORKLOAD_PATH=$2/small
fi

if [[ $1 == "medium" ]]; then
N_ELEMS=10000000 # 10 Million
N_QUERY=20000000 # 20 Million
WORKLOAD_PATH=$2/medium
fi

if [[ $1 == "large" ]]; then
N_ELEMS=100000000 # 100 Million
N_QUERY=200000000 # 200 Million
WORKLOAD_PATH=$2/large
fi

mkdir -p $2
mkdir -p ${WORKLOAD_PATH}
 
cd ${WORKLOAD_PATH}

$WORKLOAD_GEN_PATH -n ${N_ELEMS} -q ${N_QUERY} --kdist kuniform --qdist qzipfian -u $Q_UNIVERSE_SIZE -t 1 --binary-keys ../../real_datasets/books_200M_uint64
$WORKLOAD_GEN_PATH -n ${N_ELEMS} -q ${N_QUERY} --kdist kuniform --qdist qzipfian -u $Q_UNIVERSE_SIZE -t 1 --binary-keys ../../real_datasets/osm_cellids_200M_uint64
$WORKLOAD_GEN_PATH -n ${N_ELEMS} -q ${N_QUERY} --kdist kuniform --qdist qzipfian -u $Q_UNIVERSE_SIZE -t 1
$WORKLOAD_GEN_PATH -n ${N_ELEMS} -q ${N_QUERY} --kdist kuniform --qdist qcorrelated-zipf -u $Q_UNIVERSE_SIZE -t 1
