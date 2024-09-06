#!/bin/bash
BIN_DIR=./release
BPK=16

set -x

if [[ $1 == "small" ]]; then
WORKLOAD_DIR=$2/adaptivity_small/kuniform
fi

if [[ $1 == "large" ]]; then
WORKLOAD_DIR=$2/adaptivity_medium/kuniform
fi

if [[ $1 == "large" ]]; then
WORKLOAD_DIR=$2/adaptivity/kuniform
fi

for bpk in 8 10 12 14 16 18 20 22 24 26 28
do
for dir in ${WORKLOAD_DIR}/*/
do
  ${BIN_DIR}/bench/bench_memento $bpk \
    --keys ${WORKLOAD_DIR}/keys \
    --workload ${dir}left ${dir}right ${dir}result \
    --csv ${dir}memento.csv \
    --test-type adaptivity

  ${BIN_DIR}/bench/bench_arqf $bpk \
    --keys ${WORKLOAD_DIR}/keys \
    --workload ${dir}left ${dir}right ${dir}result \
    --csv ${dir}arqf.csv \
    --test-type adaptivity

  ${BIN_DIR}/bench/bench_adaptive_arqf_inmem $bpk \
    --keys ${WORKLOAD_DIR}/keys \
    --workload ${dir}left ${dir}right ${dir}result \
    --csv ${dir}/adaptive_arqf.csv \
    --test-type adaptivity
done
done
