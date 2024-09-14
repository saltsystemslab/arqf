#!/bin/bash
BIN_DIR=./release
BPK=16

set -x

if [[ $1 == "small" ]]; then
WORKLOAD_DIR=$2/adaptivity_small/kuniform
fi

if [[ $1 == "medium" ]]; then
WORKLOAD_DIR=$2/adaptivity_medium/kuniform
fi

if [[ $1 == "large" ]]; then
WORKLOAD_DIR=$2/adaptivity/kuniform
fi

if [[ $3 == "inmem" ]]; then
  TEST_TYPE=adaptivity_inmem
fi

if [[ $3 == "disk" ]]; then
  TEST_TYPE=adaptivity_disk
fi

for dir in ${WORKLOAD_DIR}/*/
do
  rm ${dir}memento_${TEST_TYPE}.csv
  rm ${dir}arqf_${TEST_TYPE}.csv
  rm ${dir}adaptive_arqf_inmem_${TEST_TYPE}.csv
  rm ${dir}adaptive_arqf_wt_${TEST_TYPE}.csv
done

for dir in ${WORKLOAD_DIR}/*/
do
for bpk in 8 10 12 14 16 18 20
do

if [[ ${dir} == "keys_wtdb" ]]; then
  break 1;
fi

  ${BIN_DIR}/bench/bench_memento $bpk \
    --keys ${WORKLOAD_DIR}/keys \
    --workload ${dir}left ${dir}right ${dir}result \
    --csv ${dir}memento_${TEST_TYPE}.csv \
    --test-type ${TEST_TYPE} --key_len 8 --val_len 504 --buffer_pool_size 256

  ${BIN_DIR}/bench/bench_arqf $bpk \
    --keys ${WORKLOAD_DIR}/keys \
    --workload ${dir}left ${dir}right ${dir}result \
    --csv ${dir}arqf_${TEST_TYPE}.csv \
    --test-type ${TEST_TYPE} --key_len 8 --val_len 504 --buffer_pool_size 256

  ${BIN_DIR}/bench/bench_adaptive_arqf_inmem $bpk \
    --keys ${WORKLOAD_DIR}/keys \
    --workload ${dir}left ${dir}right ${dir}result \
    --csv ${dir}adaptive_arqf_inmem_${TEST_TYPE}.csv \
    --test-type ${TEST_TYPE} --key_len 8 --val_len 504 --buffer_pool_size 256

  ${BIN_DIR}/bench/bench_adaptive_arqf_splinterdb $bpk \
    --keys ${WORKLOAD_DIR}/keys \
    --workload ${dir}left ${dir}right ${dir}result \
    --csv ${dir}adaptive_arqf_splinterdb_${TEST_TYPE}.csv \
    --test-type ${TEST_TYPE} --key_len 8 --val_len 504 --buffer_pool_size 256
done
done
