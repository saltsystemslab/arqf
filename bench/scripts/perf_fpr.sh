#!/bin/bash
set -x
BIN_DIR=./release
BPK=16
TEST_TYPE=fpr

if [[ $1 == "small" ]]; then
WORKLOAD_DIR=$2/small/kuniform
CACHE_SIZE=10
fi

if [[ $1 == "medium" ]]; then
WORKLOAD_DIR=$2/medium/kuniform
CACHE_SIZE=256
fi

if [[ $1 == "large" ]]; then
WORKLOAD_DIR=$2/large/kuniform
CACHE_SIZE=512
fi

RESULT_DIR=$3

for dir in ${WORKLOAD_DIR}/*/
do
  rm ${dir}memento_${TEST_TYPE}.csv
  rm ${dir}arqf_${TEST_TYPE}.csv
  rm ${dir}adaptive_arqf_inmem_${TEST_TYPE}.csv
  rm ${dir}adaptive_arqf_splinterdb_${TEST_TYPE}.csv
done

for dir in ${WORKLOAD_DIR}/*/
do
for bpk in 24 
do
  mkdir -p ${RESULT_DIR}/${dir}
  sudo perf record -g -o ./${RESULT_DIR}/${dir}memento.report ${BIN_DIR}/bench/bench_memento $bpk \
    --keys ${WORKLOAD_DIR}/keys \
    --workload ${dir}left ${dir}right ${dir}result \
    --csv ${RESULT_DIR}/${dir}memento_${TEST_TYPE}.csv \
    --test-type ${TEST_TYPE} --key_len 8 --val_len 504 --buffer_pool_size ${CACHE_SIZE}

  sudo perf record -g -o ./${RESULT_DIR}/${dir}arqf.report ${BIN_DIR}/bench/bench_arqf $bpk \
    --keys ${WORKLOAD_DIR}/keys \
    --workload ${dir}left ${dir}right ${dir}result \
    --csv ${RESULT_DIR}/${dir}arqf_${TEST_TYPE}.csv \
    --test-type ${TEST_TYPE} --key_len 8 --val_len 504 --buffer_pool_size ${CACHE_SIZE}
done
done
