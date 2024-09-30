#!/bin/bash
BIN_DIR=./release
BPK=16

set -x

if [[ $1 == "small" ]]; then
WORKLOAD_DIR=$2/mixed_small/kuniform
CACHE_SIZE=16
TEST_TYPE=adaptivity_mixed
TOTAL_OPS=10000 # Actual total ops are 1M, we divide by 100 to make multiplications integer
fi

if [[ $1 == "medium" ]]; then
WORKLOAD_DIR=$2/mixed_medium/kuniform
CACHE_SIZE=128
TOTAL_OPS=100000
TEST_TYPE=adaptivity_mixed
fi

if [[ $1 == "large" ]]; then
WORKLOAD_DIR=$2/mixed/kuniform
CACHE_SIZE=1024
TOTAL_OPS=1000000
TEST_TYPE=adaptivity_mixed
fi

echo ${WORKLOAD_DIR}
for dir in ${WORKLOAD_DIR}/*/
do
  rm ${dir}memento_${TEST_TYPE}.csv
  rm ${dir}arqf_${TEST_TYPE}.csv
  rm ${dir}adaptive_arqf_inmem_${TEST_TYPE}.csv
  rm ${dir}adaptive_arqf_splinterdb_${TEST_TYPE}.csv
done

if [[ $3 == "echo" ]]; then
  BIN_DIR="echo ./release"
fi

for read_ratio in 0 25 75 100 
do
for filter in memento arqf adaptive_arqf_inmem adaptive_arqf_splinterdb 
do
  ${BIN_DIR}/bench/bench_${filter} 14 \
    --keys ${WORKLOAD_DIR}/keys \
    --workload ${WORKLOAD_DIR}/0_quniform_trial_0/left ${WORKLOAD_DIR}/0_quniform_trial_0/right ${WORKLOAD_DIR}/0_quniform_trial_0/result \
    --csv ${WORKLOAD_DIR}/0_quniform_trial_0/${filter}_${TEST_TYPE}.csv \
    --test-type ${TEST_TYPE} --key_len 8 --val_len 504 --buffer_pool_size ${CACHE_SIZE}  \
    --mixed_num_warmup_keys $((TOTAL_OPS * 100)) --mixed_num_reads $((TOTAL_OPS * read_ratio)) --mixed_num_writes $((TOTAL_OPS * $((100 - read_ratio)) ))

  ${BIN_DIR}/bench/bench_${filter} 18 \
    --keys ${WORKLOAD_DIR}/keys \
    --workload ${WORKLOAD_DIR}/5_quniform_trial_0/left ${WORKLOAD_DIR}/5_quniform_trial_0/right ${WORKLOAD_DIR}/5_quniform_trial_0/result \
    --csv ${WORKLOAD_DIR}/5_quniform_trial_0/${filter}_${TEST_TYPE}.csv \
    --test-type ${TEST_TYPE} --key_len 8 --val_len 504 --buffer_pool_size ${CACHE_SIZE}  \
    --mixed_num_warmup_keys $((TOTAL_OPS * 100)) --mixed_num_reads $((TOTAL_OPS * read_ratio)) --mixed_num_writes $((TOTAL_OPS * $((100 - read_ratio)) ))

  ${BIN_DIR}/bench/bench_${filter} 22 \
    --keys ${WORKLOAD_DIR}/keys \
    --workload ${WORKLOAD_DIR}/10_quniform_trial_0/left ${WORKLOAD_DIR}/10_quniform_trial_0/right ${WORKLOAD_DIR}/10_quniform_trial_0/result \
    --csv ${WORKLOAD_DIR}/10_quniform_trial_0/${filter}_${TEST_TYPE}.csv \
    --test-type ${TEST_TYPE} --key_len 8 --val_len 504 --buffer_pool_size ${CACHE_SIZE} \
    --mixed_num_warmup_keys $((TOTAL_OPS * 100)) --mixed_num_reads $((TOTAL_OPS * read_ratio)) --mixed_num_writes $((TOTAL_OPS * $((100 - read_ratio)) ))
done
done
