#!/bin/bash
BIN_DIR=./release
BPK=16
TEST_TYPE=mixed

set -x

if [[ $1 == "small" ]]; then
WORKLOAD_DIR=$2/mixed_small/kuniform
CACHE_SIZE=16
TOTAL_OPS=10000 # Actual total ops are 1M, we divide by 100 to make multiplications integer
fi

if [[ $1 == "medium" ]]; then
WORKLOAD_DIR=$2/mixed_medium/kuniform
CACHE_SIZE=128
TOTAL_OPS=100000
fi

if [[ $1 == "large" ]]; then
WORKLOAD_DIR=$2/mixed_large/kuniform
CACHE_SIZE=1024
TOTAL_OPS=200000
fi

echo ${WORKLOAD_DIR}

if [[ $3 == "echo" ]]; then
  BIN_DIR="echo ./release"
fi

for read_ratio in 0 
do
for filter in adaptive_arqf_splinterdb 
do
  ${BIN_DIR}/bench/bench_${filter} 14 \
    --keys ${WORKLOAD_DIR}/keys \
    --workload ${WORKLOAD_DIR}/0_qzipfian_trial_0/left ${WORKLOAD_DIR}/0_qzipfian_trial_0/right ${WORKLOAD_DIR}/0_qzipfian_trial_0/result \
    --csv ${WORKLOAD_DIR}/0_qzipfian_trial_0/${filter}_${TEST_TYPE}.csv \
    --test-type ${TEST_TYPE} --key_len 8 --val_len 504 --buffer_pool_size 960  \
    --mixed_num_warmup_keys 1 --mixed_num_reads $((TOTAL_OPS * read_ratio)) --mixed_num_writes $((TOTAL_OPS * $((100 - read_ratio)) ))
done

for filter in memento
do
  ${BIN_DIR}/bench/bench_${filter} 14 \
    --keys ${WORKLOAD_DIR}/keys \
    --workload ${WORKLOAD_DIR}/0_qzipfian_trial_0/left ${WORKLOAD_DIR}/0_qzipfian_trial_0/right ${WORKLOAD_DIR}/0_qzipfian_trial_0/result \
    --csv ${WORKLOAD_DIR}/0_qzipfian_trial_0/${filter}_${TEST_TYPE}.csv \
    --test-type ${TEST_TYPE} --key_len 8 --val_len 504 --buffer_pool_size 1024  \
    --mixed_num_warmup_keys 1 --mixed_num_reads $((TOTAL_OPS * read_ratio)) --mixed_num_writes $((TOTAL_OPS * $((100 - read_ratio)) ))
done
done
