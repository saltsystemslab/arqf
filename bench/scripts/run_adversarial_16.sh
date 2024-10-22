#!/bin/bash
set -x
BIN_DIR=./release
BPK=16
TEST_TYPE=adversarial

if [[ $1 == "small" ]]; then
WORKLOAD_DIR=$2/adversarial_small/kuniform
CACHE_SIZE=16
fi

if [[ $1 == "medium" ]]; then
WORKLOAD_DIR=$2/adversarial_medium/kuniform
CACHE_SIZE=128
fi

if [[ $1 == "large" ]]; then
WORKLOAD_DIR=$2/adversarial_large/kuniform
CACHE_SIZE=1024
fi

for dir in ${WORKLOAD_DIR}/*/
do
  rm ${dir}memento_${TEST_TYPE}.csv
  rm ${dir}arqf_${TEST_TYPE}.csv
  rm ${dir}adaptive_arqf_inmem_${TEST_TYPE}.csv
  rm ${dir}adaptive_arqf_splinterdb_${TEST_TYPE}.csv
done

QUERY_SET=$4
RESULT_DIR=$3/${WORKLOAD_DIR}

for adversarial_rate in 1 5 10
do
  mkdir -p ${RESULT_DIR}/0_${QUERY_SET}_trial_0
  mkdir -p ${RESULT_DIR}/10_${QUERY_SET}_trial_0
  mkdir -p ${RESULT_DIR}/5_${QUERY_SET}_trial_0
for filter in memento adaptive_arqf_splinterdb 
do

  ${BIN_DIR}/bench/bench_${filter} 16 \
    --keys ${WORKLOAD_DIR}/keys \
    --workload ${WORKLOAD_DIR}/0_${QUERY_SET}_trial_0/left ${WORKLOAD_DIR}/0_${QUERY_SET}_trial_0/right ${WORKLOAD_DIR}/0_${QUERY_SET}_trial_0/result \
    --csv ${RESULT_DIR}/0_${QUERY_SET}_trial_0/${filter}_${TEST_TYPE}_16bpk.csv \
    --test-type ${TEST_TYPE} --key_len 8 --val_len 504 --buffer_pool_size ${CACHE_SIZE} --adversarial_rate ${adversarial_rate}

  ${BIN_DIR}/bench/bench_${filter} 16 \
    --keys ${WORKLOAD_DIR}/keys \
    --workload ${WORKLOAD_DIR}/5_${QUERY_SET}_trial_0/left ${WORKLOAD_DIR}/5_${QUERY_SET}_trial_0/right ${WORKLOAD_DIR}/5_${QUERY_SET}_trial_0/result \
    --csv ${RESULT_DIR}/5_${QUERY_SET}_trial_0/${filter}_${TEST_TYPE}_16bpk.csv \
    --test-type ${TEST_TYPE} --key_len 8 --val_len 504 --buffer_pool_size ${CACHE_SIZE} --adversarial_rate ${adversarial_rate}

  ${BIN_DIR}/bench/bench_${filter} 16 \
    --keys ${WORKLOAD_DIR}/keys \
    --workload ${WORKLOAD_DIR}/10_${QUERY_SET}_trial_0/left ${WORKLOAD_DIR}/10_${QUERY_SET}_trial_0/right ${WORKLOAD_DIR}/10_${QUERY_SET}_trial_0/result \
    --csv ${RESULT_DIR}/10_${QUERY_SET}_trial_0/${filter}_${TEST_TYPE}_16bpk.csv \
    --test-type ${TEST_TYPE} --key_len 8 --val_len 504 --buffer_pool_size ${CACHE_SIZE} --adversarial_rate ${adversarial_rate}
done
done
