#!/bin/bash
set -x
BIN_DIR=./release
TEST_TYPE=adversarial

if [[ $1 == "small" ]]; then
WORKLOAD_DIR=$2/adversarial_small/kuniform
CACHE_SIZES=(5 24 122)
fi

if [[ $1 == "medium" ]]; then
WORKLOAD_DIR=$2/adversarial_medium/kuniform
CACHE_SIZES=(48 244 1220)
fi

if [[ $1 == "large" ]]; then
WORKLOAD_DIR=$2/adversarial_large/kuniform
CACHE_SIZES=(488 2441 12207)
fi

QUERY_SET=$4
RESULT_DIR=$3/${WORKLOAD_DIR}

for CACHE_SIZE in "${CACHE_SIZES[@]}"
do
for adversarial_rate in 1 5 10
do
for filter in surf
do
  mkdir -p ${RESULT_DIR}/0_${QUERY_SET}_trial_0
  mkdir -p ${RESULT_DIR}/5_${QUERY_SET}_trial_0
  mkdir -p ${RESULT_DIR}/10_${QUERY_SET}_trial_0

  # FPR 13- 17, 22, 28

  ${BIN_DIR}/bench/bench_${filter} 13 \
    --keys ${WORKLOAD_DIR}/keys \
    --workload ${WORKLOAD_DIR}/0_${QUERY_SET}_trial_0/left ${WORKLOAD_DIR}/0_${QUERY_SET}_trial_0/right \
    --csv ${RESULT_DIR}/0_${QUERY_SET}_trial_0/${filter}_${TEST_TYPE}_fpr13.csv \
    --test-type ${TEST_TYPE} --key_len 8 --val_len 504 --buffer_pool_size ${CACHE_SIZE} --adversarial_rate ${adversarial_rate}

  ${BIN_DIR}/bench/bench_${filter} 6 \
    --keys ${WORKLOAD_DIR}/keys \
    --workload ${WORKLOAD_DIR}/5_${QUERY_SET}_trial_0/left ${WORKLOAD_DIR}/5_${QUERY_SET}_trial_0/right \
    --csv ${RESULT_DIR}/5_${QUERY_SET}_trial_0/${filter}_${TEST_TYPE}_fpr13.csv \
    --test-type ${TEST_TYPE} --key_len 8 --val_len 504 --buffer_pool_size ${CACHE_SIZE} --adversarial_rate ${adversarial_rate}

  ${BIN_DIR}/bench/bench_${filter}  7 \
    --keys ${WORKLOAD_DIR}/keys \
    --workload ${WORKLOAD_DIR}/10_${QUERY_SET}_trial_0/left ${WORKLOAD_DIR}/10_${QUERY_SET}_trial_0/right \
    --csv ${RESULT_DIR}/10_${QUERY_SET}_trial_0/${filter}_${TEST_TYPE}_fpr13.csv \
    --test-type ${TEST_TYPE} --key_len 8 --val_len 504 --buffer_pool_size ${CACHE_SIZE} --adversarial_rate ${adversarial_rate}

done
done
done

for CACHE_SIZE in "${CACHE_SIZES[@]}"
do
for adversarial_rate in 1 5 10
do
for filter in memento adaptive_arqf_splinterdb grafite snarf 
do
  mkdir -p ${RESULT_DIR}/0_${QUERY_SET}_trial_0
  mkdir -p ${RESULT_DIR}/5_${QUERY_SET}_trial_0
  mkdir -p ${RESULT_DIR}/10_${QUERY_SET}_trial_0

  # FPR 13- 17, 22, 28

  ${BIN_DIR}/bench/bench_${filter} 13 \
    --keys ${WORKLOAD_DIR}/keys \
    --workload ${WORKLOAD_DIR}/0_${QUERY_SET}_trial_0/left ${WORKLOAD_DIR}/0_${QUERY_SET}_trial_0/right \
    --csv ${RESULT_DIR}/0_${QUERY_SET}_trial_0/${filter}_${TEST_TYPE}.csv \
    --test-type ${TEST_TYPE} --key_len 8 --val_len 504 --buffer_pool_size ${CACHE_SIZE} --adversarial_rate ${adversarial_rate}

  ${BIN_DIR}/bench/bench_${filter} 18 \
    --keys ${WORKLOAD_DIR}/keys \
    --workload ${WORKLOAD_DIR}/5_${QUERY_SET}_trial_0/left ${WORKLOAD_DIR}/5_${QUERY_SET}_trial_0/right \
    --csv ${RESULT_DIR}/5_${QUERY_SET}_trial_0/${filter}_${TEST_TYPE}.csv \
    --test-type ${TEST_TYPE} --key_len 8 --val_len 504 --buffer_pool_size ${CACHE_SIZE} --adversarial_rate ${adversarial_rate}

  ${BIN_DIR}/bench/bench_${filter} 24 \
    --keys ${WORKLOAD_DIR}/keys \
    --workload ${WORKLOAD_DIR}/10_${QUERY_SET}_trial_0/left ${WORKLOAD_DIR}/10_${QUERY_SET}_trial_0/right \
    --csv ${RESULT_DIR}/10_${QUERY_SET}_trial_0/${filter}_${TEST_TYPE}.csv \
    --test-type ${TEST_TYPE} --key_len 8 --val_len 504 --buffer_pool_size ${CACHE_SIZE} --adversarial_rate ${adversarial_rate}

done
done
done
