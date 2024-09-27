#!/bin/bash
BIN_DIR=./release
BPK=16

if [[ $1 == "small" ]]; then
WORKLOAD_DIR=$2/adversarial_small/kuniform
CACHE_SIZE=16
fi

if [[ $1 == "medium" ]]; then
WORKLOAD_DIR=$2/adversarial_medium/kuniform
CACHE_SIZE=128
fi

if [[ $1 == "large" ]]; then
WORKLOAD_DIR=$2/adversarial/kuniform
CACHE_SIZE=1024
fi

if [[ $3 == "inmem" ]]; then
  TEST_TYPE=adaptivity_inmem
fi

if [[ $3 == "disk" ]]; then
  TEST_TYPE=adaptivity_disk
fi

if [[ $4 == "echo" ]]; then
  BIN_DIR="echo ./release"
fi

for dir in ${WORKLOAD_DIR}/*/
do
  rm ${dir}memento_${TEST_TYPE}.csv
  rm ${dir}arqf_${TEST_TYPE}.csv
  rm ${dir}adaptive_arqf_inmem_${TEST_TYPE}.csv
  rm ${dir}adaptive_arqf_splinterdb_${TEST_TYPE}.csv
done

for adversarial_rate in 1 5 10
do
for filter in memento arqf adaptive_arqf_inmem adaptive_arqf_splinterdb 
do
  ${BIN_DIR}/bench/bench_${filter} 14 \
    --keys ${WORKLOAD_DIR}/keys \
    --workload ${WORKLOAD_DIR}/0_quniform_trial_0/left ${WORKLOAD_DIR}/0_quniform_trial_0/right ${WORKLOAD_DIR}/0_quniform_trial_0/result \
    --csv ${WORKLOAD_DIR}/0_quniform_trial_0/${filter}_${TEST_TYPE}.csv \
    --test-type ${TEST_TYPE} --key_len 8 --val_len 504 --buffer_pool_size ${CACHE_SIZE} --adversarial_rate ${adversarial_rate}

  ${BIN_DIR}/bench/bench_${filter} 18 \
    --keys ${WORKLOAD_DIR}/keys \
    --workload ${WORKLOAD_DIR}/5_quniform_trial_0/left ${WORKLOAD_DIR}/5_quniform_trial_0/right ${WORKLOAD_DIR}/5_quniform_trial_0/result \
    --csv ${WORKLOAD_DIR}/5_quniform_trial_0/${filter}_${TEST_TYPE}.csv \
    --test-type ${TEST_TYPE} --key_len 8 --val_len 504 --buffer_pool_size ${CACHE_SIZE} --adversarial_rate ${adversarial_rate}

  ${BIN_DIR}/bench/bench_${filter} 22 \
    --keys ${WORKLOAD_DIR}/keys \
    --workload ${WORKLOAD_DIR}/10_quniform_trial_0/left ${WORKLOAD_DIR}/10_quniform_trial_0/right ${WORKLOAD_DIR}/10_quniform_trial_0/result \
    --csv ${WORKLOAD_DIR}/10_quniform_trial_0/${filter}_${TEST_TYPE}.csv \
    --test-type ${TEST_TYPE} --key_len 8 --val_len 504 --buffer_pool_size ${CACHE_SIZE} --adversarial_rate ${adversarial_rate}
done
done
