#!/bin/bash

TEST_SIZE=$1 # small/medium/large

./bench/scripts/gen_fpr_workload.sh ${TEST_SIZE} workloads
./bench/scripts/run_fpr.sh ${TEST_SIZE} workloads results kuniform
./bench/scripts/run_fpr.sh ${TEST_SIZE} workloads results books
./bench/scripts/run_fpr.sh ${TEST_SIZE} workloads results osm
./bench/scripts/run_inserts.sh ${TEST_SIZE} workloads results kuniform
./bench/scripts/run_mixed.sh ${TEST_SIZE} workloads results kuniform

./bench/scripts/gen_adversarial_workload.sh ${TEST_SIZE} workloads 
./bench/scripts/run_adversarial.sh ${TEST_SIZE} workloads results quniform

# TODO: 
# 1. Mixed test inserts keys in random order. 
# Sorted order test was done by commenting out the shuffle step in bench_template. Need to add a flag for that.
# 2. Add scripts for expandability branch.
