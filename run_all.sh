#!/bin/bash

dataset_size=$1 #small/medium/large

./bench/scripts/gen_adaptivity_workload.sh $dataset_size workloads
./bench/scripts/gen_mixed_workload.sh $dataset_size workloads
./bench/scripts/run_fpr.sh $dataset_size workloads
./bench/scripts/run_adversarial.sh $dataset_size workloads
./bench/scripts/run_mixed.sh $dataset_size workloads
