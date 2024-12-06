#!/bin/bash

dataset_size=$1 #small/medium/large
./bench/scripts/gen_fpr_workload.sh small ./workloads
./bench/scripts/run_fpr.sh small workloads results

./bench/scripts/gen_fpr_workload.sh medium ./workloads
./bench/scripts/run_fpr.sh medium workloads results

./bench/scripts/gen_fpr_workload.sh large workloads
./bench/scripts/perf_fpr.sh large workloads
