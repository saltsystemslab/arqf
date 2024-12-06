#!/bin/bash

dataset_size=$1 #small/medium/large
./bench/scripts/gen_fpr_workload.sh small workloads
./bench/scripts/perf_fpr.sh small workloads

./bench/scripts/gen_fpr_workload.sh medium workloads
./bench/scripts/perf_fpr.sh medium workloads

./bench/scripts/gen_fpr_workload.sh large workloads
./bench/scripts/perf_fpr.sh large workloads
