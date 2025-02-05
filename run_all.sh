#!/bin/bash

./bench/scripts/gen_fpr_workload.sh large workloads
./bench/scripts/run_inserts.sh large workloads results

exit 0

# FPR Tests
#./bench/scripts/gen_fpr_workload.sh small workloads
#./bench/scripts/run_fpr.sh small workloads results

#./bench/scripts/gen_fpr_workload.sh medium workloads
#./bench/scripts/run_fpr.sh medium workloads results

#./bench/scripts/gen_fpr_workload.sh large workloads
#./bench/scripts/run_fpr.sh large workloads results

#Adversarial Tests
./bench/scripts/gen_adversarial_workload.sh small workloads
./bench/scripts/run_adversarial_fpr13.sh small workloads results quniform

./bench/scripts/gen_adversarial_workload.sh medium workloads results 
./bench/scripts/run_adversarial_fpr13.sh medium workloads results quniform

./bench/scripts/gen_adversarial_workload.sh large workloads
./bench/scripts/run_adversarial_fpr13.sh large workloads results quniform

#Mixed Workload Test
./bench/scripts/gen_mixed_workload.sh small workloads
./bench/scripts/run_mixed.sh small workloads results

./bench/scripts/gen_mixed_workload.sh medium workloads 
./bench/scripts/run_mixed.sh medium workloads results

./bench/scripts/gen_mixed_workload.sh large workloads
./bench/scripts/run_mixed.sh large workloads results
