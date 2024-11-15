#!/bin/bash

#time ./bench/scripts/gen_expandability_workload.sh small workloads
#time ./bench/scripts/run_expandability.sh small workloads disk
time ./bench/scripts/gen_expandability_workload.sh medium workloads
time ./bench/scripts/run_expandability.sh medium workloads disk
#time ./bench/scripts/gen_expandability_workload.sh large workloads
#time ./bench/scripts/run_expandability.sh large workloads disk
