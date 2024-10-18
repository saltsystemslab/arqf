#!/bin/bash

./bench/scripts/gen_expandability_workload.sh small workloads
./bench/scripts/run_expandability.sh small workloads disk
./bench/scripts/gen_expandability_workload.sh medium workloads
./bench/scripts/run_expandability.sh medium workloads disk
./bench/scripts/gen_expandability_workload.sh large workloads
./bench/scripts/run_expandability.sh large workloads disk
