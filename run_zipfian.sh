#!/bin/bash

./bench/scripts/gen_zipfian_workload.sh small workloads
./bench/scripts/run_zipfian.sh small workloads disk
./bench/scripts/gen_zipfian_workload.sh medium workloads
./bench/scripts/run_zipfian.sh medium workloads disk
./bench/scripts/gen_zipfian_workload.sh large workloads
./bench/scripts/run_zipfian.sh large workloads disk
