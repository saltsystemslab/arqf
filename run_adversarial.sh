#!/bin/bash

./bench/scripts/gen_uniform_workload.sh small workloads
./bench/scripts/run_adversarial.sh small workloads disk
./bench/scripts/gen_uniform_workload.sh medium workloads
./bench/scripts/run_adversarial.sh medium workloads disk
./bench/scripts/gen_uniform_workload.sh large workloads
./bench/scripts/run_adversarial.sh large workloads disk
