#!/bin/bash

git submodule update --init --recursive

# Build SplinterDB  (From https://github.com/vmware/splinterdb/blob/main/docs/build.md#full-build)
pushd .
cd adaptiveqf/external/splinterdb
export COMPILER=gcc
export CC=$COMPILER
export LD=$COMPILER
make
popd

# Build WiredTiger
pushd .
cd external/wiredtiger
mkdir build
cd build
cmake ../ -DBUILD_TYPE=Release -DENABLE_PYTHON=OFF
make -j
popd

#Build 
pushd .
mkdir release # Workload scripts hardcode the build directory to release
cd release
cmake -DCMAKE_BUILD_TYPE=Release ../
make bench_arqf bench_memento bench_adaptive_arqf_inmem bench_adaptive_arqf_splinterdb bench_snarf bench_surf bench_grafite workload_gen
popd

# Download datasts
bash ./bench/scripts/download_datasets.sh
