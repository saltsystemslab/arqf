## Building external dependecies

```bash
# Fetch Submodules
$ git submodule update --init --recursive

# Build SplinterDB  (From https://github.com/vmware/splinterdb/blob/main/docs/build.md#full-build)
$ pushd
$ cd adaptiveqf/external/splinterdb
$ export COMPILER=gcc
$ export CC=$COMPILER
$ export LD=$COMPILER
$ make
$ popd

# Build WiredTiger
$ pushd
$ cd external/wiredtiger
$ mkdir build
$ cd build
$ cmake ../
$ make -j
$ popd

# Build 
$ mkdir release # Workload scripts hardcode the build directory to release
$ cd release
$ cmake -DCMAKE_BUILD_TYPE=Release ../
$ make bench_memento bench_arqf bench_adaptive_arqf_inmem bench_adaptive_arqf_splinterdb workload_gen
```

## Running tests

The below tests will run all the tests. The first is the standard FPR vs Bpk test with a zipfian query distribution. 

The second is an adversarial test that injects collected false positives at some frequency.

Both the below scripts run a small, medium and large test versions of the same test.

```bash
.$ /run_zipfian.sh
$ ./run_adversarial.sh
```

Use `bench/scripts/graph.ipynb` to plot the results.

## Code

The ARQF changes are implemented in `gqf.c`, `arqf.c` (splinterdb as reverse hash map)  and `arqf_inmem.cc` (`std::unordered_map` as reverse hash map).

TODO: Document out the exact changes, but you should be able to backtrack from `bench/filters_benchmark/bench_arqf.cpp`, `bench_adaptive_arqf_inmem.cpp` or `bench_adaptive_arqf_splinterdb.cpp`.
