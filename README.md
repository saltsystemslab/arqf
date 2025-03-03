# Aeris Filter

The Aeris filter, an Adaptive Expandable Range filter, is a range filter that dynamically resolves false positives. It is the first range filter to guarantee a bounded false positive rate for any query distribution, including skewed and adversarial where existing range filters exhibit unbounded false positive rates. Aeris supports efficient expansions and ensures monotonic adaptivity, meaning it never forgets a false positive. Built on the Memento filter—a fingerprint-based dynamic range filter—Aeris inherits its support for dynamic updates, constant-time operations, and robust false positive rate guarantees

# API

Refer to `./bench/filters_benchmark/bench_adaptive_arqf_splinterdb.cpp` for reference.

```cpp

//Initialization
data_config* data_cfg;
splinterdb_config* splinterdb_cfg;
splinterdb* db;
qf_init_splinterdb(&db, &data_cfg, &splinterdb_cfg, "rhm");
ARQF* arqf = (ARQF*)malloc(sizeof(ARQF));
arqf_init_with_rhm(arqf, db, n_slots, key_size, memento_bits, seed);

// Insert key
qf_insert_memento(arqf->qf, value, 0, &fingerprint);

// Query
result = qf_point_query(qf->qf, left, QF_NO_LOCK);
result = qf_range_query(qf->qf, left, right, QF_NO_LOCK);

// Adapt false positive query
arqf_adapt(qf, left, 0);
arqf_adapt_range(qf, left, right, 0);

```



## Test reproducibility

```bash
$ ./setup_tests.sh
$ ./run_tests small # Sanity check.
$ ./run_tests large
```

Use `bench/scripts/graph.ipynb` to plot the results.
