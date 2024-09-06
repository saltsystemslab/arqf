## Zipfian Query Workload

```bash
$./bench/scripts/gen_zipfian_workload.sh large ./workload
$./bench/scripts/run_zipfian_workload.sh large ./workload
# use bench/scripts/graph.ipynb
```

#### Notes
* `memento` and `rqf` are filled to 0.90 load factor.
* `adaptivity_fpr` test is not complete (Might need to delete).
