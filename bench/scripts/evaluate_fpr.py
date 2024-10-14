import mmh3
import pandas as pd
import numpy as np

def measure_fpr_point(filter, queries, q, r, m):
  filter = {}
  for item in items:
    memento = item & ((1<<m)-1)
    prefix = item >> m
    prefix_hash = mmh3.hash(int(prefix).to_bytes(32, 'big'))
    fingerprint = prefix_hash & ((1 << (q+r))-1)
    if fingerprint not in filter:
      filter[fingerprint] = set()
    filter[fingerprint].add(memento)

  fingerprint_collisions = 0
  memento_collisions_after_fp_collision = 0
  overall_false_positives = 0
  true_queries = 0

  for query in queries:
    if query in items:
      true_queries += 1
      continue # ignore true positives
    memento = query & ((1<<m)-1)
    prefix = query >> m
    prefix_hash = mmh3.hash(int(prefix).to_bytes(32, 'big'))
    fingerprint = prefix_hash & ((1 << (q+r))-1)
    if fingerprint in filter:
      fingerprint_collisions += 1
      if memento in filter[fingerprint]:
        memento_collisions_after_fp_collision += 1
        overall_false_positives += 1

  return {
    'q': q,
    'r': r,
    'm': m,
    'fingerprint_collisions': fingerprint_collisions, 
    'memento_collisions': memento_collisions_after_fp_collision, 
    'false_positives': overall_false_positives,
    'overall_queries': len(queries),
    'true_queries': true_queries
  }

def measure_fpr_range(filter, queries, q, r, m, l=32):
  filter = {}
  for item in items:
    memento = item & ((1<<m)-1)
    prefix = item >> m
    prefix_hash = mmh3.hash(int(prefix).to_bytes(32, 'big'))
    fingerprint = prefix_hash & ((1 << (q+r))-1)
    if fingerprint not in filter:
      filter[fingerprint] = set()
    filter[fingerprint].add(memento)

  fingerprint_collisions = 0
  memento_collisions_after_fp_collision = 0
  overall_false_positives = 0
  filter_queries = 0
  true_queries = 0

  for query in queries:
    left = query
    right = query + l

    l_memento = left & ((1<<m)-1)
    l_prefix = left >> m
    l_prefix_hash = mmh3.hash(int(l_prefix).to_bytes(32, 'big'))
    l_fingerprint = l_prefix_hash & ((1 << (q+r))-1)

    r_memento = right & ((1<<m)-1)
    r_prefix = right >> m
    r_prefix_hash = mmh3.hash(int(r_prefix).to_bytes(32, 'big'))
    r_fingerprint = r_prefix_hash & ((1 << (q+r))-1)
    
    is_fp = False

    if l_prefix == r_prefix:
        filter_queries += 1
        if l_fingerprint in filter:
            fingerprint_collisions += 1
            for memento in filter[fingerprint]:
                if memento >= l_memento and memento <= r_memento:
                    memento_collisions_after_fp_collision += 1
                    overall_false_positives += 1
                    is_fp = True
                    break

    filter_queries += 1
    if l_fingerprint in filter:
      fingerprint_collisions += 1
      for memento in filter[fingerprint]:
          if memento >= l_memento:
            memento_collisions_after_fp_collision += 1
            is_fp = True
            break


    filter_queries += 1
    if r_fingerprint in filter:
      fingerprint_collisions += 1
      for memento in filter[fingerprint]:
          if memento <= r_memento:
            memento_collisions_after_fp_collision += 1
            is_fp = True
            break

    if is_fp:
        overall_false_positives += 1

  return {
    'q': q,
    'r': r,
    'm': m,
    'l': l,
    'fingerprint_collisions': fingerprint_collisions, 
    'memento_collisions': memento_collisions_after_fp_collision, 
    'filter_queries': filter_queries,
    'false_positives': overall_false_positives,
    'overall_queries': len(queries),
  }

U = 2**32
q = 20
r = 4
m = 0
items = set(np.random.random_integers(low=0, high=U, size=2**q))
queries = set(np.random.random_integers(low=0, high=U, size=10000000))

fpr = measure_fpr_range(items, queries, q=q, r=r, m=5, l=32)
print(fpr)
fpr = measure_fpr_range(items, queries, q=q, r=r, m=10, l=1024)
print(fpr)

print(f'q={q}, r={r}')

table = []

for m in range(0, 5):
    fpr = measure_fpr_point(items, queries, q=q, r=r, m=m)
    table.append(fpr)

print("False positive rate (Point Queries)")

df = pd.DataFrame(table)
df['expected_fingerprint_collision (2^-r)'] = 1 / (2**df['r'])
df['actual_fingerprint_collision'] = df['fingerprint_collisions']/ (df['overall_queries']-df['true_queries'])
print(df[['q', 'r', 'm', 'expected_fingerprint_collision (2^-r)', 'actual_fingerprint_collision']].to_markdown())

df['expected_memento_collision (2^-m)'] = 1 / (2**df['m'])
df['actual_memento_collision'] = df['memento_collisions']/ (df['fingerprint_collisions'])
print("Memento Collision, given fingerprint collision has happened")
print(df[['q', 'r', 'm', 'expected_memento_collision (2^-m)', 'actual_memento_collision']].to_markdown())

df['expected_overall_fpr (2^-(r+m))'] = 1 / (2**(df['r'] + df['m']))
df['actual_overall_fpr'] = df['false_positives']/ (df['overall_queries']-df['true_queries'])
print("False positive rate")
print(df[['q', 'r', 'm', 'expected_overall_fpr (2^-(r+m))', 'actual_overall_fpr']].to_markdown())

print("False positive rate (Range Queries)")

table = []
for m in range(2, 6):
    fpr = measure_fpr_range(items, queries, q=q, r=r, m=m, l=2**m)
    table.append(fpr)

# TODO(chesetti): For range queries, remove the true queries.
df = pd.DataFrame(table)
df['expected_fingerprint_collision (2^-r)'] = 1 / (2**df['r'])
df['actual_fingerprint_collision'] = df['fingerprint_collisions']/ (df['filter_queries'])
print(df[['q', 'r', 'm', 'expected_fingerprint_collision (2^-r)', 'actual_fingerprint_collision']].to_markdown())

df['expected_memento_collision (2^-1)'] = 0.5 # 1 / (2**df['m'])
df['actual_memento_collision'] = df['memento_collisions']/ (df['fingerprint_collisions'])
print("Memento Collision, given fingerprint collision has happened")
print(df[['q', 'r', 'm', 'expected_memento_collision (2^-1)', 'actual_memento_collision']].to_markdown())

df['expected_overall_fpr (2^-r)'] = 1 / (2**(df['r']))
df['actual_overall_fpr'] = df['false_positives']/ (df['overall_queries'])
print("False positive rate")
print(df[['q', 'r', 'm', 'expected_overall_fpr (2^-r)', 'actual_overall_fpr']].to_markdown())
