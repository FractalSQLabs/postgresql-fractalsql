# FractalSQL benchmark: HNSW vs Scout Mode

Head-to-head comparison of pgvector's HNSW index against FractalSQL's
`fractal_search_explore` (Scout Mode, `walk=0`). Measures search latency
and island recall on a synthetic Gaussian-cluster dataset.

## Prerequisites

- PostgreSQL 16 with `pgvector` and `fractalsql` installed
- Python 3.9+
- A database you can create/drop tables in (default DSN expects
  a database named `fractalsql_bench`)

## Setup

```bash
pip install -r bench/requirements.txt
createdb fractalsql_bench                # one-time, as a PG superuser
```

Verify both extensions are available:

```sql
CREATE EXTENSION vector;
CREATE EXTENSION fractalsql;
\dx
```

## Run the benchmark

```bash
make bench                               # data_gen + head_to_head
```

Or manually:

```bash
python3 bench/data_gen.py                # ~30–60s to populate 100k rows
python3 bench/head_to_head.py            # ~1–3 min for 5 queries
```

## What you should see

The output is a per-query table followed by an average:

```
qi  anchor      |       HNSW ms   HNSW recall    |       SFS ms   SFS recall
-------------------------------------------------------------------------
 0  cluster  12 |        3.2      1 / 50         |    18400.1    28 / 50
 1  cluster   7 |        2.8      1 / 50         |    18100.4    31 / 50
...

Averages over 5 queries:
  HNSW:      3.0 ms   recall  1.0 / 50
  SFS :  18200.0 ms   recall 29.4 / 50
  SFS is 6000x slower and discovers 29x more distinct clusters
```

The shape of the result will vary run to run, but the pattern is robust:
HNSW finds ~1–2 clusters at millisecond latency; Scout Mode finds 20–35
clusters at multi-second latency. This is the intended comparison —
different algorithms solving different problems.

## Scaling notes

The SFS fitness is `min over stored_set of ||candidate - v||²`, evaluated
brute-force. Per-fitness cost is O(N × D), and SFS makes ~2500 evaluations
in a population=50, iterations=8 run. That scales linearly with the
stored-set size:

| N (stored vectors) | Approx per-query SFS time at d=768 |
| ------------------ | ---------------------------------- |
| 10 000             |   2–5 seconds                      |
| 100 000 (default)  |  20–60 seconds                     |
| 1 000 000          |   3–10 minutes                     |

HNSW is approximately N-independent in comparison. For production use
beyond ~100k vectors, a future version of `fractal_search_explore`
could use an approximate-NN index internally for fitness lookups. For
now, Scout Mode is best applied to curated sub-corpora where diversity
matters more than scan throughput.

## Tuning

`head_to_head.py` exposes a few knobs:

```
--n-queries        number of queries to average (default 5)
--top-k            #results per method, also SFS population_size (50)
--sfs-iter         SFS generations (default 8)
--sfs-mdn          diffusion factor (default 2)
--hnsw-ef-search   pgvector search quality (default 40)
--seed             query-selection RNG seed
```

`data_gen.py` exposes the dataset shape:

```
--n        total points (default 100000)
--dim      vector dimension (default 768)
--clusters number of Gaussian islands (default 50)
--sigma    intra-cluster std (default 0.05)
```
