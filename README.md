<p align="center">
  <img src="FractalSQLforPostgreSQL.jpg" alt="FractalSQL for PostgreSQL" width="720">
</p>

# postgresql-fractalsql by FractalSQLabs

**Beyond Vector Search: A Two-Mode Discovery Engine for PostgreSQL.**

## Production Ready

- **Multi-PG**: native builds for **PostgreSQL 14, 15, 16, 17, and 18**,
  each compiled against the matching `postgresql-server-dev-*` so
  `PG_MODULE_MAGIC` lines up with the target server.
- **Multi-arch**: first-class support for **AMD64 / x86_64** and
  **ARM64 / aarch64** — AWS Graviton (EC2, RDS on Graviton hosts),
  Apple Silicon development, Ampere Altra, Raspberry Pi class boards.
- **Multi-OS**: native `.deb` / `.rpm` for Linux (amd64 + arm64), plus
  signed-ready `.msi` installers for **Windows x64** across all five
  PG majors. Windows ARM64 coverage is planned for a follow-up release
  once upstream EDB Windows ARM64 publishing stabilises.
- **Minimum glibc 2.38** — aligned with Ubuntu 24.04 LTS / Debian 13
  and any RHEL-family distro shipping glibc 2.34+.

## Compatibility matrix

| PostgreSQL | Linux `.deb` / `.rpm` (amd64) | Linux (arm64) | Windows x64 |
| --- | :---: | :---: | :---: |
| 14 | ✓ | ✓ | ✓ |
| 15 | ✓ | ✓ | ✓ |
| 16 | ✓ | ✓ | ✓ |
| 17 | ✓ | ✓ | ✓ |
| 18 | ✓ | ✓ | ✓ |

Package-name patterns:

- Linux: `postgresql-<PG>-fractalsql-<arch>.{deb,rpm}`
- Windows: `FractalSQL-PostgreSQL-<PG>-<VERSION>-x64.msi`

Because PG extensions hard-depend on `PG_MODULE_MAGIC`, a binary
compiled for one major refuses to load under any other. Install the
package matching your server's major. Windows ARM64 is not shipped
in v1.0.0 — EDB publishes Windows ARM64 PostgreSQL as an interactive
`.exe` installer only (no `-binaries.zip` variant), and the silent
extraction plumbing to harvest `postgres.lib` from it is deferred to
a later release.

---


Most vector databases give you one tool: find the `k` stored points
nearest to a query. That's the right answer when the question is *"what
is most similar?"* — and the wrong answer when the question is *"what
interesting regions of my data should I be looking at?"*

FractalSQL ships **two modes** in a single extension, built around the
Stochastic Fractal Search metaheuristic running in LuaJIT inside the
Postgres backend:

| Mode | Function | What it's for |
| --- | --- | --- |
| **Sniper Search** | `fractal_search` | High-precision convergence to the single best point |
| **Scout Discovery** | `fractal_search_explore` | Diverse exploration returning N scouts from distinct data basins |

Same algorithm. Two parameter regimes. One build.

---

## Mode 1: Sniper Search

**When to use it:** you have a query, you want the best match, you're
willing to trade some latency for a solution that isn't constrained to
the stored set.

```sql
SELECT fractal_search(
    ARRAY[0.6, 0.8, 0.0]::float8[],
    iterations       => 100
);
-- → {0.600, 0.800, 2.3e-06}
```

Sniper Search uses SFS's diffusion step in its canonical form (`walk=0.5`):
candidates are drawn around a tracked global best, and the population
converges tightly. The output is a continuous point in R^d that
minimizes your objective — not necessarily one of your stored vectors.

## Mode 2: Scout Discovery

**When to use it:** you have a corpus, you want to see its *structure* —
which basins of attraction it contains, what distinct regions a RAG
retriever ought to consider, where the modes of your embedding
distribution sit.

```sql
SELECT p FROM fractal_search_explore(
    'my_embeddings',        -- table
    'emb_arr',              -- float8[] column
    ARRAY[...]::float8[],   -- query (reserved; doesn't constrain fitness)
    '{"population_size": 50, "iterations": 8, "walk": 0}'::jsonb
) AS p;
-- → 50 rows, each a float8[], each sitting in a different data basin
```

Scout Discovery uses `walk=0`: diffusion always draws around the
particle's own source, never the global best. The 50 "scouts" descend
independently into whichever local minimum they started closest to.
The result is a set of coordinates that **covers the data landscape**
instead of collapsing to the single nearest cluster.

### Why this matters for RAG

Standard retrievers have a well-known failure mode: given a query,
cosine top-K returns K results that are mutually very similar to each
other. Your LLM then reasons over K near-duplicates and produces
narrow, one-dimensional answers. This is **mode collapse**, and it's
what makes RAG pipelines fragile to queries that require synthesizing
across multiple perspectives.

Scout Discovery is designed to slot into the retrieval step as a
**diversity layer**: either as a complement to vector search (take top-K
from HNSW, add top-N scouts from SFS) or as a standalone stage for
"give me an ensemble that spans the corpus." The 50 returned particles
live in different regions by construction, so whatever downstream
reasoning you do starts from genuine variety.

---

## Benchmark: HNSW vs Scout Discovery

Real output from `make bench` on 100 000 vectors in R^128 organized into
50 Gaussian clusters. Each method returns 50 results; we measure how
many of the 50 clusters are represented.

```
qi  anchor      |       HNSW ms   HNSW recall    |       SFS ms   SFS recall
----------------------------------------------------------------------------
 0  cluster  23 |       13.2      1 / 50         |    16931.3    22 / 50
 1  cluster  25 |       11.1      1 / 50         |    16196.0    24 / 50
 2  cluster  37 |       31.7      1 / 50         |    18169.0    21 / 50
 3  cluster  47 |       32.2      1 / 50         |    17939.3    19 / 50
 4  cluster   1 |       59.3      1 / 50         |    18298.4    22 / 50

Averages over 5 queries:
  HNSW:     29.5 ms   recall  1.0 / 50
  SFS :  17506.8 ms   recall 21.6 / 50
  SFS is 593x slower and discovers 21x more distinct clusters
```

The pattern is stable across seeds: **HNSW finds exactly one cluster
per query**. Its top-50 neighbors are all from the same basin as the
query, because that's what top-K proximity search is supposed to do.
**Scout Discovery finds 20–25 distinct clusters per query**. No single
basin dominates the population because `walk=0` removes the
cross-particle best-pull.

The latency gap is real and reflects the different workloads. HNSW
answers a graph-traversal question in milliseconds; SFS solves a
continuous optimization problem with thousands of fitness evaluations,
each of which scans the stored set. This is not the same workload
done faster or slower — it's a different workload entirely.

**Reproduce:** `make bench` runs end-to-end in ~3 minutes on a typical
laptop (fitness cost scales linearly with `N × d`; see
`bench/README.md` for the scaling table).

---

## Architectural Performance

The core optimizer is distributed as **pre-compiled LuaJIT bytecode**
embedded in the shared library. No Lua source ships with the
extension.

### No script parsing at runtime

A conventional LuaJIT embedding loads source, invokes the parser, and
generates bytecode before the first opcode executes. FractalSQL skips
all of this: the bytecode is compiled once at release time and embedded
in `fractalsql.so` as a C byte array. Loading the optimizer on the
first SQL call is a `luaL_loadbuffer` over an in-memory buffer — no
tokenizer, no parser, no AST walk. Combined with per-backend caching of
the initialized Lua state, the parse cost is paid once per backend, not
per query.

### FFI hot loops

Both modes use pre-allocated `double[]` FFI cdata buffers for every
per-generation computation. The inner loops — fitness evaluation,
diffusion walks, bound checking — JIT-compile to tight machine code
comparable to hand-written C. The population itself and all scratch
buffers are allocated once per SFS run and reused across generations.

---

## Installation

### From the release packages (recommended)

Grab the `.deb` or `.rpm` matching your PostgreSQL major AND your CPU
arch from [GitHub Releases](https://github.com/FractalSQLabs/postgresql-fractalsql/releases).

```bash
# Debian / Ubuntu — pick the filename matching your PG major + arch:
#   postgresql-{14,15,16,17,18}-fractalsql-{amd64,arm64}.deb

sudo apt install ./postgresql-17-fractalsql-arm64.deb   # e.g. PG 17 on Graviton

# RHEL / Fedora / Oracle Linux — same naming, .rpm extension
sudo rpm -i postgresql-17-fractalsql-arm64.rpm
```

Each package drops `fractalsql.so` into
`/usr/lib/postgresql/<VER>/lib/` and the control + SQL scripts into
`/usr/share/postgresql/<VER>/extension/` (the RPM uses the matching
`/usr/pgsql-<VER>/...` layout). Activate the extension once:

```bash
sudo -u postgres psql -c "CREATE EXTENSION fractalsql;"
```

### Windows (MSI)

Grab the MSI matching your PG major **and** your CPU arch from
[GitHub Releases](https://github.com/FractalSQLabs/postgresql-fractalsql/releases).
Filename pattern:

```
FractalSQL-PostgreSQL-<PG_MAJOR>-<VERSION>-<ARCH>.msi
```

e.g. `FractalSQL-PostgreSQL-17-1.0.0-x64.msi` for PG 17 on Windows x64.

```powershell
# Interactive install (Welcome → EULA → folder picker → Ready).
msiexec /i FractalSQL-PostgreSQL-17-1.0.0-x64.msi

# Silent install into EDB's default PG root (C:\Program Files\PostgreSQL\17\).
msiexec /i FractalSQL-PostgreSQL-17-1.0.0-x64.msi /qn

# Silent install into a custom PG install root.
msiexec /i FractalSQL-PostgreSQL-17-1.0.0-x64.msi /qn PGROOT="D:\PostgreSQL\17"
```

The MSI drops:

```
<PG_ROOT>\lib\fractalsql.dll
<PG_ROOT>\share\extension\fractalsql.control
<PG_ROOT>\share\extension\fractalsql--1.0.sql
<PG_ROOT>\share\doc\fractalsql\{LICENSE, LICENSE-THIRD-PARTY, README.txt}
```

Restart the PostgreSQL Windows service (or the backend connection)
and activate:

```powershell
& "C:\Program Files\PostgreSQL\17\bin\psql.exe" -U postgres `
    -c "CREATE EXTENSION fractalsql;"
```

The Windows build statically links LuaJIT and the MSVC C runtime
(`/MT /GL`) — no separate Visual C++ Redistributable install required,
no `lua51.dll` dependency.

### Building from source

The canonical build is Docker-driven and emits one `.so` per PG major
per target architecture:

```bash
./build.sh amd64   # -> dist/amd64/fractalsql_pg{14,15,16,17,18}.so
./build.sh arm64   # -> dist/arm64/fractalsql_pg{14,15,16,17,18}.so
```

The Dockerfile (`docker/Dockerfile`) uses five independent build
stages — `postgres:14-bookworm`, `postgres:15-bookworm`,
`postgres:16-bookworm`, `postgres:17-bookworm`, `postgres:18-bookworm`
— so each `.so`'s `PG_MODULE_MAGIC` matches the target server's ABI
exactly. Cross-arch builds use buildx + QEMU; CI runs both arches on
every tag.

For quick local iteration against your installed PG:

```bash
sudo apt install -y build-essential postgresql-server-dev-all \
                    libluajit-5.1-dev pkg-config

make PG_CONFIG=/usr/lib/postgresql/17/bin/pg_config
sudo make install PG_CONFIG=/usr/lib/postgresql/17/bin/pg_config
sudo -u postgres psql -c "CREATE EXTENSION fractalsql;"
```

**Runtime requirements.** LuaJIT 2.1 with FFI enabled (default in
Ubuntu/Debian). `pgvector` is required only for the benchmark harness
(which compares against HNSW); the core extension does not depend on
it.

---

## API reference

### `fractal_search(query, iterations, population_size, diffusion_factor) → float8[]`

Sniper Mode. Returns the best point found minimizing cosine distance
to `query` over the unit box `[-1, 1]^dim`.

| Arg | Default | Range | Notes |
| --- | --- | --- | --- |
| `iterations` | 30 | 1–100 000 | SFS generations |
| `population_size` | 50 | 2–10 000 | Points in the population |
| `diffusion_factor` | 2 | 1–100 | SFS MDN (walk-per-particle count) |

Uses `walk=0.5` internally (canonical SFS; best-pull enabled).

### `fractal_search_explore(table, vector_col, query, options) → SETOF float8[]`

Scout Mode. Scans `table.vector_col` (a `float8[]` column) once, loads
it into a contiguous buffer, and runs SFS with a min-distance-to-any-
stored-vector fitness. Returns the final population as one row per
particle.

| Option (jsonb key) | Default | Notes |
| --- | --- | --- |
| `iterations` | 15 | SFS generations |
| `population_size` | 50 | Also the number of returned rows |
| `diffusion_factor` | 2 | SFS MDN |
| `walk` | 0.0 | Scout default. Set to 0.5 for convergent behavior. |

### `fractal_search_debug(...) → jsonb`

Sniper Mode with full particle trajectory. Same signature as
`fractal_search`; returns a JSONB document with
`best_fit_per_gen` and per-generation particle positions. Useful for
generating animations or diagnosing non-convergence.

---

## pgvector integration

FractalSQL does not hard-link pgvector at build time. Scout Mode scans
`float8[]` columns; to feed pgvector-stored embeddings through,
cast at the SQL level:

```sql
-- generated column approach
ALTER TABLE my_embeddings
ADD COLUMN emb_arr float8[]
GENERATED ALWAYS AS (emb::real[]::double precision[]) STORED;

CREATE INDEX ON my_embeddings USING hnsw (emb vector_l2_ops);

-- now both methods coexist
SELECT id FROM my_embeddings ORDER BY emb <-> $1::vector LIMIT 50;
SELECT p FROM fractal_search_explore(
    'my_embeddings', 'emb_arr', $2::float8[], '{}'::jsonb
) AS p;
```

The `STORED` generated column doubles the storage footprint but gives
you both HNSW and SFS paths off the same underlying embeddings.

---

## Scaling notes

Scout Mode's fitness is `min over N_stored of ||x - v||²`, evaluated
brute-force in pure Lua. Per-fitness cost is O(N × d), and a
population=50, iterations=8 run makes ~2500 evaluations.

| N (stored vectors) | Approx per-query SFS time at d=128 |
| ------------------ | ---------------------------------- |
| 10 000             | <1 second                          |
| 100 000 (demo)     | 15–20 seconds                      |
| 1 000 000          | 2–4 minutes                        |

HNSW is approximately N-independent. For production Scout Mode use at
>100k vectors, a future version could back fitness with an
approximate-NN index — if you have this need, open an issue.

---

## Architecture notes

**One Lua state per backend.** Lazy-initialized on first SQL call;
torn down in `_PG_fini`. All FFI buffers allocated inside the optimizer
are GC'd when the Lua function returns — no persistent allocations
cross the PG call boundary.

**Batch loading.** Scout Mode issues a single SPI `SELECT` per call
and loads the entire column into a contiguous double buffer (palloc in
the query context). The buffer is handed to Lua as a `lightuserdata`
pointer; the fitness closure casts it back to `double*` with zero
copying. Memory is released automatically when the function call ends.

**Determinism.** LuaJIT's `math.random` is xoshiro256\*\*. Results are
reproducible within a backend when you pin `population_size` and an
explicit seed.

---

## License

MIT. See `LICENSE`.

---

## Third-Party Components

FractalSQL is licensed under the MIT License.

This project incorporates third-party components, including:

- **SFS (Simultaneous Fractal Search)** algorithms based on work by
  Hamid Salimi (2014), used under the BSD-3-Clause License.
- **LuaJIT**, used under the MIT License.

Full attribution and license texts can be found in
[`LICENSE-THIRD-PARTY`](LICENSE-THIRD-PARTY).

---

[github.com/FractalSQLabs](https://github.com/FractalSQLabs) · Issues and
PRs welcome.
