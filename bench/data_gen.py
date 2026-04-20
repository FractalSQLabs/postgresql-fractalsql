#!/usr/bin/env python3
"""
bench/data_gen.py — Generate the synthetic "Island" dataset for the
head-to-head benchmark.

Creates N points in d dimensions, organized into K Gaussian clusters.
Cluster centers are placed uniformly in [-1, 1]^d; each point is sampled
from a Gaussian around its assigned center with per-component std=sigma.
Values are clipped to [-1, 1] so they fall within FractalSQL's default
search bounds.

Writes two tables:
    bench_vectors (id int, cluster_id int, emb vector(d), emb_arr float8[])
    bench_centers (cluster_id int, center_arr float8[])

Builds an HNSW index on bench_vectors.emb for the pgvector comparison
arm of the benchmark.

Usage:
    python3 bench/data_gen.py --dsn postgresql:///fractalsql_bench \\
        --n 100000 --dim 768 --clusters 50

Defaults are the brief: 100k / d=768 / 50 clusters.
"""

import argparse
import sys
import time

import numpy as np
import psycopg
from pgvector.psycopg import register_vector


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dsn", default="postgresql:///fractalsql_bench",
                    help="PG connection string (default: %(default)s)")
    ap.add_argument("--n", type=int, default=100_000,
                    help="number of points (default: %(default)s)")
    ap.add_argument("--dim", type=int, default=128,
                    help="vector dimension (default: %(default)s). Use --dim 768 "
                         "for realistic-embedding scale; note that HNSW index "
                         "build time and SFS fitness cost both scale linearly "
                         "with dim.")
    ap.add_argument("--clusters", type=int, default=50,
                    help="number of Gaussian clusters (default: %(default)s)")
    ap.add_argument("--sigma", type=float, default=0.05,
                    help="per-component std of intra-cluster noise "
                         "(default: %(default)s)")
    ap.add_argument("--seed", type=int, default=42,
                    help="RNG seed (default: %(default)s)")
    args = ap.parse_args()

    rng = np.random.default_rng(args.seed)

    print(f"Generating {args.n} points in R^{args.dim}, "
          f"{args.clusters} clusters, sigma={args.sigma}")
    t0 = time.perf_counter()

    # Cluster centers in [-1, 1]^dim.
    centers = rng.uniform(-1.0, 1.0, (args.clusters, args.dim))

    # Assign each point to a cluster, generate coords around the center,
    # and clip to the search box.
    labels  = rng.integers(0, args.clusters, size=args.n)
    noise   = rng.normal(0.0, args.sigma, (args.n, args.dim))
    vectors = np.clip(centers[labels] + noise, -1.0, 1.0)

    print(f"  generated in {time.perf_counter() - t0:.1f}s "
          f"({vectors.nbytes / 1e6:.1f} MB)")

    # ---- load into Postgres --------------------------------------------
    print(f"Connecting to {args.dsn} ...")
    with psycopg.connect(args.dsn, autocommit=True) as conn:
        conn.execute("CREATE EXTENSION IF NOT EXISTS vector;")
        conn.execute("CREATE EXTENSION IF NOT EXISTS fractalsql;")
        register_vector(conn)

        conn.execute("DROP TABLE IF EXISTS bench_vectors;")
        conn.execute("DROP TABLE IF EXISTS bench_centers;")
        conn.execute(f"""
            CREATE TABLE bench_vectors (
                id         int       PRIMARY KEY,
                cluster_id int       NOT NULL,
                emb        vector({args.dim}) NOT NULL,
                emb_arr    float8[]  NOT NULL
            );
        """)
        conn.execute(f"""
            CREATE TABLE bench_centers (
                cluster_id int       PRIMARY KEY,
                center_arr float8[]  NOT NULL
            );
        """)

        print(f"  inserting {args.clusters} cluster centers ...")
        with conn.cursor() as cur:
            cur.executemany(
                "INSERT INTO bench_centers VALUES (%s, %s)",
                [(i, centers[i].tolist()) for i in range(args.clusters)])

        print(f"  bulk-loading {args.n} vectors via COPY ...")
        t0 = time.perf_counter()
        # Text COPY — float format is simple and fast enough for this scale.
        # Using list representation for both vector and float8[] columns;
        # pgvector registers a text-out adapter that produces "[1,2,...]".
        with conn.cursor() as cur:
            with cur.copy("COPY bench_vectors (id, cluster_id, emb, emb_arr) "
                          "FROM STDIN WITH (FORMAT TEXT)") as copy:
                for i in range(args.n):
                    v = vectors[i]
                    # vector type's text input:   [1.23,4.56,...]
                    # float8[] type's text input: {1.23,4.56,...}
                    coords = ",".join(f"{x:.6f}" for x in v)
                    vec_lit = f"[{coords}]"
                    arr_lit = "{" + coords + "}"
                    copy.write_row((i, int(labels[i]), vec_lit, arr_lit))
        print(f"    COPY done in {time.perf_counter() - t0:.1f}s")

        print(f"  building HNSW index on emb ...")
        t0 = time.perf_counter()
        # Tuned down from defaults (m=16, ef_construction=64) to keep demo
        # build time reasonable at 100k rows. Production deployments should
        # tune up for better recall quality.
        conn.execute("CREATE INDEX bench_emb_hnsw ON bench_vectors "
                     "USING hnsw (emb vector_l2_ops) "
                     "WITH (m = 8, ef_construction = 32);")
        conn.execute("ANALYZE bench_vectors;")
        print(f"    index built in {time.perf_counter() - t0:.1f}s")

        n = conn.execute("SELECT count(*) FROM bench_vectors").fetchone()[0]
        k = conn.execute("SELECT count(*) FROM bench_centers").fetchone()[0]
        print(f"\nDone. bench_vectors={n} rows, bench_centers={k} rows")

    return 0


if __name__ == "__main__":
    sys.exit(main())
