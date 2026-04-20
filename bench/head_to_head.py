#!/usr/bin/env python3
"""
bench/head_to_head.py — HNSW vs FractalSQL Scout Mode.

Metrics
    Latency       Wall time per search, milliseconds.
    Island recall Distinct clusters (of K=50 Gaussian islands) represented
                  in the returned point set. A cluster is "discovered" if
                  at least one returned coordinate is nearest to that
                  cluster's center.

Evaluation is symmetric: for BOTH methods we take the returned coords
and map each one to its nearest cluster center. This treats HNSW-returned
stored vectors and SFS-returned free-floating particles with the same
labeling rule, so we're not giving either side an unfair advantage from
how it handles ground-truth labels.

Usage:
    python3 bench/head_to_head.py --dsn postgresql:///fractalsql_bench \\
        --n-queries 5 --top-k 50 --sfs-iter 8
"""

import argparse
import json
import sys
import time
from contextlib import contextmanager

import numpy as np
import psycopg
from pgvector.psycopg import register_vector


@contextmanager
def timed():
    """Yield a callable returning elapsed ms since entry."""
    t0 = time.perf_counter()
    yield lambda: (time.perf_counter() - t0) * 1000.0


def nearest_cluster(points: np.ndarray, centers: np.ndarray) -> np.ndarray:
    """
    For each point in `points` (N x D), return the index of its nearest
    center in `centers` (K x D). Uses the ||a - b||^2 = ||a||^2 + ||b||^2
    - 2 a.b identity, computed via matrix multiply.
    """
    # pn: (N,)   cn: (K,)   ab: (N, K)
    pn = (points  * points ).sum(axis=1, keepdims=True)   # (N, 1)
    cn = (centers * centers).sum(axis=1, keepdims=True).T # (1, K)
    ab = points @ centers.T                                # (N, K)
    d2 = pn + cn - 2.0 * ab
    return np.argmin(d2, axis=1)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dsn", default="postgresql:///fractalsql_bench")
    ap.add_argument("--n-queries", type=int, default=5,
                    help="number of queries to average over (default: %(default)s)")
    ap.add_argument("--top-k", type=int, default=50,
                    help="#returned points per method; also SFS population_size "
                         "(default: %(default)s)")
    ap.add_argument("--sfs-iter", type=int, default=8,
                    help="SFS generations (default: %(default)s)")
    ap.add_argument("--sfs-mdn", type=int, default=2,
                    help="SFS diffusion factor (default: %(default)s)")
    ap.add_argument("--hnsw-ef-search", type=int, default=40,
                    help="pgvector hnsw.ef_search (default: %(default)s)")
    ap.add_argument("--seed", type=int, default=1,
                    help="RNG seed for query selection (default: %(default)s)")
    args = ap.parse_args()

    with psycopg.connect(args.dsn, autocommit=True) as conn:
        register_vector(conn)
        conn.execute(f"SET hnsw.ef_search = {int(args.hnsw_ef_search)}")

        # ----- load centers into memory (K is small; ~300 KB) -----
        rows = conn.execute(
            "SELECT cluster_id, center_arr FROM bench_centers ORDER BY cluster_id"
        ).fetchall()
        centers = np.array([r[1] for r in rows], dtype=np.float64)
        K, dim = centers.shape
        n_total = conn.execute("SELECT count(*) FROM bench_vectors").fetchone()[0]

        print(f"Benchmark: {n_total} stored vectors, {K} clusters, dim={dim}")
        print(f"  HNSW: ef_search={args.hnsw_ef_search}, LIMIT {args.top_k}")
        print(f"  SFS : population={args.top_k}, iterations={args.sfs_iter}, "
              f"mdn={args.sfs_mdn}, walk=0.0 (Scout Mode)")
        print()

        # ----- pick queries: one per randomly chosen cluster, slightly noised -----
        rng = np.random.default_rng(args.seed)
        qci     = rng.integers(0, K, size=args.n_queries)
        queries = centers[qci] + rng.normal(0.0, 0.02, (args.n_queries, dim))
        queries = np.clip(queries, -1.0, 1.0)

        # ----- run ---------------------------------------------------------
        hdr = ("qi  anchor      |       HNSW ms   HNSW recall    |"
               "       SFS ms   SFS recall")
        print(hdr)
        print("-" * len(hdr))

        hnsw_ms_list, hnsw_recall_list = [], []
        sfs_ms_list,  sfs_recall_list  = [], []

        for qi in range(args.n_queries):
            q_anchor = int(qci[qi])
            q = queries[qi]
            q_vec   = q.astype(np.float32).tolist()
            q_fl8   = q.astype(np.float64).tolist()

            # -- HNSW top-K
            with timed() as clk:
                rows = conn.execute(
                    f"SELECT emb_arr "
                    f"FROM bench_vectors "
                    f"ORDER BY emb <-> %s::vector "
                    f"LIMIT {int(args.top_k)}",
                    (q_vec,)
                ).fetchall()
            hnsw_ms = clk()
            hnsw_pts = np.array([r[0] for r in rows], dtype=np.float64)
            hnsw_clusters = len(set(nearest_cluster(hnsw_pts, centers).tolist()))

            # -- FractalSQL Scout Mode
            opts = json.dumps({
                "population_size":   int(args.top_k),
                "iterations":        int(args.sfs_iter),
                "diffusion_factor":  int(args.sfs_mdn),
                "walk":              0.0,
            })
            with timed() as clk:
                rows = conn.execute(
                    "SELECT p FROM fractal_search_explore("
                    "    'bench_vectors', 'emb_arr', %s, %s::jsonb"
                    ") AS p",
                    (q_fl8, opts)
                ).fetchall()
            sfs_ms = clk()
            sfs_pts = np.array([r[0] for r in rows], dtype=np.float64)
            sfs_clusters = len(set(nearest_cluster(sfs_pts, centers).tolist()))

            hnsw_ms_list.append(hnsw_ms);  hnsw_recall_list.append(hnsw_clusters)
            sfs_ms_list.append(sfs_ms);    sfs_recall_list.append(sfs_clusters)

            print(f"{qi:2d}  cluster {q_anchor:3d} | "
                  f"{hnsw_ms:10.1f}   {hnsw_clusters:4d} / {K}     | "
                  f"{sfs_ms:10.1f}   {sfs_clusters:4d} / {K}")

        print()
        print("Averages over", args.n_queries, "queries:")
        print(f"  HNSW: {np.mean(hnsw_ms_list):>8.1f} ms   "
              f"recall {np.mean(hnsw_recall_list):>4.1f} / {K}")
        print(f"  SFS : {np.mean(sfs_ms_list):>8.1f} ms   "
              f"recall {np.mean(sfs_recall_list):>4.1f} / {K}")
        lat_ratio = np.mean(sfs_ms_list) / max(np.mean(hnsw_ms_list), 1e-9)
        rec_ratio = np.mean(sfs_recall_list) / max(np.mean(hnsw_recall_list), 1e-9)
        print(f"  SFS is {lat_ratio:.1f}x slower and discovers "
              f"{rec_ratio:.1f}x more distinct clusters")

    return 0


if __name__ == "__main__":
    sys.exit(main())
