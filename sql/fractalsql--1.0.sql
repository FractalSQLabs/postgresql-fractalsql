-- sql/fractalsql--1.0.sql
\echo Use "CREATE EXTENSION fractalsql" to load this file. \quit

CREATE FUNCTION fractal_search(
    query            float8[],
    iterations       int4 DEFAULT 30,
    population_size  int4 DEFAULT 50,
    diffusion_factor int4 DEFAULT 2
) RETURNS float8[]
AS 'MODULE_PATHNAME', 'fractal_search'
LANGUAGE C VOLATILE STRICT;

COMMENT ON FUNCTION fractal_search(float8[], int4, int4, int4) IS
  'Stochastic Fractal Search (minimizing cosine distance to query). '
  'Returns the best point found in the unit box [-1, 1]^dim.';

CREATE FUNCTION fractal_search_debug(
    query            float8[],
    iterations       int4 DEFAULT 30,
    population_size  int4 DEFAULT 50,
    diffusion_factor int4 DEFAULT 2
) RETURNS jsonb
AS 'MODULE_PATHNAME', 'fractal_search_debug'
LANGUAGE C VOLATILE STRICT;

COMMENT ON FUNCTION fractal_search_debug(float8[], int4, int4, int4) IS
  'Like fractal_search, but returns a JSONB document with per-generation '
  'particle positions for visualization. Keys: dim, generations, '
  'population_size, best_point, best_fit, best_fit_per_gen, paths.';

CREATE FUNCTION fractal_search_explore(
    table_name  text,
    vector_col  text,
    query       float8[],
    options     jsonb DEFAULT '{}'::jsonb
) RETURNS SETOF float8[]
AS 'MODULE_PATHNAME', 'fractal_search_explore'
LANGUAGE C VOLATILE STRICT;

COMMENT ON FUNCTION fractal_search_explore(text, text, float8[], jsonb) IS
  'Diversity-mode SFS: scans table_name.vector_col once, then runs SFS '
  'with a min-distance-to-any-stored-vector fitness. Returns all N '
  'particles of the final population as SETOF float8[] — intended for '
  'discovering distinct basins of attraction (clusters) in the stored '
  'embedding distribution. Options (jsonb): iterations, population_size, '
  'diffusion_factor, walk. Defaults: 15 / 50 / 2 / 0.0 (walk=0 disables '
  'best-pull for diversity).';

CREATE FUNCTION fractalsql_edition() RETURNS text
AS 'MODULE_PATHNAME', 'fractalsql_edition'
LANGUAGE C IMMUTABLE STRICT;

COMMENT ON FUNCTION fractalsql_edition() IS
  'Returns the FractalSQL edition string (e.g. ''Community'').';

CREATE FUNCTION fractalsql_version() RETURNS text
AS 'MODULE_PATHNAME', 'fractalsql_version'
LANGUAGE C IMMUTABLE STRICT;

COMMENT ON FUNCTION fractalsql_version() IS
  'Returns the FractalSQL extension version (e.g. ''1.0.0'').';
