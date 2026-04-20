/* src/fractalsql.c
 * FractalSQL v1.0 — Stochastic Fractal Search for PostgreSQL via LuaJIT.
 *
 * Architecture
 *   * One Lua state per backend, lazy-initialized on first SQL call.
 *   * The LuaJIT optimizer core is compiled to stripped bytecode at
 *     release time (luajit -b -s) and embedded as a C array via
 *     include/sfs_core_bc.h. The loaded .so contains only stripped
 *     bytecode, no Lua source.
 *   * Module table pinned in Lua registry for O(1) access per call.
 *
 * SQL surface
 *   fractal_search(query float8[],
 *                  iterations       int4 DEFAULT 30,
 *                  population_size  int4 DEFAULT 50,
 *                  diffusion_factor int4 DEFAULT 2)
 *     -> float8[]
 *
 *   fractal_search_debug(query float8[], ...)
 *     -> jsonb           (best_point, best_fit, per-gen best, particle paths)
 *
 *   fractal_search_explore(table_name text, vector_col text,
 *                          query float8[], options jsonb)
 *     -> SETOF float8[]  (final population of N diverse particles)
 *
 * Memory
 *   All FFI buffers are allocated inside the Lua function body and
 *   garbage-collected when it returns. Between PG backend restarts,
 *   _PG_fini calls lua_close which tears down the entire state.
 *   No persistent allocations cross the call boundary.
 *
 * fractal_search_explore batch-loading
 *   The target table column is scanned once via SPI and loaded into a
 *   contiguous double[] buffer in the call's palloc context. A
 *   lightuserdata pointer to that buffer is handed to Lua; the
 *   diversity_fitness closure casts it back to double* with zero copy.
 *   The buffer stays valid for the duration of the PG function call,
 *   which spans the entire SFS run.
 */

#include "postgres.h"
#include "fmgr.h"
#include "funcapi.h"
#include "miscadmin.h"
#include "access/htup_details.h"
#include "catalog/pg_type.h"
#include "executor/spi.h"
#include "utils/array.h"
#include "utils/builtins.h"
#include "utils/jsonb.h"
#include "utils/memutils.h"

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <luajit.h>

#include "sfs_core_bc.h"   /* luaJIT_BC_fractalsql_community[] + _SIZE */

#define FRACTALSQL_EDITION "Community"
#define FRACTALSQL_VERSION "1.0.0"

PG_MODULE_MAGIC;

void _PG_init(void);
void _PG_fini(void);

/* Forward declarations for SQL-callable functions are emitted by the
 * PG_FUNCTION_INFO_V1 macro below, with PGDLLEXPORT on platforms that
 * need it (Windows / MSVC). Declaring them again here without
 * PGDLLEXPORT provokes MSVC C2375 ("different linkage"); on GCC it
 * was silently tolerated. Rely on the macro's implicit forward decl. */

/* ------------------------------------------------------------------ */
/* Per-backend Lua state                                              */
/* ------------------------------------------------------------------ */

static lua_State *g_L = NULL;
static int        g_module_ref = LUA_NOREF;

static int
l_panic(lua_State *L)
{
    const char *msg = lua_tostring(L, -1);
    ereport(ERROR,
            (errcode(ERRCODE_INTERNAL_ERROR),
             errmsg("LuaJIT panic: %s", msg ? msg : "(unknown)")));
    return 0;  /* unreachable; ereport longjmps */
}

static void
ensure_lua(void)
{
    int rc;

    if (g_L != NULL)
        return;

    g_L = luaL_newstate();
    if (g_L == NULL)
        ereport(ERROR,
                (errcode(ERRCODE_OUT_OF_MEMORY),
                 errmsg("could not allocate LuaJIT state")));
    lua_atpanic(g_L, l_panic);
    luaL_openlibs(g_L);

    /* Load embedded stripped bytecode. Chunk name "=sfs_core" skips the
     * default "[string ...]" wrapping in tracebacks. */
    rc = luaL_loadbuffer(g_L,
                         (const char *) luaJIT_BC_fractalsql_community,
                         luaJIT_BC_fractalsql_community_SIZE,
                         "=sfs_core");
    if (rc != 0) {
        const char *msg = lua_tostring(g_L, -1);
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("loading sfs_core bytecode: %s", msg ? msg : "?")));
    }

    rc = lua_pcall(g_L, 0, 1, 0);
    if (rc != 0) {
        const char *msg = lua_tostring(g_L, -1);
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("initializing sfs_core: %s", msg ? msg : "?")));
    }

    g_module_ref = luaL_ref(g_L, LUA_REGISTRYINDEX);
}

void
_PG_init(void)
{
    /* Keep backend startup light. Lua state is built on first call. */
}

void
_PG_fini(void)
{
    if (g_L != NULL) {
        lua_close(g_L);  /* releases every cdata buffer created in run() */
        g_L = NULL;
        g_module_ref = LUA_NOREF;
    }
}

/* ------------------------------------------------------------------ */
/* Array <-> Lua table helpers                                        */
/* ------------------------------------------------------------------ */

static void
push_float8_array_as_table(lua_State *L, ArrayType *arr, int *out_n)
{
    Datum *ds;
    bool  *nulls;
    int    n, i;

    if (ARR_NDIM(arr) != 1)
        ereport(ERROR,
                (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR),
                 errmsg("fractal_search: expected 1-dimensional array")));

    deconstruct_array(arr, FLOAT8OID, 8, FLOAT8PASSBYVAL, 'd',
                      &ds, &nulls, &n);

    lua_createtable(L, n, 0);
    for (i = 0; i < n; i++) {
        if (nulls[i])
            ereport(ERROR,
                    (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
                     errmsg("fractal_search: vector must not contain NULLs")));
        lua_pushnumber(L, DatumGetFloat8(ds[i]));
        lua_rawseti(L, -2, i + 1);
    }

    if (out_n) *out_n = n;
}

static ArrayType *
build_float8_array_from_table(lua_State *L, int t_index, int n)
{
    Datum *elems = palloc(sizeof(Datum) * n);
    int    i;

    for (i = 0; i < n; i++) {
        lua_rawgeti(L, t_index, i + 1);
        elems[i] = Float8GetDatum(lua_tonumber(L, -1));
        lua_pop(L, 1);
    }
    return construct_array(elems, n, FLOAT8OID, 8, FLOAT8PASSBYVAL, 'd');
}

/* ------------------------------------------------------------------ */
/* Shared setup: given query_arr, iterations, pop_size, diff_factor,  */
/* pushes run() or run_debug() entry on the stack, followed by the    */
/* cfg table (with fitness already captured).                         */
/*                                                                    */
/* Stack on exit: [entry_fn, cfg].                                    */
/* Caller is responsible for lua_pcall and result extraction.         */
/* ------------------------------------------------------------------ */

static int
prepare_call(lua_State *L,
             const char *entry_name,
             ArrayType  *query_arr,
             int32       iterations,
             int32       pop_size,
             int32       diff_factor,
             int        *out_dim)
{
    int rc, i, dim = 0;

    /* Validate bounds. */
    if (iterations < 1 || iterations > 100000)
        ereport(ERROR,
                (errcode(ERRCODE_NUMERIC_VALUE_OUT_OF_RANGE),
                 errmsg("iterations must be between 1 and 100000")));
    if (pop_size < 2 || pop_size > 10000)
        ereport(ERROR,
                (errcode(ERRCODE_NUMERIC_VALUE_OUT_OF_RANGE),
                 errmsg("population_size must be between 2 and 10000")));
    if (diff_factor < 1 || diff_factor > 100)
        ereport(ERROR,
                (errcode(ERRCODE_NUMERIC_VALUE_OUT_OF_RANGE),
                 errmsg("diffusion_factor must be between 1 and 100")));

    /* [M] */
    lua_rawgeti(L, LUA_REGISTRYINDEX, g_module_ref);
    /* [M, entry] */
    lua_getfield(L, -1, entry_name);
    /* [M, entry, cf] */
    lua_getfield(L, -2, "cosine_fitness");
    /* [entry, cf] */
    lua_remove(L, -3);

    /* Build query table and call cosine_fitness(query). */
    push_float8_array_as_table(L, query_arr, &dim);     /* [entry, cf, q] */
    rc = lua_pcall(L, 1, 1, 0);                          /* [entry, fn]   */
    if (rc != 0)
        return rc;

    /* Build cfg table. */
    lua_createtable(L, 0, 8);                            /* [entry, fn, cfg] */

    lua_createtable(L, dim, 0);
    for (i = 1; i <= dim; i++) {
        lua_pushnumber(L, -1.0);
        lua_rawseti(L, -2, i);
    }
    lua_setfield(L, -2, "lower");

    lua_createtable(L, dim, 0);
    for (i = 1; i <= dim; i++) {
        lua_pushnumber(L, 1.0);
        lua_rawseti(L, -2, i);
    }
    lua_setfield(L, -2, "upper");

    lua_pushinteger(L, iterations);
    lua_setfield(L, -2, "max_generation");

    lua_pushinteger(L, pop_size);
    lua_setfield(L, -2, "population_size");

    lua_pushinteger(L, diff_factor);
    lua_setfield(L, -2, "maximum_diffusion");

    lua_pushnumber(L, 0.5);
    lua_setfield(L, -2, "walk");

    lua_pushboolean(L, 1);
    lua_setfield(L, -2, "bound_clipping");

    /* Capture fn into cfg.fitness. */
    lua_pushvalue(L, -2);                                /* [entry, fn, cfg, fn] */
    lua_setfield(L, -2, "fitness");                      /* [entry, fn, cfg] */
    lua_remove(L, -2);                                   /* [entry, cfg] */

    *out_dim = dim;
    return 0;
}

/* ------------------------------------------------------------------ */
/* fractal_search(query, iterations, pop_size, diff_factor) -> fl8[]  */
/* ------------------------------------------------------------------ */

PG_FUNCTION_INFO_V1(fractal_search);

Datum
fractal_search(PG_FUNCTION_ARGS)
{
    ArrayType  *query_arr  = PG_GETARG_ARRAYTYPE_P(0);
    int32       iterations = PG_GETARG_INT32(1);
    int32       pop_size   = PG_GETARG_INT32(2);
    int32       diff_f     = PG_GETARG_INT32(3);
    int         dim = 0, rc, saved_top;
    ArrayType  *result;

    ensure_lua();
    saved_top = lua_gettop(g_L);

    rc = prepare_call(g_L, "run", query_arr,
                      iterations, pop_size, diff_f, &dim);
    if (rc != 0) {
        const char *msg = lua_tostring(g_L, -1);
        lua_settop(g_L, saved_top);
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("preparing SFS call: %s", msg ? msg : "?")));
    }

    /* Call run(cfg) -> best_point, best_fit, trace[, nil] */
    rc = lua_pcall(g_L, 1, 4, 0);
    if (rc != 0) {
        const char *msg = lua_tostring(g_L, -1);
        lua_settop(g_L, saved_top);
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("sfs_core.run: %s", msg ? msg : "?")));
    }

    /* [bp, bf, trace, paths]. best_point at index saved_top+1. */
    result = build_float8_array_from_table(g_L, saved_top + 1, dim);

    elog(DEBUG1, "fractal_search dim=%d iters=%d pop=%d mdn=%d best_fit=%g",
         dim, iterations, pop_size, diff_f,
         (double) lua_tonumber(g_L, saved_top + 2));

    lua_settop(g_L, saved_top);
    PG_RETURN_ARRAYTYPE_P(result);
}

/* ------------------------------------------------------------------ */
/* fractal_search_debug(...) -> jsonb                                 */
/* ------------------------------------------------------------------ */

PG_FUNCTION_INFO_V1(fractal_search_debug);

Datum
fractal_search_debug(PG_FUNCTION_ARGS)
{
    ArrayType  *query_arr  = PG_GETARG_ARRAYTYPE_P(0);
    int32       iterations = PG_GETARG_INT32(1);
    int32       pop_size   = PG_GETARG_INT32(2);
    int32       diff_f     = PG_GETARG_INT32(3);
    int         dim = 0, rc, saved_top;
    const char *json_str;
    size_t      json_len;
    char       *json_buf;
    Datum       result;

    ensure_lua();
    saved_top = lua_gettop(g_L);

    rc = prepare_call(g_L, "run_debug", query_arr,
                      iterations, pop_size, diff_f, &dim);
    if (rc != 0) {
        const char *msg = lua_tostring(g_L, -1);
        lua_settop(g_L, saved_top);
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("preparing SFS debug call: %s", msg ? msg : "?")));
    }

    /* run_debug(cfg) -> best_point, best_fit, json_string */
    rc = lua_pcall(g_L, 1, 3, 0);
    if (rc != 0) {
        const char *msg = lua_tostring(g_L, -1);
        lua_settop(g_L, saved_top);
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("sfs_core.run_debug: %s", msg ? msg : "?")));
    }

    /* JSON string is at index saved_top+3. */
    json_str = lua_tolstring(g_L, saved_top + 3, &json_len);
    if (json_str == NULL) {
        lua_settop(g_L, saved_top);
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("run_debug did not return a string")));
    }

    /* Copy into palloc memory before jsonb_in runs (jsonb_in requires
     * a null-terminated cstring owned by palloc context). */
    json_buf = palloc(json_len + 1);
    memcpy(json_buf, json_str, json_len);
    json_buf[json_len] = '\0';

    lua_settop(g_L, saved_top);

    result = DirectFunctionCall1(jsonb_in, CStringGetDatum(json_buf));
    PG_RETURN_DATUM(result);
}

/* ================================================================= */
/* fractal_search_explore                                            */
/*                                                                   */
/* Table-backed diversity search. Scans the stored vectors via SPI,  */
/* loads them into a palloc'd double[] buffer, runs SFS with a       */
/* min-distance-to-any-stored-vector fitness, and returns the full   */
/* final N-particle population as SETOF float8[].                    */
/* ================================================================= */

/* Helper: pull an int from a jsonb document with a default. Keeps the
 * options parser short; not exhaustive (ignores non-numeric values). */
static int32
jsonb_get_int(Jsonb *jb, const char *key, int32 fallback)
{
    JsonbValue  v;
    JsonbValue  k;
    JsonbValue *hit;

    if (jb == NULL)
        return fallback;

    k.type = jbvString;
    k.val.string.val = (char *) key;
    k.val.string.len = strlen(key);

    hit = findJsonbValueFromContainer(&jb->root, JB_FOBJECT, &k);
    if (hit == NULL || hit->type != jbvNumeric)
        return fallback;

    v = *hit;
    return DatumGetInt32(DirectFunctionCall1(numeric_int4,
                                             NumericGetDatum(v.val.numeric)));
}

static double
jsonb_get_float(Jsonb *jb, const char *key, double fallback)
{
    JsonbValue  k;
    JsonbValue *hit;

    if (jb == NULL)
        return fallback;

    k.type = jbvString;
    k.val.string.val = (char *) key;
    k.val.string.len = strlen(key);

    hit = findJsonbValueFromContainer(&jb->root, JB_FOBJECT, &k);
    if (hit == NULL || hit->type != jbvNumeric)
        return fallback;

    return DatumGetFloat8(DirectFunctionCall1(numeric_float8,
                                              NumericGetDatum(hit->val.numeric)));
}

/* Load a single float8[] cell into dst[0..dim-1]. Fast path for
 * fixed-length, no-null arrays uses ARR_DATA_PTR + memcpy. */
static void
copy_float8_array_row(ArrayType *arr, double *dst, int dim)
{
    int nelems;

    if (ARR_NDIM(arr) != 1)
        ereport(ERROR,
                (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR),
                 errmsg("expected 1-dimensional float8[] column")));
    if (ARR_HASNULL(arr))
        ereport(ERROR,
                (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
                 errmsg("stored vectors must not contain NULL components")));
    if (ARR_ELEMTYPE(arr) != FLOAT8OID)
        ereport(ERROR,
                (errcode(ERRCODE_DATATYPE_MISMATCH),
                 errmsg("vector_col must be of type float8[]")));

    nelems = ArrayGetNItems(ARR_NDIM(arr), ARR_DIMS(arr));
    if (nelems != dim)
        ereport(ERROR,
                (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR),
                 errmsg("vector dimension mismatch: expected %d, got %d",
                        dim, nelems)));

    memcpy(dst, ARR_DATA_PTR(arr), sizeof(double) * dim);
}

PG_FUNCTION_INFO_V1(fractal_search_explore);

Datum
fractal_search_explore(PG_FUNCTION_ARGS)
{
    text         *table_name_t = PG_GETARG_TEXT_PP(0);
    text         *vector_col_t = PG_GETARG_TEXT_PP(1);
    ArrayType    *query_arr    = PG_GETARG_ARRAYTYPE_P(2);
    Jsonb        *options      = PG_GETARG_JSONB_P(3);
    ReturnSetInfo *rsinfo      = (ReturnSetInfo *) fcinfo->resultinfo;
    char         *table_name, *vector_col;
    const char   *qtable, *qcol;
    StringInfoData sql;
    int32         iterations, pop_size, diff_f;
    double        walk;
    int           dim = 0, n_store = 0, rc, saved_top, i;
    double       *store = NULL;
    TupleDesc     tupdesc;
    Tuplestorestate *tupstore;
    MemoryContext per_query_ctx, oldcontext;

    /* --- SRF plumbing ---------------------------------------------- */
    if (rsinfo == NULL || !IsA(rsinfo, ReturnSetInfo) ||
        (rsinfo->allowedModes & SFRM_Materialize) == 0)
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                 errmsg("fractal_search_explore requires materialize mode")));

    if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
        tupdesc = CreateTemplateTupleDesc(1);
    /* SETOF float8[] -> single column of float8 array type */
    TupleDescInitEntry(tupdesc, (AttrNumber) 1, "particle",
                       FLOAT8ARRAYOID, -1, 0);
    tupdesc = BlessTupleDesc(tupdesc);

    per_query_ctx = rsinfo->econtext->ecxt_per_query_memory;

    /* --- parse options --------------------------------------------- */
    iterations = jsonb_get_int  (options, "iterations",       15);
    pop_size   = jsonb_get_int  (options, "population_size",  50);
    diff_f     = jsonb_get_int  (options, "diffusion_factor", 2);
    walk       = jsonb_get_float(options, "walk",             0.0);
    /* Diversity default: walk=0 (always Walk 2, no best-pull). This
     * departs from fractal_search which uses 0.5; documented in README. */

    if (iterations < 1 || iterations > 100000)
        ereport(ERROR, (errcode(ERRCODE_NUMERIC_VALUE_OUT_OF_RANGE),
                        errmsg("iterations must be 1..100000")));
    if (pop_size < 2 || pop_size > 10000)
        ereport(ERROR, (errcode(ERRCODE_NUMERIC_VALUE_OUT_OF_RANGE),
                        errmsg("population_size must be 2..10000")));
    if (diff_f < 1 || diff_f > 100)
        ereport(ERROR, (errcode(ERRCODE_NUMERIC_VALUE_OUT_OF_RANGE),
                        errmsg("diffusion_factor must be 1..100")));

    /* Query length = dim. We'll use the query's dimensionality as the
     * problem dimension and cross-check every scanned row against it. */
    if (ARR_NDIM(query_arr) != 1)
        ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR),
                        errmsg("query must be a 1-D float8[]")));
    dim = ArrayGetNItems(ARR_NDIM(query_arr), ARR_DIMS(query_arr));

    table_name = text_to_cstring(table_name_t);
    vector_col = text_to_cstring(vector_col_t);
    qtable = quote_identifier(table_name);
    qcol   = quote_identifier(vector_col);

    /* --- SPI scan: one pass, batch into contiguous buffer ---------- */
    if ((rc = SPI_connect()) != SPI_OK_CONNECT)
        ereport(ERROR, (errmsg("SPI_connect failed: %d", rc)));

    initStringInfo(&sql);
    appendStringInfo(&sql, "SELECT %s FROM %s", qcol, qtable);

    rc = SPI_execute(sql.data, true /* read-only */, 0);
    if (rc != SPI_OK_SELECT) {
        SPI_finish();
        ereport(ERROR, (errmsg("SPI_execute failed on table scan: %d", rc)));
    }

    n_store = SPI_processed;
    if (n_store < 1) {
        SPI_finish();
        ereport(ERROR, (errmsg("table %s has no rows to search", qtable)));
    }

    /* Allocate the flat double buffer in the per-query context so it
     * outlives SPI_finish but is freed on function exit. */
    oldcontext = MemoryContextSwitchTo(per_query_ctx);
    store = palloc_extended((size_t) n_store * dim * sizeof(double),
                            MCXT_ALLOC_HUGE | MCXT_ALLOC_NO_OOM);
    MemoryContextSwitchTo(oldcontext);
    if (store == NULL) {
        SPI_finish();
        ereport(ERROR,
                (errcode(ERRCODE_OUT_OF_MEMORY),
                 errmsg("could not allocate %zu bytes for store buffer",
                        (size_t) n_store * dim * sizeof(double))));
    }

    /* Fill store from SPI tuples. SPI values live in the SPI context,
     * which is distinct from per_query — we copy each row through. */
    for (i = 0; i < n_store; i++) {
        HeapTuple t = SPI_tuptable->vals[i];
        bool      isnull;
        Datum     d = SPI_getbinval(t, SPI_tuptable->tupdesc, 1, &isnull);
        ArrayType *arr;

        if (isnull) {
            SPI_finish();
            ereport(ERROR,
                    (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
                     errmsg("row %d has NULL vector", i)));
        }
        arr = DatumGetArrayTypeP(d);
        copy_float8_array_row(arr, store + (size_t) i * dim, dim);

        /* Honor cancellation every 4096 rows so large tables stay
         * interruptible under pg_cancel_backend. */
        if ((i & 0xfff) == 0)
            CHECK_FOR_INTERRUPTS();
    }

    SPI_finish();

    elog(DEBUG1, "fractal_search_explore: loaded %d x %d vectors (%.1f MB)",
         n_store, dim, (n_store * (double) dim * 8) / (1024.0 * 1024.0));

    /* --- hand off to Lua: run_explore with diversity fitness ------- */
    ensure_lua();
    saved_top = lua_gettop(g_L);

    /* [M] [run_explore] [diversity_fitness_from_ptr] */
    lua_rawgeti(g_L, LUA_REGISTRYINDEX, g_module_ref);
    lua_getfield(g_L, -1, "run_explore");
    lua_getfield(g_L, -2, "diversity_fitness_from_ptr");
    lua_remove(g_L, -3);

    /* Build diversity_fitness(store_ptr, n_store, dim). */
    lua_pushlightuserdata(g_L, (void *) store);
    lua_pushinteger(g_L, n_store);
    lua_pushinteger(g_L, dim);
    rc = lua_pcall(g_L, 3, 1, 0);              /* [run_explore, fit_closure] */
    if (rc != 0) {
        const char *m = lua_tostring(g_L, -1);
        lua_settop(g_L, saved_top);
        ereport(ERROR, (errmsg("building diversity fitness: %s", m ? m : "?")));
    }

    /* Build cfg table. Bounds are drawn from [-1,1]^dim by default —
     * callers normalizing embeddings to unit norm can use as-is.
     * Future work: derive per-dim bounds from the store's min/max. */
    lua_createtable(g_L, 0, 8);                /* [run, fit, cfg] */

    lua_createtable(g_L, dim, 0);
    for (i = 1; i <= dim; i++) {
        lua_pushnumber(g_L, -1.0);
        lua_rawseti(g_L, -2, i);
    }
    lua_setfield(g_L, -2, "lower");

    lua_createtable(g_L, dim, 0);
    for (i = 1; i <= dim; i++) {
        lua_pushnumber(g_L, 1.0);
        lua_rawseti(g_L, -2, i);
    }
    lua_setfield(g_L, -2, "upper");

    lua_pushinteger(g_L, iterations);
    lua_setfield(g_L, -2, "max_generation");
    lua_pushinteger(g_L, pop_size);
    lua_setfield(g_L, -2, "population_size");
    lua_pushinteger(g_L, diff_f);
    lua_setfield(g_L, -2, "maximum_diffusion");
    lua_pushnumber(g_L, walk);
    lua_setfield(g_L, -2, "walk");
    lua_pushboolean(g_L, 1);
    lua_setfield(g_L, -2, "bound_clipping");

    /* Capture fit closure into cfg.fitness. */
    lua_pushvalue(g_L, -2);                    /* [run, fit, cfg, fit] */
    lua_setfield(g_L, -2, "fitness");          /* [run, fit, cfg] */
    lua_remove(g_L, -2);                       /* [run, cfg] */

    /* Call run_explore(cfg) -> pop_table, fit_table */
    rc = lua_pcall(g_L, 1, 2, 0);
    if (rc != 0) {
        const char *m = lua_tostring(g_L, -1);
        lua_settop(g_L, saved_top);
        ereport(ERROR, (errmsg("sfs_core.run_explore: %s", m ? m : "?")));
    }

    /* Stack: [pop_table, fit_table]. Materialize each particle into
     * the tuplestore. The pop_table is a Lua array of Lua arrays. */
    MemoryContextSwitchTo(per_query_ctx);
    tupstore = tuplestore_begin_heap(true, false, work_mem);
    MemoryContextSwitchTo(oldcontext);

    {
        int  pop_idx  = saved_top + 1;
        int  n_pop    = lua_objlen(g_L, pop_idx);
        for (i = 1; i <= n_pop; i++) {
            Datum     values[1];
            bool      nulls[1] = { false };
            ArrayType *arr;

            lua_rawgeti(g_L, pop_idx, i);   /* push particle (Lua array) */
            arr = build_float8_array_from_table(g_L, lua_gettop(g_L), dim);
            values[0] = PointerGetDatum(arr);
            tuplestore_putvalues(tupstore, tupdesc, values, nulls);
            lua_pop(g_L, 1);
        }
    }

    lua_settop(g_L, saved_top);

    rsinfo->returnMode = SFRM_Materialize;
    rsinfo->setResult  = tupstore;
    rsinfo->setDesc    = tupdesc;
    return (Datum) 0;
}

/* ------------------------------------------------------------------ */
/* fractalsql_edition() / fractalsql_version() — edition metadata     */
/* ------------------------------------------------------------------ */

PG_FUNCTION_INFO_V1(fractalsql_edition);

Datum
fractalsql_edition(PG_FUNCTION_ARGS)
{
    PG_RETURN_TEXT_P(cstring_to_text(FRACTALSQL_EDITION));
}

PG_FUNCTION_INFO_V1(fractalsql_version);

Datum
fractalsql_version(PG_FUNCTION_ARGS)
{
    PG_RETURN_TEXT_P(cstring_to_text(FRACTALSQL_VERSION));
}
