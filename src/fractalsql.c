/* src/fractalsql.c
 * fractalsql-postgresql v1.0 — Stochastic Fractal Search for PostgreSQL.
 *
 * Links the vendored C search core. The reasoning VFS surface is layered
 * on top of the minimal SFS ABI; for search-only deployments the reasoning
 * VFS is simply not injected and the overhead is zero.
 *
 * SQL surface
 *   fractal_search(query float8[],
 *                  iterations       int4 DEFAULT 30,
 *                  population_size  int4 DEFAULT 50,
 *                  diffusion_factor int4 DEFAULT 2)
 *     -> float8[]                — refined best_point
 *
 *   fractal_search_debug(query float8[], ...)
 *     -> jsonb                   — full fsql_search_ptr result JSON
 *
 *   fractal_search_explore(table_name text, vector_col text,
 *                          query float8[], options jsonb)
 *     -> SETOF float8[]          — Scout mode. Scans table.vector_col
 *                                  into a corpus, runs SFS with
 *                                  return_population=true and walk=0.0
 *                                  (min-distance-to-any-stored fitness),
 *                                  and returns the final population as
 *                                  one float8[] row per particle.
 *
 *   fractal_reason(query text, context text DEFAULT '{}')
 *     -> text                    — Dispatch query + JSON context to the
 *                                  configured LLM reasoning plugin and
 *                                  return the response. Requires
 *                                  fractalsql.reasoning_plugin to be set
 *                                  in postgresql.conf. No-op if the GUC
 *                                  is absent — search functions continue
 *                                  to work regardless.
 *
 *   fractal_text_to_sql(question text, table_names text[] DEFAULT NULL)
 *     -> text                    — GENERATE/ALLOWLIST/EXPLAIN pipeline
 *                                  returning a single SQL statement,
 *                                  never auto-executed. See its own
 *                                  header comment below.
 *
 *   fractal_embed(input text) -> float8[]
 *     -> float8[]                — Dispatch input to the configured
 *                                  embedding endpoint and return the
 *                                  parsed vector. Requires
 *                                  fractalsql.reasoning_plugin AND
 *                                  fractalsql.http_embed_url to be set.
 *
 *   fractal_edition() -> text
 *   fractal_version() -> text
 *
 * Reasoning plugin wiring (optional):
 *   Set in postgresql.conf (restart required):
 *     fractalsql.reasoning_plugin = '/abs/path/fractalsql-reasoning-http.so'
 *     fractalsql.http_url         = 'https://api.openai.com/v1/chat/completions'
 *     fractalsql.http_token       = 'sk-...'
 *     fractalsql.http_model       = 'gpt-4o-mini'   -- optional
 *     fractalsql.http_embed_url   = 'https://api.openai.com/v1/embeddings'   -- for fractal_embed()
 *     fractalsql.http_embed_model = 'text-embedding-3-small'                -- optional
 *   Without the plugin GUC set the extension loads normally; only
 *   fractal_reason()/fractal_text_to_sql()/fractal_embed() will error if
 *   called.
 *
 * Reasoning runs through three INDEPENDENT plugin contexts (fractal_reason,
 * fractal_text_to_sql's GENERATE step, fractal_embed), each lazily loaded
 * on first use with its own FSQL_REASONING_HTTP_MODE/RESPONSE_MODE/
 * SYSTEM_TAG -- see ensure_reason_ctx()/ensure_text_to_sql_ctx()/
 * ensure_embed_ctx() below for why a single shared context can't serve
 * all three (env vars are read once at plugin init, no per-call mode
 * override in the ABI).
 */

#include <math.h>

#include "postgres.h"
#include "fmgr.h"

/*
 * PG_FUNCTION_INFO_V1 only decorates the raw funcname declaration with
 * PGDLLEXPORT from PG16 onward -- PG14/15's own fmgr.h emits a plain
 * "extern Datum funcname(...)" (confirmed by diffing fmgr.h across
 * every supported major). On Windows, where nothing is exported from a
 * DLL by default, that leaves every V1 SQL-callable function in this
 * file unreachable via CREATE FUNCTION ... LANGUAGE C on PG14/15 --
 * confirmed directly: PG_FUNCTION_INFO_V1-registered agent-tier
 * functions failed "could not find function ... in file ...dll" only
 * on PG14/15 Windows builds, never on PG16+. Redefine the macro to
 * match PG16's own version for exactly this gap (Windows, PG < 16) --
 * this is upstream Postgres's own fix, just backported here since we
 * can't edit an older major's installed system header. Deliberately
 * NOT decorating the function definitions themselves (below): a prior
 * declaration with PGDLLEXPORT is sufficient on MSVC, matching how
 * Postgres's own core functions rely solely on this same macro.
 */
#if defined(_WIN32) && PG_VERSION_NUM < 160000
#undef PG_FUNCTION_INFO_V1
#define PG_FUNCTION_INFO_V1(funcname) \
extern PGDLLEXPORT Datum funcname(PG_FUNCTION_ARGS); \
extern PGDLLEXPORT const Pg_finfo_record * CppConcat(pg_finfo_,funcname)(void); \
const Pg_finfo_record * \
CppConcat(pg_finfo_,funcname) (void) \
{ \
	static const Pg_finfo_record my_finfo = { 1 }; \
	return &my_finfo; \
} \
extern int no_such_variable
#endif

#include "funcapi.h"
#include "miscadmin.h"
#include "access/htup_details.h"
#include "access/heapam.h"      /* heap_form_tuple -- single-record composite Datum */
#include "catalog/namespace.h"
#include "catalog/pg_type.h"
#include "utils/array.h"
#include "utils/builtins.h"   /* format_type_be is declared here (no separate format_type.h in PG16) */
#include "utils/jsonb.h"
#include "utils/json.h"       /* escape_json -- safe error message in result_json */
#include "utils/memutils.h"
#include "utils/guc.h"
#include "executor/spi.h"
#include "access/xact.h"

#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>           /* LONG_MAX -- ent_file_size_win32's bounds check */
#if !defined(_WIN32) && !defined(_MSC_VER)
#include <dlfcn.h>            /* dlopen/dlsym/dlclose for the enterprise core */
#endif

#include "fractalsql.h"
#include "fractalsql_sql.h"
#include "fractalsql_vector.h"
#include "fractalsql_parse.h"
/* Header-only SHA-256 + HMAC-SHA256 (vendored, no libcrypto link) for the
 * QTL ledger MAC envelope (fractalsql.enterprise_ledger_key). */
#include "fractalsql_hmac.h"
/* OpenSSL EVP for Ed25519 detached-signature verification of the
 * enterprise core .so (unlike the vendored SHA-256/HMAC above, signature
 * verification is security-critical enough that using OpenSSL's vetted
 * implementation is the right call over hand-rolling Ed25519 curve
 * arithmetic; Postgres already links libcrypto when built --with-openssl,
 * the common case). See ent_verify_signature() below. */
#include <openssl/evp.h>

/* fractal_text_to_sql's statement-shape allowlist uses the backend's OWN
 * parser (raw_parser), not a vendored copy. We run inside a live
 * PostgreSQL backend, so the real parser is already loaded and callable
 * -- using it parses SQL with the exact same grammar the server will
 * execute (no version skew), on every platform, with no vendored
 * dependency. (A vendored libpg_query was tried and rejected: it links a
 * large slice of backend source and, on Windows, corrupted the
 * extension DLL's load-time state.) */
#include "parser/parser.h"     /* raw_parser, RAW_PARSE_DEFAULT */
#include "tcop/utility.h"      /* CreateCommandTag */
#include "tcop/cmdtag.h"       /* GetCommandTagName */
#include "nodes/nodes.h"       /* nodeTag, T_SelectStmt, ... */
#include "parser/analyze.h"   /* parse_analyze_fixedparams, Query.hasModifyingCTE */

#ifndef INT8PASSBYVAL
#define INT8PASSBYVAL true
#endif

typedef enum
{
    T2S_ALLOW_SELECT = 0,
    T2S_ALLOW_SELECT_INSERT_UPDATE = 1
} T2SAllowedStmts;

/* Forward declarations for t2s pipeline helpers */
static char *t2s_check_readonly(const char *sql);
static char *t2s_check_allowlist(const char *sql);
static char *t2s_check_explain(const char *sql);
static bool  t2s_run_review(const char *question, const char *candidate_sql, char **critique_out);
static T2SAllowedStmts t2s_allowed_stmts_mode(void);

/* Internal text-to-sql generator used by the agent loop */
static char *fractal_text_to_sql_internal(const char *question, ArrayType *table_names, char *feedback);

#define FSQL_EDITION "Community"
#define FSQL_VERSION "2.0.11"

/* B4-extended (H3) — supply-side DoS guards.
 *
 * Same shape as the redis/valkey blob caps: a SQL caller controls
 * the query-vector dim and the SFS hyperparameters, all of which
 * feed allocations sized as some multiple of dim or pop_size. Cap
 * each at a value well above any realistic workload so adversarial
 * input can't translate into a backend-process OOM kill.
 *
 * MAX_QUERY_DIM        = 1 M float8 = 8 MiB query, plenty for any
 *                        embedding model in current use.
 * MAX_ITERATIONS       = 10 000 generations, far past convergence.
 * MAX_POPULATION_SIZE  = 100 000 particles.
 * MAX_DIFFUSION_FACTOR = 32, double-digit values already pathological. */
#define MAX_QUERY_DIM         (1 * 1024 * 1024)
#define MAX_ITERATIONS        10000
#define MAX_POPULATION_SIZE   100000
#define MAX_DIFFUSION_FACTOR  32

/* Cap the number of tables fractal_schema_context() will introspect
 * when the caller passes an explicit table_names[] array. Each named
 * table costs several catalog round-trips (structure, comments, FKs),
 * so an enormous array is a cheap way for a caller to fan out a lot of
 * SPI work. 512 is far above any realistic hand-authored schema-context
 * request; callers needing more should scope down. The auto-discover
 * path (table_names IS NULL) is naturally bounded by what the role can
 * actually see, so it is not capped here. */
#define MAX_SCHEMA_CONTEXT_TABLES  512

/* Sanity ceiling on the reasoning plugin's reported response length.
 * The reasoning ABI supplies summary_len and the core forwards it
 * verbatim (it caps inputs, not the response), so a BUGGY plugin
 * returning an uninitialized or wildly-wrong length would drive an
 * unbounded read/allocation in the response handling below. 16 MiB is
 * far above any real LLM response (bounded by the model's context
 * window, well under a megabyte of text) -- a clean rejection, never a
 * silent truncation (truncating would corrupt the SQL/summary). This
 * defends only against a buggy plugin; a MALICIOUS in-process plugin is
 * out of scope by the sovereign "you provide the trust boundary"
 * contract -- it can do anything regardless of this check. */
#define FSQL_MAX_AI_RESPONSE_BYTES  ((size_t) 16 * 1024 * 1024)

/* Cap on parsed embedding dimension for fractal_embed(). Real embedding
 * models top out around 3072 dims (OpenAI text-embedding-3-large,
 * Vertex gemini-embedding-001) -- 16384 is generous headroom above any
 * current model while still bounding the palloc below against a buggy
 * or adversarial plugin response, same reasoning as the other DoS
 * guards in this file. */
#define MAX_EMBED_DIM  16384

/* Reject an implausibly large plugin response, freeing it first. NULL
 * summary is already guaranteed non-NULL by fsql_dispatch_ai on rc==0,
 * so callers only invoke this after a successful dispatch. */
static void
guard_ai_response_len(fsql_ai_response_t *resp)
{
    if (resp->summary_len > FSQL_MAX_AI_RESPONSE_BYTES)
    {
        size_t len = resp->summary_len;
        fsql_ai_response_free(resp);
        ereport(ERROR,
                (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
                 errmsg("fractalsql: reasoning plugin reported an implausible "
                        "response length (%zu bytes, limit %zu) -- likely a "
                        "plugin bug",
                        len, (size_t) FSQL_MAX_AI_RESPONSE_BYTES)));
    }
}

static void
validate_sfs_params(int dim, int iterations, int pop_size, int diff_f)
{
    if (dim <= 0 || dim > MAX_QUERY_DIM)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("fractalsql: query dim %d out of range [1, %d]",
                        dim, MAX_QUERY_DIM)));
    if (iterations <= 0 || iterations > MAX_ITERATIONS)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("fractalsql: iterations %d out of range [1, %d]",
                        iterations, MAX_ITERATIONS)));
    if (pop_size <= 0 || pop_size > MAX_POPULATION_SIZE)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("fractalsql: population_size %d out of range [1, %d]",
                        pop_size, MAX_POPULATION_SIZE)));
    if (diff_f <= 0 || diff_f > MAX_DIFFUSION_FACTOR)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("fractalsql: diffusion_factor %d out of range [1, %d]",
                        diff_f, MAX_DIFFUSION_FACTOR)));
}

PG_MODULE_MAGIC;

/* PGDLLEXPORT (fmgr.h): on MSVC, cl.exe /LD does not export any symbol
 * by default -- unlike Unix, where every non-static global is visible
 * in a -shared object automatically. PG_FUNCTION_INFO_V1 bakes this in
 * for its own pg_finfo_* symbols, but _PG_init/_PG_fini are plain
 * user-declared hooks with no such macro, so they need it explicitly.
 * Confirmed on real CI hardware (2026-08): without this, PG16-18's
 * headers happened to make _PG_init exported anyway (Postgres server
 * version differences upstream, not anything in this file), but PG14/
 * 15 did not -- dumpbin /exports showed all 71 pg_finfo_* and
 * Pg_magic_func symbols present, and _PG_init/_PG_fini absent. Explicit annotation
 * here makes this correct on every PG major, not just the ones whose
 * headers happened to cover for its absence.
 */
PGDLLEXPORT void _PG_init(void);
PGDLLEXPORT void _PG_fini(void);

/* Process-wide fsql context for SEARCH only (fractal_search,
 * fractal_search_explore). Created lazily on first SQL call
 * (ensure_search_ctx); freed in _PG_fini at backend exit. One ctx per
 * backend process — the PostgreSQL process-per-connection model
 * satisfies the plugin's single-CURL*-per-ctx contract automatically. */
static fsql_ctx *g_ctx = NULL;

/* Reasoning runs through three INDEPENDENT contexts, not one shared
 * one. A single fsql_ctx has exactly one reasoning-plugin slot --
 * fsql_load_reasoning() called again on the same ctx REPLACES whatever
 * was previously loaded (runs that plugin's fini, inits the new one),
 * it does not add a second live config alongside the first. Since
 * FSQL_REASONING_HTTP_MODE/RESPONSE_MODE/SYSTEM_TAG are read once at
 * plugin init from the process environment (no per-call override in
 * the ABI), fractal_reason() (chat, text), fractal_text_to_sql()'s
 * GENERATE step (chat, code-mode extraction), and fractal_embed()
 * (embedding mode) each need their own ctx with its own load, or
 * they'd stomp on each other's config the moment more than one is used
 * in the same backend. Each is lazy -- only created if that specific
 * SQL function is actually called in a given backend. */
static fsql_ctx *g_reason_ctx    = NULL;   /* fractal_reason(), t2s review */
static bool      g_reason_loaded = false;

static fsql_ctx *g_t2s_ctx       = NULL;   /* fractal_text_to_sql() GENERATE */
static bool      g_t2s_loaded    = false;

static fsql_ctx *g_embed_ctx     = NULL;   /* fractal_embed() */
static bool      g_embed_loaded  = false;

/* An operator can set FSQL_REASONING_HTTP_RESPONSE_MODE at the process
 * level (same mechanism as FSQL_REASONING_HTTP_TIMEOUT_MS) to control
 * fractal_reason()'s own response parsing. Captured once here, in
 * _PG_init, before any SQL function in this backend has a chance to
 * run and before fractal_text_to_sql() ever sets its own temporary
 * "code" value. ensure_reason_ctx() asserts this captured value
 * explicitly on every load instead of trusting whatever the process
 * environment currently holds, so it can never end up loading with a
 * value some other tier left behind. See ensure_reason_ctx() below. */
static char *g_response_mode_boot = NULL;

/* GUC storage — PostgreSQL requires static lifetime for GUC string vars. */
static char *g_reasoning_plugin   = NULL;
static char *g_http_url           = NULL;
static char *g_http_token         = NULL;
static char *g_http_model         = NULL;
static bool  g_http_allow_plain   = false;
static char *g_http_embed_url     = NULL;
static char *g_http_embed_model   = NULL;

/* Reasoning-effort knobs (v1.4.0+ plugin). Chat-only by design -- never
 * wired into ensure_embed_ctx(), which explicitly unsetenv()s all four
 * so a value left over from an earlier fractal_reason()/
 * fractal_text_to_sql() call in the same backend can't leak into an
 * embedding request. */
static char *g_http_think          = NULL;
static char *g_http_think_provider = NULL;
static char *g_http_native_url     = NULL;
static int   g_http_num_ctx        = 0;

/* text-to-sql GUCs. See fractal_text_to_sql() below for how each is
 * used; kept together here since they're a matched set. */
static int   g_t2s_max_attempts     = 2;
static char *g_t2s_allowed_stmts    = NULL;   /* "select" | "select_insert_update" */
static bool  g_t2s_use_review       = false;

/* ------------------------------------------------------------------ */
/* Enterprise tier (QTL ledger + CISO audit) -- runtime-gated          */
/* ------------------------------------------------------------------ */
/* The community core archive this extension links does NOT compile the
 * ledger/audit surface: in core's fsql.c, fsql_ledger_* and
 * fsql_audit_unpack live behind #ifdef FSQL_ENTERPRISE, and community is
 * built with only -DFSQL_SOVEREIGN. So those symbols are ABSENT from a
 * clean community archive and must be resolved at runtime by dlopen-ing
 * the enterprise core shared library on demand. (The vendored archive is
 * currently stale and still carries them, but the wiring never references
 * the community copy -- it dlsym's the enterprise library's -- so it is
 * robust whether the vendored archive is stale or rebuilt clean.)
 *
 * Until the library is loaded, every enterprise SQL function raises a
 * clear "enterprise tier not loaded" error; the extension still builds
 * and search works on community alone. Activation: set
 * fractalsql.enterprise_lib (postgresql.conf / ALTER SYSTEM + reload) to
 * the enterprise core library path; the first enterprise call in a fresh
 * backend dlopens it and dlsym's the eight symbols. Removing the library
 * (or pointing the GUC elsewhere) and reconnecting re-dormants it. */
static char *g_enterprise_lib   = NULL;   /* GUC: path to enterprise core */
/* GUC: HMAC-SHA256 key for the QTL ledger's MAC envelope. Empty
 * (default) = structural-only validation; non-empty
 * = every flush tags the persisted blob with HMAC-SHA256(key, blob) and every
 * load verifies the tag before decode (cryptographic tamper-evidence). PGC_SUSET
 * so a superuser can SET it per-session (no reload). */
static char *g_enterprise_ledger_key = NULL;
/* GUC: whether ensure_enterprise_lib() requires a valid detached Ed25519
 * signature (a sibling <path>.sig file) before dlopen-ing the enterprise
 * .so. Default off: a missing .sig just logs a WARNING and the library
 * still loads (backward compatible with unsigned releases). An INVALID
 * signature is always refused regardless of this flag -- only "absent"
 * is soft. See ent_verify_signature(). */
static bool  g_enterprise_require_signature = false;
static void *g_ent_handle       = NULL;   /* dlopen handle, NULL until loaded */
static bool  g_ent_attempted    = false;  /* tried this backend (any outcome) */
static bool  g_ent_loaded       = false;  /* dlopen + all 8 symbols resolved */

typedef int  (*ent_ledger_void_fn)(fsql_ctx *ctx);
typedef int  (*ent_ledger_count_fn)(const fsql_ctx *ctx, size_t *out);
typedef int  (*ent_audit_unpack_fn)(const void *blob, size_t blob_len,
                                    char *json_out, size_t *json_cap);
typedef int  (*ent_portfolio_multimodal_fn)(const double *mu, const double *cov,
                                            size_t n_assets, size_t k,
                                            int n_restarts, double overlap_threshold,
                                            double quality_frac, uint64_t seed,
                                            double *out_weights, double *out_sharpes,
                                            int *out_n_found);
typedef int  (*ent_portfolio_multimodal_ex_fn)(const double *mu, const double *cov,
                                               size_t n_assets, size_t k,
                                               int n_restarts, double overlap_threshold,
                                               double quality_frac, uint64_t seed,
                                               int use_obl, int diffusion_mode,
                                               double *out_weights, double *out_sharpes,
                                               int *out_n_found);
typedef int  (*ent_portfolio_multimodal_pareto_fn)(const double *mu, const double *cov,
                                                   size_t n_assets, size_t k,
                                                   int n_restarts, int max_front,
                                                   uint64_t seed,
                                                   int use_obl, int diffusion_mode,
                                                   double *out_weights, double *out_returns,
                                                   double *out_risks, int *out_n_found);

static ent_ledger_void_fn   g_ent_ledger_flush;
static ent_ledger_void_fn   g_ent_ledger_load;
static ent_ledger_void_fn   g_ent_ledger_compact;
static ent_ledger_void_fn   g_ent_ledger_reset_soft;
static ent_ledger_void_fn   g_ent_ledger_reset_hard;
static ent_ledger_count_fn  g_ent_ledger_truth_count;
static ent_ledger_count_fn  g_ent_ledger_shadow_count;
static ent_audit_unpack_fn  g_ent_audit_unpack;
/* Optional (unlike the 8 above): resolved best-effort, not required for
 * ensure_enterprise_lib() to succeed, so an older enterprise .so without
 * this symbol still activates ledger/audit normally. NULL means "not in
 * this enterprise build" -- the SQL wrapper reports that specifically. */
static ent_portfolio_multimodal_fn g_ent_optimize_portfolio_multimodal;
/* Optional (unlike the 8 required symbols): same tolerant-absence
 * convention as g_ent_optimize_portfolio_multimodal above. NULL means
 * "not in this enterprise build" -- falls back to
 * g_ent_optimize_portfolio_multimodal (use_obl/diffusion_mode
 * unsupported) when absent. */
static ent_portfolio_multimodal_ex_fn g_ent_optimize_portfolio_multimodal_ex;
/* Optional (unlike the 8 required symbols): same tolerant-absence
 * convention as g_ent_optimize_portfolio_multimodal above. NULL means
 * "not in this enterprise build". */
static ent_portfolio_multimodal_pareto_fn g_ent_optimize_portfolio_multimodal_pareto;

void
_PG_init(void)
{
    /* GUC context is PGC_SIGHUP so registration succeeds whether the
     * library is loaded via shared_preload_libraries (postmaster startup)
     * or on first use in a backend (CREATE EXTENSION / first SQL call).
     * PGC_POSTMASTER is restricted to postmaster-phase-only code; using
     * it in an extension _PG_init called from a running backend causes
     * "cannot create PGC_POSTMASTER variables after startup". PGC_SIGHUP
     * is the correct context for extension GUCs — values are read from
     * postgresql.conf placeholders when DefineCustom*Variable is called,
     * and we only act on them in ensure_search_ctx()/ensure_reasoning_ctx()
     * on first use. */
    DefineCustomStringVariable(
        "fractalsql.reasoning_plugin",
        "Absolute path to a fractalsql-reasoning-*.so plugin.",
        "Set to the path of a compiled reasoning plugin to enable "
        "fractal_reason(). Leave empty for search-only operation.",
        &g_reasoning_plugin,
        NULL,
        PGC_SIGHUP,
        GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

    DefineCustomStringVariable(
        "fractalsql.http_url",
        "OpenAI-compatible chat completions endpoint URL.",
        "Forwarded to the reasoning plugin via FSQL_REASONING_HTTP_URL.",
        &g_http_url,
        NULL,
        PGC_SIGHUP,
        GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

    DefineCustomStringVariable(
        "fractalsql.http_token",
        "Bearer token for the reasoning endpoint.",
        "Forwarded via FSQL_REASONING_HTTP_TOKEN. "
        "Prefer systemd Environment= over plaintext postgresql.conf.",
        &g_http_token,
        NULL,
        PGC_SIGHUP,
        GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

    DefineCustomStringVariable(
        "fractalsql.http_model",
        "Model name forwarded to the reasoning endpoint.",
        "Forwarded via FSQL_REASONING_HTTP_MODEL. "
        "Defaults to gpt-4o-mini inside the plugin if not set.",
        &g_http_model,
        NULL,
        PGC_SIGHUP,
        0, NULL, NULL, NULL);

    DefineCustomBoolVariable(
        "fractalsql.http_allow_plaintext",
        "Allow plain HTTP for the reasoning endpoint (dev/local use only).",
        "Sets FSQL_REASONING_HTTP_ALLOW_PLAINTEXT=1 for the plugin. "
        "Required when the endpoint uses http:// instead of https:// "
        "(e.g. Ollama on a LAN host). Prompts are sent unencrypted — "
        "do not use in production with sensitive data.",
        &g_http_allow_plain,
        false,
        PGC_SIGHUP,
        GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

    DefineCustomStringVariable(
        "fractalsql.http_embed_url",
        "OpenAI-compatible embeddings endpoint URL, for fractal_embed().",
        "Forwarded via FSQL_REASONING_HTTP_URL when loading the embed "
        "context. Required for fractal_embed() -- unlike http_url there "
        "is no fallback: chat and embeddings are different endpoint "
        "paths even on the same host (e.g. .../chat/completions vs. "
        ".../embeddings), so silently reusing http_url would send embed "
        "requests to the wrong endpoint. fractal_embed() errors clearly "
        "if this is unset.",
        &g_http_embed_url,
        NULL,
        PGC_SIGHUP,
        GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

    DefineCustomStringVariable(
        "fractalsql.http_embed_model",
        "Embedding model name, for fractal_embed().",
        "Forwarded via FSQL_REASONING_HTTP_MODEL when loading the embed "
        "context. Leave unset to use the plugin's own embedding default "
        "(text-embedding-3-small) rather than silently reusing "
        "http_model -- a chat model (e.g. gemma4:12b) is not a "
        "substitute for a purpose-trained embedding model (e.g. "
        "embeddinggemma).",
        &g_http_embed_model,
        NULL,
        PGC_SIGHUP,
        0, NULL, NULL, NULL);

    DefineCustomStringVariable(
        "fractalsql.http_think",
        "Reasoning effort for hybrid-thinker models: none/off/anything else.",
        "Forwarded via FSQL_REASONING_HTTP_THINK to fractal_reason() and "
        "fractal_text_to_sql()'s GENERATE step only -- never fractal_embed(). "
        "Leave unset for the plugin's own default (none: no thinking-control "
        "field sent). 'off' explicitly disables thinking, distinct from "
        "unset/none. Any other value (low/medium/high/...) is forwarded to "
        "the provider verbatim, not checked against a fixed list.",
        &g_http_think,
        NULL,
        PGC_SIGHUP,
        0, NULL, NULL, NULL);

    DefineCustomStringVariable(
        "fractalsql.http_think_provider",
        "Which field/shape carries http_think: openai/ollama/anthropic/vllm/grok.",
        "Forwarded via FSQL_REASONING_HTTP_THINK_PROVIDER. Names a request "
        "SHAPE, not a vendor -- 'openai' also covers Azure OpenAI, AWS "
        "Bedrock, and Google Vertex AI's OpenAI-compatible surfaces, since "
        "this is independent of how http_url is authenticated. 'grok' is "
        "for xAI's Grok models on Bedrock's OpenAI-compatible surface, "
        "which take a nested reasoning.effort field. Ignored entirely when "
        "http_think is unset. Defaults to openai inside the plugin if "
        "http_think is set but this is left unset.",
        &g_http_think_provider,
        NULL,
        PGC_SIGHUP,
        0, NULL, NULL, NULL);

    DefineCustomStringVariable(
        "fractalsql.http_native_url",
        "Endpoint override for the ollama/anthropic native request shape.",
        "Forwarded via FSQL_REASONING_HTTP_NATIVE_URL. Only consulted when "
        "http_think_provider is ollama or anthropic (those two speak a "
        "native shape instead of the OpenAI-compatible one, see api-cognition "
        "docs). Leave unset to target http_url verbatim -- most Ollama/"
        "Anthropic deployments don't need a separate URL for the native path.",
        &g_http_native_url,
        NULL,
        PGC_SIGHUP,
        0, NULL, NULL, NULL);

    DefineCustomIntVariable(
        "fractalsql.http_num_ctx",
        "Ollama-native context window cap (options.num_ctx).",
        "Forwarded via FSQL_REASONING_HTTP_NUM_CTX when > 0. Only applies "
        "to the ollama-native shape (http_think_provider=ollama with "
        "http_think set) -- a measured fix for hybrid-thinker VRAM blowup "
        "on memory-constrained GPUs. 0 (default) leaves it unset, letting "
        "the plugin/server apply its own default.",
        &g_http_num_ctx,
        0, 0, 1048576,
        PGC_SIGHUP,
        0, NULL, NULL, NULL);

    DefineCustomIntVariable(
        "fractalsql.text_to_sql_max_attempts",
        "Max GENERATE attempts for fractal_text_to_sql().",
        "Shared budget across both failure classes -- a review rejection "
        "and an EXPLAIN rejection draw from the same counter, not "
        "separate ones. Kept low deliberately: more attempts buys less "
        "than good schema context does, and repair-from-error-message "
        "has real diminishing returns past a couple of tries.",
        &g_t2s_max_attempts,
        2, 1, 10,
        PGC_SIGHUP,
        0, NULL, NULL, NULL);

    DefineCustomStringVariable(
        "fractalsql.text_to_sql_allowed_statements",
        "Statement types fractal_text_to_sql() may return.",
        "'select' (default) or 'select_insert_update'. The latter is "
        "materially higher risk -- table-scoped write grants stop an "
        "attacker touching the wrong table, they do not validate that a "
        "write is semantically correct. See docs/text-to-sql-setup.md "
        "before enabling it.",
        &g_t2s_allowed_stmts,
        "select",
        PGC_SIGHUP,
        0, NULL, NULL, NULL);

    DefineCustomBoolVariable(
        "fractalsql.text_to_sql_use_review",
        "Add an LLM self-review pass before EXPLAIN in fractal_text_to_sql().",
        "Default off for cost/latency, not safety -- review is just a "
        "second fractal_reason()-shaped call with a critique prompt, "
        "not a distinct security mechanism, and EXPLAIN plus the "
        "execution role's grants remain the real gates regardless of "
        "this setting. Roughly doubles LLM calls per attempt when on.",
        &g_t2s_use_review,
        false,
        PGC_SIGHUP,
        0, NULL, NULL, NULL);

    DefineCustomStringVariable(
        "fractalsql.enterprise_lib",
        "Path to the FractalSQL Enterprise core shared library.",
        "When set, QTL ledger (fractal_ledger_*) and CISO audit "
        "(fractal_audit_unpack) are activated by dlopen-ing this library "
        "on first use. When unset (or the file is absent), those functions "
        "raise 'enterprise tier not loaded' and the extension runs as "
        "community edition. The community archive this extension links "
        "does not compile those symbols, so the enterprise library must be "
        "present to resolve them. Reload after changing (PGC_SIGHUP).",
        &g_enterprise_lib,
        NULL,
        PGC_SIGHUP,
        GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

    DefineCustomStringVariable(
        "fractalsql.enterprise_ledger_key",
        "HMAC-SHA256 key authenticating the persisted QTL ledger blob.",
        "When non-empty, every fractal_ledger_flush() tags the persisted blob "
        "with HMAC-SHA256(key, blob) and every fractal_ledger_load() verifies "
        "the tag before decoding -- so a payload byte-flip or a re-encoded "
        "substitution is detected (cryptographic tamper-evidence), closing the "
        "structural-only gap. When empty (default), the ledger is validated "
        "against structural corruption only (truncation / count-length "
        "mismatch) -- the historical behavior. The raw bytes of this string are "
        "the HMAC key; keep it stable between flush and load. PGC_SUSET so a "
        "superuser can SET it per-session (ALTER SYSTEM for a persistent "
        "default). Superuser-only.",
        &g_enterprise_ledger_key,
        NULL,
        PGC_SUSET,
        GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

    DefineCustomBoolVariable(
        "fractalsql.enterprise_require_signature",
        "Require a valid detached Ed25519 signature on the enterprise .so.",
        "The 8-symbol dlsym sanity check in ensure_enterprise_lib() only "
        "proves a file has the right function names -- a tampered file with "
        "the same names sails through it untouched. When on, a sibling "
        "<fractalsql.enterprise_lib path>.sig file (64 raw bytes) must "
        "verify against a fixed FractalSQLabs Ed25519 public key before the "
        "library is dlopen'd; a missing .sig is refused the same as an "
        "invalid one. When off (default), a missing .sig only logs a "
        "WARNING and the library still loads -- backward compatible with "
        "unsigned releases / a sales-mediated distribution channel that "
        "doesn't need this yet. An INVALID signature (present but wrong) is "
        "ALWAYS refused regardless of this setting -- unambiguous tamper "
        "evidence, unlike a merely absent file. Superuser-only.",
        &g_enterprise_require_signature,
        false,
        PGC_SIGHUP,
        GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

    /* Plugin loading deferred to ensure_reasoning_ctx() — see comment there. */

    /* Capture whatever RESPONSE_MODE an operator set at the process
     * level, before any SQL function in this backend can run and
     * before fractal_text_to_sql() ever sets its own temporary value.
     * Plain malloc+memcpy, not pstrdup: this needs to survive for the
     * life of the backend process, independent of any PostgreSQL
     * memory context. Not strdup either: MSVC deprecates it in favor
     * of _strdup, and this file builds on Windows too. */
    {
        const char *v = getenv("FSQL_REASONING_HTTP_RESPONSE_MODE");
        if (v)
        {
            size_t len = strlen(v) + 1;
            g_response_mode_boot = malloc(len);
            if (g_response_mode_boot)
                memcpy(g_response_mode_boot, v, len);
        }
    }
}

void
_PG_fini(void)
{
    if (g_ctx)       { fsql_free(g_ctx);       g_ctx       = NULL; }
    if (g_reason_ctx) { fsql_free(g_reason_ctx); g_reason_ctx = NULL; }
    if (g_t2s_ctx)    { fsql_free(g_t2s_ctx);    g_t2s_ctx    = NULL; }
    if (g_embed_ctx)  { fsql_free(g_embed_ctx);  g_embed_ctx  = NULL; }
    g_reason_loaded = false;
    g_t2s_loaded    = false;
    g_embed_loaded  = false;

    /* Drop the enterprise core library AFTER the ctxs are freed: fsql_free
     * may invoke the storage VFS seal (no-op here) and -- if the vendored
     * community archive carries truth/shadow destroy -- destroy ledgers
     * the enterprise library allocated (same source, same malloc: safe).
     * dlclose after the ctxs stop referencing those symbols. */
    if (g_ent_handle)
    {
#if defined(_WIN32) || defined(_MSC_VER)
        FreeLibrary((HMODULE) g_ent_handle);
#else
        dlclose(g_ent_handle);
#endif
        g_ent_handle = NULL;
    }
    g_ent_attempted        = false;
    g_ent_loaded           = false;
    g_ent_ledger_flush      = NULL;
    g_ent_ledger_load       = NULL;
    g_ent_ledger_compact    = NULL;
    g_ent_ledger_reset_soft = NULL;
    g_ent_ledger_reset_hard = NULL;
    g_ent_ledger_truth_count  = NULL;
    g_ent_ledger_shadow_count = NULL;
    g_ent_audit_unpack      = NULL;
    g_ent_optimize_portfolio_multimodal = NULL;
    g_ent_optimize_portfolio_multimodal_ex = NULL;
    g_ent_optimize_portfolio_multimodal_pareto = NULL;
}

/* ------------------------------------------------------------------ */
/* Enterprise dlopen / dlsym                                           */
/* ------------------------------------------------------------------ */
static void *
ent_dlopen(const char *path)
{
#if defined(_WIN32) || defined(_MSC_VER)
    return (void *) LoadLibraryA(path);
#else
    return dlopen(path, RTLD_NOW | RTLD_LOCAL);
#endif
}

static void *
ent_dlsym(void *handle, const char *name)
{
#if defined(_WIN32) || defined(_MSC_VER)
    return (void *) GetProcAddress((HMODULE) handle, name);
#else
    return dlsym(handle, name);
#endif
}

static void
ent_dlclose(void *handle)
{
#if defined(_WIN32) || defined(_MSC_VER)
    FreeLibrary((HMODULE) handle);
#else
    dlclose(handle);
#endif
}

/* ------------------------------------------------------------------ */
/* Enterprise .so detached-signature verification (Ed25519)            */
/* ------------------------------------------------------------------ */
/* Optional hardening on top of the 8-symbol dlsym sanity check in
 * ensure_enterprise_lib(): that check only proves "this file has the
 * right function names," which a tampered file with the same names
 * sails through untouched. This verifies a detached Ed25519 signature
 * (a sibling <path>.sig file, exactly 64 raw bytes) over the enterprise
 * .so's exact bytes, against a fixed FractalSQLabs public key embedded
 * here. New enterprise releases only need a fresh signature from the
 * same long-lived private key -- no change to this extension required,
 * preserving the "drop-in .so, no rebuild" design goal a hash pin would
 * have broken (a hash would need updating on every enterprise release).
 *
 * FractalSQLabs's long-lived Ed25519 signing public key. The matching
 * private key is held offline in the enterprise release process, never
 * in either git repo. */
static const unsigned char FSQL_ENTERPRISE_PUBKEY[32] = {
    0xd5, 0xf6, 0x08, 0xa5, 0x8b, 0x1e, 0xb7, 0xe5, 0x9a, 0xcb, 0x8f, 0xab,
    0x80, 0x35, 0x9d, 0x58, 0x3f, 0x4e, 0xd1, 0xd1, 0xa2, 0x9c, 0x33, 0x6b,
    0xcb, 0x4b, 0x43, 0xcf, 0xf1, 0x07, 0x7f, 0xcb
};

typedef enum
{
    ENT_SIG_OK,         /* .sig present and verifies against the pubkey */
    ENT_SIG_MISSING,    /* no .sig file found -- soft unless require=on */
    ENT_SIG_INVALID,    /* .sig present but wrong -- always fatal */
    ENT_SIG_IOERROR     /* could not read the .so or .sig file at all */
} ent_sig_result_t;

/* Windows: the UCRT stdio path (fread() and fread_s() alike -- both were
 * tried and both fail identically) fail-fasts with STATUS_STACK_BUFFER_
 * OVERRUN inside its own internal invalid-parameter validation when called
 * from ent_verify_signature() in-process inside a real Postgres backend.
 * Root-caused via minidump forensics (gate 24, 2026-08-23): 100%
 * reproducible in that context, but never across five separate isolated
 * repros (standalone exe debug/release, LoadLibrary-loaded DLL, both
 * fread() and fread_s()) -- so whatever's wrong is inside the UCRT stdio
 * layer's state in this hosting context, not in the call sites or in our
 * logic. Read the two files via raw Win32 CreateFileA/ReadFile instead,
 * which shares no code path with CRT stdio at all. */
#if defined(_WIN32) || defined(_MSC_VER)
static bool
ent_read_file_win32(const char *path, void *buf, size_t len)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    bool ok = true;
    size_t total = 0;
    while (total < len)
    {
        DWORD chunk = (DWORD) ((len - total) > 0x10000000UL ? 0x10000000UL : (len - total));
        DWORD nread = 0;
        if (!ReadFile(h, (char *) buf + total, chunk, &nread, NULL) || nread == 0)
        {
            ok = false;
            break;
        }
        total += nread;
    }
    CloseHandle(h);
    return ok && total == len;
}
static bool
ent_file_size_win32(const char *path, long *out_len)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    LARGE_INTEGER sz;
    bool ok = GetFileSizeEx(h, &sz) && sz.QuadPart >= 0 && sz.QuadPart <= LONG_MAX;
    if (ok)
        *out_len = (long) sz.QuadPart;
    CloseHandle(h);
    return ok;
}
#endif

static ent_sig_result_t
ent_verify_signature(const char *so_path)
{
    char             sig_path[MAXPGPATH];
    unsigned char    sig_bytes[64];
    unsigned char   *so_bytes = NULL;
    long             so_len;
    ent_sig_result_t result = ENT_SIG_IOERROR;
    EVP_PKEY        *pkey = NULL;
    EVP_MD_CTX      *mdctx = NULL;

    snprintf(sig_path, sizeof(sig_path), "%s.sig", so_path);

#if defined(_WIN32) || defined(_MSC_VER)
    {
        long sig_len;
        if (!ent_file_size_win32(sig_path, &sig_len))
            return ENT_SIG_MISSING;
        /* Confirm the file is EXACTLY 64 bytes, not >=64 -- a longer file
         * silently truncated to 64 would otherwise verify against the
         * wrong (partial) signature. */
        if (sig_len != (long) sizeof(sig_bytes))
            return ENT_SIG_INVALID;   /* wrong-sized .sig -- corrupt/tampered, not "absent" */
        if (!ent_read_file_win32(sig_path, sig_bytes, sizeof(sig_bytes)))
            return ENT_SIG_IOERROR;
    }

    if (!ent_file_size_win32(so_path, &so_len))
        return ENT_SIG_IOERROR;
    so_bytes = (unsigned char *) malloc((size_t) so_len);
    if (so_bytes == NULL)
        return ENT_SIG_IOERROR;
    if (!ent_read_file_win32(so_path, so_bytes, (size_t) so_len))
    {
        free(so_bytes);
        return ENT_SIG_IOERROR;
    }
#else
    FILE *f;

    f = fopen(sig_path, "rb");
    if (f == NULL)
        return ENT_SIG_MISSING;
    {
        size_t n = fread(sig_bytes, 1, sizeof(sig_bytes), f);
        /* Confirm the file is EXACTLY 64 bytes, not >=64 -- a longer file
         * silently truncated to 64 by fread would otherwise verify
         * against the wrong (partial) signature. */
        int c = fgetc(f);
        fclose(f);
        if (n != sizeof(sig_bytes) || c != EOF)
            return ENT_SIG_INVALID;   /* wrong-sized .sig -- corrupt/tampered, not "absent" */
    }

    f = fopen(so_path, "rb");
    if (f == NULL)
        return ENT_SIG_IOERROR;
    if (fseek(f, 0, SEEK_END) != 0)
    {
        fclose(f);
        return ENT_SIG_IOERROR;
    }
    so_len = ftell(f);
    if (so_len < 0 || fseek(f, 0, SEEK_SET) != 0)
    {
        fclose(f);
        return ENT_SIG_IOERROR;
    }
    so_bytes = (unsigned char *) malloc((size_t) so_len);
    if (so_bytes == NULL)
    {
        fclose(f);
        return ENT_SIG_IOERROR;
    }
    if (fread(so_bytes, 1, (size_t) so_len, f) != (size_t) so_len)
    {
        fclose(f);
        free(so_bytes);
        return ENT_SIG_IOERROR;
    }
    fclose(f);
#endif

    pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                       FSQL_ENTERPRISE_PUBKEY,
                                       sizeof(FSQL_ENTERPRISE_PUBKEY));
    if (pkey == NULL)
    {
        free(so_bytes);
        return ENT_SIG_IOERROR;
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
    {
        EVP_PKEY_free(pkey);
        free(so_bytes);
        return ENT_SIG_IOERROR;
    }

    /* Ed25519 is "PureEdDSA" in OpenSSL's EVP API -- one-shot verify over
     * the whole message, no Update() calls, no pre-hash digest type. */
    if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pkey) == 1 &&
        EVP_DigestVerify(mdctx, sig_bytes, sizeof(sig_bytes),
                         so_bytes, (size_t) so_len) == 1)
        result = ENT_SIG_OK;
    else
        result = ENT_SIG_INVALID;

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    free(so_bytes);
    return result;
}

/* Lazily dlopen the enterprise core library and dlsym the eight
 * ledger/audit symbols. Cached per-backend (g_ent_attempted): a single
 * attempt, success or failure, sticks for the backend's life -- flip
 * the GUC or remove the file and start a new backend to re-evaluate.
 * Returns true when the surface is live. */
static bool
ensure_enterprise_lib(void)
{
    if (g_ent_loaded)
        return true;
    if (g_ent_attempted)
        return false;
    g_ent_attempted = true;

    if (g_enterprise_lib == NULL || g_enterprise_lib[0] == '\0')
        return false;

    ent_sig_result_t sig = ent_verify_signature(g_enterprise_lib);
    if (sig == ENT_SIG_INVALID)
    {
        ereport(WARNING,
                (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                 errmsg("fractalsql: enterprise library \"%s\" failed "
                        "signature verification -- refusing to load",
                        g_enterprise_lib),
                 errhint("The .so or its .sig does not match the expected "
                         "FractalSQLabs signing key -- the file may be "
                         "corrupt or tampered. Re-download it, or contact "
                         "your vendor.")));
        return false;
    }
    if (sig == ENT_SIG_MISSING && g_enterprise_require_signature)
    {
        ereport(WARNING,
                (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                 errmsg("fractalsql: no signature found for enterprise "
                        "library \"%s\" (expected \"%s.sig\")",
                        g_enterprise_lib, g_enterprise_lib),
                 errhint("fractalsql.enterprise_require_signature is on. "
                         "Place the matching .sig file alongside the "
                         "library, or turn this setting off to load "
                         "unsigned libraries.")));
        return false;
    }
    if (sig == ENT_SIG_MISSING)
        ereport(WARNING,
                (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                 errmsg("fractalsql: no signature found for enterprise "
                        "library \"%s\" -- loading unverified",
                        g_enterprise_lib),
                 errhint("Set fractalsql.enterprise_require_signature = on "
                         "to refuse unsigned enterprise libraries.")));

    void *h = ent_dlopen(g_enterprise_lib);
    if (h == NULL)
    {
        ereport(WARNING,
                (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                 errmsg("fractalsql: could not load enterprise library \"%s\"",
                        g_enterprise_lib),
                 errhint("Install FractalSQL Enterprise and set "
                         "fractalsql.enterprise_lib to its path, or unset it "
                         "to silence this warning.")));
        return false;
    }

    g_ent_ledger_flush       = (ent_ledger_void_fn)  ent_dlsym(h, "fsql_ledger_flush");
    g_ent_ledger_load        = (ent_ledger_void_fn)  ent_dlsym(h, "fsql_ledger_load");
    g_ent_ledger_compact     = (ent_ledger_void_fn)  ent_dlsym(h, "fsql_ledger_compact");
    g_ent_ledger_reset_soft  = (ent_ledger_void_fn)  ent_dlsym(h, "fsql_ledger_reset_soft");
    g_ent_ledger_reset_hard  = (ent_ledger_void_fn)  ent_dlsym(h, "fsql_ledger_reset_hard");
    g_ent_ledger_truth_count = (ent_ledger_count_fn) ent_dlsym(h, "fsql_ledger_truth_count");
    g_ent_ledger_shadow_count= (ent_ledger_count_fn) ent_dlsym(h, "fsql_ledger_shadow_count");
    g_ent_audit_unpack       = (ent_audit_unpack_fn) ent_dlsym(h, "fsql_audit_unpack");

    if (!g_ent_ledger_flush || !g_ent_ledger_load || !g_ent_ledger_compact ||
        !g_ent_ledger_reset_soft || !g_ent_ledger_reset_hard ||
        !g_ent_ledger_truth_count || !g_ent_ledger_shadow_count ||
        !g_ent_audit_unpack)
    {
        ereport(WARNING,
                (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                 errmsg("fractalsql: \"%s\" is missing expected enterprise "
                        "symbols (fsql_ledger_*/fsql_audit_unpack) -- not a "
                        "FractalSQL Enterprise core library?",
                        g_enterprise_lib)));
        ent_dlclose(h);
        g_ent_ledger_flush = NULL;
        g_ent_ledger_load = NULL;
        g_ent_ledger_compact = NULL;
        g_ent_ledger_reset_soft = NULL;
        g_ent_ledger_reset_hard = NULL;
        g_ent_ledger_truth_count = NULL;
        g_ent_ledger_shadow_count = NULL;
        g_ent_audit_unpack = NULL;
        return false;
    }

    /* Optional 9th symbol -- absent in older enterprise builds, does not
     * fail activation. */
    g_ent_optimize_portfolio_multimodal =
        (ent_portfolio_multimodal_fn) ent_dlsym(h, "fsql_optimize_portfolio_multimodal");

    /* Optional 10th symbol -- same tolerant-absence convention. */
    g_ent_optimize_portfolio_multimodal_pareto =
        (ent_portfolio_multimodal_pareto_fn) ent_dlsym(h, "fsql_optimize_portfolio_multimodal_pareto");

    /* Optional 11th symbol -- same tolerant-absence convention. */
    g_ent_optimize_portfolio_multimodal_ex =
        (ent_portfolio_multimodal_ex_fn) ent_dlsym(h, "fsql_optimize_portfolio_multimodal_ex");

    g_ent_handle = h;
    g_ent_loaded = true;
    return true;
}

/* Common error for the enterprise SQL functions when the surface is
 * dormant. ereport(ERROR) throws, so callers do not return. */
static void
enterprise_not_loaded_error(void)
{
    ereport(ERROR,
            (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
             errmsg("fractalsql: enterprise tier not loaded"),
             errhint("QTL ledger and CISO audit are FractalSQL Enterprise "
                     "features. Set fractalsql.enterprise_lib to the path of "
                     "the enterprise core library "
                     "(libfractalsql-enterprise-sovereign-c.so / .dll / "
                     ".dylib) and reconnect, or contact your vendor for "
                     "FractalSQL Enterprise.")));
}

/* ------------------------------------------------------------------ */
/* QTL ledger storage VFS (Postgres-backed)                            */
/* ------------------------------------------------------------------ */
/* The enterprise core's fsql_ledger_flush() encodes truth+shadow into a
 * QTL blob and calls storage_vfs.write_entry(kind=1,...); fsql_ledger_load()
 * calls read_entry to pull it back. We persist an APPEND-ONLY chain of
 * bytea rows per `kind` in fractalsql_ledger: each row links to
 * its predecessor via entry_hash = SHA256(prev_hash || blob || mac), so a
 * rewritten row breaks the chain and a deleted row leaves a visible gap in
 * the bigserial id sequence. ledger_read_entry always returns the LATEST
 * row for a kind, so the core still sees "the current blob" -- only the
 * storage layer knows it's backed by history. The table is created lazily
 * on first use so a community-only deployment never carries it.
 * seal_ledger is a no-op: each flush is an immediate INSERT (nothing
 * pending to commit) and it is called from fsql_free during teardown,
 * where SPI may not be usable. */
static bool
ledger_ensure_table(void)
{
    /* Detect a pre-chain table (kind PRIMARY KEY, no id/prev_hash/
     * entry_hash -- a single last-writer-wins row per kind, not a chain)
     * and migrate. Nothing worth preserving from that shape: it never
     * carried real history. One query covers both "does the table exist"
     * and "does it have the new shape" so a fresh install (neither) skips
     * straight to CREATE TABLE with no spurious NOTICE. */
    int rc = SPI_execute(
        "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_tables "
        "                WHERE tablename = 'fractalsql_ledger'),"
        "       EXISTS (SELECT 1 FROM information_schema.columns "
        "                WHERE table_name = 'fractalsql_ledger' "
        "                  AND column_name = 'id')",
        true, 1);
    if (rc != SPI_OK_SELECT || SPI_processed == 0)
        return false;

    bool  isnull1, isnull2;
    Datum d_exists = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &isnull1);
    Datum d_has_id = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 2, &isnull2);
    bool  tbl_exists     = !isnull1 && DatumGetBool(d_exists);
    bool  has_new_schema = !isnull2 && DatumGetBool(d_has_id);

    if (tbl_exists && !has_new_schema)
    {
        ereport(NOTICE,
                (errmsg("fractalsql: migrating fractalsql_ledger from the "
                        "single-row snapshot schema to the append-only "
                        "chain schema -- prior state was a single "
                        "last-writer-wins snapshot with no history to "
                        "preserve; starting a fresh chain")));
        if (SPI_execute("DROP TABLE fractalsql_ledger", false, 0) != SPI_OK_UTILITY)
            return false;
    }

    return SPI_execute(
        "CREATE TABLE IF NOT EXISTS fractalsql_ledger ("
        "  id         bigserial   PRIMARY KEY,"
        "  kind       integer     NOT NULL,"
        "  blob       bytea       NOT NULL,"
        "  mac        bytea,"                 /* HMAC-SHA256 tag (32B), NULL when the key is unset */
        "  prev_hash  bytea       NOT NULL,"  /* entry_hash of the prior row for this kind; all-zero = genesis */
        "  entry_hash bytea       NOT NULL,"  /* SHA256(prev_hash || blob || mac) -- the chain link */
        "  sealed     boolean     NOT NULL DEFAULT false,"
        "  updated    timestamptz NOT NULL DEFAULT now()"
        ")", false, 0) == SPI_OK_UTILITY
        && SPI_execute(
        "CREATE INDEX IF NOT EXISTS fractalsql_ledger_kind_id_idx "
        "ON fractalsql_ledger (kind, id DESC)",
        false, 0) == SPI_OK_UTILITY;
}

static int
ledger_write_entry(fsql_storage_user_ctx user, int kind,
                   const void *payload, size_t len)
{
    (void) user;
    if (SPI_connect() != SPI_OK_CONNECT)
        return FSQL_ESTORAGE;

    /* Serialize concurrent writers of the SAME kind for the remainder of
     * this transaction -- acquired BEFORE anything else, including
     * ledger_ensure_table(). "read the current head, then INSERT a row
     * that links to it" is a read-then-write sequence, and without a lock
     * two concurrent flushes could both read the same head and both
     * insert a row claiming it as prev_hash -- a fork fractal_ledger_
     * verify() would (correctly) report as a chain-link break, even
     * though nothing was actually tampered.
     *
     * This MUST come before ledger_ensure_table(): its idempotent CREATE
     * TABLE/INDEX IF NOT EXISTS statements take their own transient
     * relation-level locks even when they turn out to be no-ops, and
     * acquiring the advisory lock AFTER that created exactly the AB-BA
     * deadlock this comment used to warn about only in the abstract --
     * worker A holding the relation lock from its ensure_table check
     * while waiting on the advisory lock (held by worker B), worker B
     * holding the advisory lock while its own INSERT waits on the
     * relation lock (held by worker A). Locking here FIRST means nobody
     * touches the relation at all until they already hold the advisory
     * lock, so only one lock is ever contended for at a time. Released
     * automatically at the end of the calling statement's transaction.
     *
     * read_only=false (not true) on BOTH this call and the head-read
     * below is load-bearing, not cosmetic: SPI's read_only=true reuses
     * whatever snapshot was already active for the calling statement
     * rather than taking a fresh one ("avoid the overhead of maintaining
     * a fresh snapshot when it isn't required", per SPI_execute's own
     * documentation) -- under READ COMMITTED that snapshot was captured
     * when the OUTER `SELECT fractal_ledger_flush()` statement began,
     * before this lock was even requested. With read_only=true here, 8
     * concurrent flushes all launched around the same instant would each
     * still see the SAME pre-lock snapshot after acquiring the lock in
     * turn -- serialized in acquisition order, but each one blind to
     * what the PRIOR lock holder just committed, reconstructing the
     * exact fork this lock exists to prevent. (Caught by gate 25 Phase
     * C(b) during development: all 8 workers logged the identical
     * prev_hash despite no deadlock and no error.) read_only=false forces
     * a fresh snapshot at each of these two calls, so the head-read after
     * acquiring the lock actually observes the latest commit. */
    {
        /* Two-key form (key1, key2) namespaces this lock against any
         * OTHER advisory-lock use in the same database -- key1 is a
         * fixed, arbitrary-but-stable tag ('FSL1' packed as int4) unique
         * to this ledger, key2 is `kind`, so different kinds (if this
         * ever carries more than kind=1) serialize independently. */
        Oid   lk_argtypes[2] = { INT4OID, INT4OID };
        Datum lk_values[2]    = { Int32GetDatum(0x46534C31), Int32GetDatum(kind) };
        char  lk_nulls[2]     = { ' ', ' ' };
        if (SPI_execute_with_args(
                "SELECT pg_advisory_xact_lock($1, $2)",
                2, lk_argtypes, lk_values, lk_nulls, false, 1) != SPI_OK_SELECT)
        {
            SPI_finish();
            return FSQL_ESTORAGE;
        }
    }

    if (!ledger_ensure_table())
    {
        SPI_finish();
        return FSQL_ESTORAGE;
    }

    /* Chain link: prev_hash is the latest row's entry_hash for this kind,
     * or a fixed all-zero sentinel for the first (genesis) entry --
     * entry_hash always covers exactly 32 bytes of "prev", never a SQL
     * NULL, so verification has one code path for every row. */
    uint8_t prev_hash[32];
    memset(prev_hash, 0, sizeof(prev_hash));
    {
        Oid   pk_argtypes[1] = { INT4OID };
        Datum pk_values[1]    = { Int32GetDatum(kind) };
        char  pk_nulls[1]     = { ' ' };
        int   prc = SPI_execute_with_args(
            "SELECT entry_hash FROM fractalsql_ledger "
            "WHERE kind = $1 ORDER BY id DESC LIMIT 1",
            1, pk_argtypes, pk_values, pk_nulls, false, 1);
        if (prc != SPI_OK_SELECT)
        {
            SPI_finish();
            return FSQL_ESTORAGE;
        }
        if (SPI_processed > 0)
        {
            bool  pisnull;
            Datum ph = SPI_getbinval(SPI_tuptable->vals[0],
                                     SPI_tuptable->tupdesc, 1, &pisnull);
            if (!pisnull)
            {
                bytea *phb = DatumGetByteaPCopy(ph);
                if (VARSIZE(phb) - VARHDRSZ == 32)
                    memcpy(prev_hash, VARDATA(phb), 32);
            }
        }
    }

    bytea *b = (bytea *) palloc(len + VARHDRSZ);
    SET_VARSIZE(b, len + VARHDRSZ);
    memcpy(VARDATA(b), payload, len);

    /* MAC envelope: if a ledger key is configured, tag the blob with
     * HMAC-SHA256(key, blob) so a later load can detect a payload
     * byte-flip or a re-encoded substitution (the structural decode
     * check alone cannot). Empty key => no mac. */
    uint8_t     mac_tag[32];
    bool        have_mac = false;
    const char *key = g_enterprise_ledger_key;
    if (key && key[0] != '\0')
    {
        fsql_hmac_sha256((const uint8_t *) key, strlen(key),
                         (const uint8_t *) payload, len, mac_tag);
        have_mac = true;
    }

    /* Chain link: entry_hash = SHA256(prev_hash || blob || mac).
     * Computed unconditionally -- even with no key configured (mac absent
     * from the hash input), this still makes every historical row's
     * integrity and ordering independently verifiable, without requiring
     * a key at all. */
    uint8_t entry_hash[32];
    {
        size_t   buflen = 32 + len + (have_mac ? 32 : 0);
        uint8_t *buf    = (uint8_t *) palloc(buflen);
        memcpy(buf, prev_hash, 32);
        memcpy(buf + 32, payload, len);
        if (have_mac) memcpy(buf + 32 + len, mac_tag, 32);
        fsql_sha256(buf, buflen, entry_hash);
        pfree(buf);
    }

    bytea *mac = NULL;
    if (have_mac)
    {
        mac = (bytea *) palloc(32 + VARHDRSZ);
        SET_VARSIZE(mac, 32 + VARHDRSZ);
        memcpy(VARDATA(mac), mac_tag, 32);
    }
    bytea *prev_hash_b = (bytea *) palloc(32 + VARHDRSZ);
    SET_VARSIZE(prev_hash_b, 32 + VARHDRSZ);
    memcpy(VARDATA(prev_hash_b), prev_hash, 32);
    bytea *entry_hash_b = (bytea *) palloc(32 + VARHDRSZ);
    SET_VARSIZE(entry_hash_b, 32 + VARHDRSZ);
    memcpy(VARDATA(entry_hash_b), entry_hash, 32);

    Oid   argtypes[5] = { INT4OID, BYTEAOID, BYTEAOID, BYTEAOID, BYTEAOID };
    Datum values[5]    = { Int32GetDatum(kind), PointerGetDatum(b),
                           mac ? PointerGetDatum(mac) : (Datum) 0,
                           PointerGetDatum(prev_hash_b),
                           PointerGetDatum(entry_hash_b) };
    char  nulls[5]     = { ' ', ' ', mac ? ' ' : 'n', ' ', ' ' };

    /* Plain INSERT -- append-only, no ON CONFLICT. id auto-increments;
     * a deleted row later leaves a visible gap in that sequence. */
    int rc = SPI_execute_with_args(
        "INSERT INTO fractalsql_ledger "
        "(kind, blob, mac, prev_hash, entry_hash, sealed, updated) "
        "VALUES ($1, $2, $3, $4, $5, false, now())",
        5, argtypes, values, nulls, false, 0);

    SPI_finish();
    return (rc < 0) ? FSQL_ESTORAGE : FSQL_OK;
}

static int
ledger_read_entry(fsql_storage_user_ctx user, int kind,
                  const void **payload_out, size_t *len_out)
{
    (void) user;
    *payload_out = NULL;
    *len_out     = 0;

    if (SPI_connect() != SPI_OK_CONNECT)
        return FSQL_ESTORAGE;
    if (!ledger_ensure_table())
    {
        SPI_finish();
        return FSQL_ESTORAGE;
    }

    Oid   argtypes[1] = { INT4OID };
    Datum values[1]    = { Int32GetDatum(kind) };
    char  nulls[1]     = { ' ' };

    int rc = SPI_execute_with_args(
        "SELECT blob FROM fractalsql_ledger "
        "WHERE kind = $1 ORDER BY id DESC LIMIT 1",
        1, argtypes, values, nulls, true, 1);
    if (rc != SPI_OK_SELECT)
    {
        SPI_finish();
        return FSQL_ESTORAGE;
    }
    if (SPI_processed == 0)
    {
        SPI_finish();
        return FSQL_ESTORAGE_UNAVAILABLE;   /* first load, no ledger yet */
    }

    bool  isnull;
    Datum blob_datum = SPI_getbinval(SPI_tuptable->vals[0],
                                     SPI_tuptable->tupdesc, 1, &isnull);
    if (isnull)
    {
        SPI_finish();
        return FSQL_ESTORAGE;
    }

    /* Copy into the caller's memory context: fsql_ledger_load reads the
     * buffer synchronously and never frees it (per the VFS contract), and
     * SPI's context is reset on SPI_finish. */
    bytea *b = DatumGetByteaPCopy(blob_datum);
    SPI_finish();

    *payload_out = VARDATA(b);
    *len_out     = VARSIZE(b) - VARHDRSZ;
    return FSQL_OK;
}

static int
ledger_seal_ledger(fsql_storage_user_ctx user)
{
    /* No-op: each flush is an immediate UPSERT (nothing pending to seal),
     * and this is called from fsql_free at teardown where SPI may not be
     * usable. Never fail teardown. */
    (void) user;
    return FSQL_OK;
}

static const fsql_storage_vfs_t g_ledger_vfs = {
    NULL,                /* user_ctx -- callbacks use SPI (backend-global) */
    ledger_write_entry,
    ledger_read_entry,
    ledger_seal_ledger
};

/* Lazy sovereign ctx init for SEARCH -- never attempts to load the
 * reasoning plugin, so a broken/misconfigured plugin can't take down
 * Sniper/Scout search. Called by every search-only SQL entry-point
 * before any fsql_search* call. The Postgres-backed storage VFS above
 * is injected here so the enterprise ledger functions (when activated)
 * can persist QTL blobs to fractalsql_ledger; search itself never
 * touches it, so community-only operation is unaffected. */
static void
ensure_search_ctx(void)
{
    if (g_ctx) return;

    g_ctx = fsql_new_sovereign(&g_ledger_vfs, NULL);
    if (!g_ctx)
        ereport(ERROR,
                (errcode(ERRCODE_OUT_OF_MEMORY),
                 errmsg("fractalsql: fsql_new_sovereign failed")));
}

/* Shared plugin-load step for the three tier-specific ensure_*_ctx()
 * functions below. Each caller has already setenv()'d its own tier's
 * config; this just allocates *ctx_out on first use (independent of
 * g_ctx -- fsql_dispatch_ai doesn't need search state) and loads the
 * plugin into it. A failed load raises ERROR but does NOT null out
 * *ctx_out if it was already allocated, matching ensure_search_ctx():
 * the caller's *loaded_out flag (left false) gates the retry on the
 * next call, not a fresh allocation. */
static void
ensure_reasoning_tier_ctx(fsql_ctx **ctx_out, bool *loaded_out,
                          const char *tier_name)
{
    if (*ctx_out == NULL)
    {
        *ctx_out = fsql_new_sovereign(NULL, NULL);
        if (!*ctx_out)
            ereport(ERROR,
                    (errcode(ERRCODE_OUT_OF_MEMORY),
                     errmsg("fractalsql: fsql_new_sovereign failed (%s)",
                            tier_name)));
    }

    int rc = fsql_load_reasoning(*ctx_out, g_reasoning_plugin);
    if (rc != 0)
    {
        const char *err = fsql_last_error(*ctx_out);
        ereport(ERROR,
                (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                 errmsg("fractalsql: failed to load reasoning plugin "
                        "\"%s\" for %s (rc=%d): %s",
                        g_reasoning_plugin, tier_name, rc,
                        err && *err ? err : "(no detail)")));
    }

    *loaded_out = true;
}

/* Shared by ensure_reason_ctx()/ensure_text_to_sql_ctx() -- both chat
 * tiers forward the same four reasoning-effort GUCs identically.
 * ensure_embed_ctx() does NOT call this; it unsetenv()s all four
 * itself, since http_think has no embedding-mode meaning. */
static void
apply_think_env(void)
{
    if (g_http_think && *g_http_think)
        setenv("FSQL_REASONING_HTTP_THINK", g_http_think, 1);
    else
        unsetenv("FSQL_REASONING_HTTP_THINK");

    if (g_http_think_provider && *g_http_think_provider)
        setenv("FSQL_REASONING_HTTP_THINK_PROVIDER", g_http_think_provider, 1);
    else
        unsetenv("FSQL_REASONING_HTTP_THINK_PROVIDER");

    if (g_http_native_url && *g_http_native_url)
        setenv("FSQL_REASONING_HTTP_NATIVE_URL", g_http_native_url, 1);
    else
        unsetenv("FSQL_REASONING_HTTP_NATIVE_URL");

    if (g_http_num_ctx > 0)
    {
        char num_ctx_str[32];
        snprintf(num_ctx_str, sizeof num_ctx_str, "%d", g_http_num_ctx);
        setenv("FSQL_REASONING_HTTP_NUM_CTX", num_ctx_str, 1);
    }
    else
        unsetenv("FSQL_REASONING_HTTP_NUM_CTX");
}

/* fractal_reason(): chat mode. Explicit unsetenv() of MODE/SYSTEM_TAG
 * so a value set by a different tier earlier in this backend (e.g.
 * fractal_embed() called first) can't leak into this tier's getenv().
 *
 * RESPONSE_MODE is fractal_reason()'s own opt-in lever
 * (FSQL_REASONING_HTTP_RESPONSE_MODE), an operator-set process
 * environment variable, never a value this file computes itself. We
 * assert the value captured once at _PG_init (g_response_mode_boot)
 * rather than reading whatever is currently in the process
 * environment: fractal_text_to_sql() temporarily sets this same
 * variable to "code" for its own GENERATE step and clears it right
 * after (see ensure_text_to_sql_ctx() below), but if that load ever
 * fails partway through, an ereport(ERROR) unwinds past the cleanup
 * and leaves "code" sitting in the environment for the rest of the
 * backend's life. Asserting our own captured value here, instead of
 * trusting ambient state, means this load is correct regardless of
 * what any other tier's load left behind. */
static void
ensure_reason_ctx(void)
{
    if (g_reason_loaded) return;
    if (!g_reasoning_plugin || !*g_reasoning_plugin) return;

    if (g_http_url   && *g_http_url)
        setenv("FSQL_REASONING_HTTP_URL",   g_http_url,   1);
    if (g_http_token && *g_http_token)
        setenv("FSQL_REASONING_HTTP_TOKEN", g_http_token, 1);
    if (g_http_model && *g_http_model)
        setenv("FSQL_REASONING_HTTP_MODEL", g_http_model, 1);
    if (g_http_allow_plain)
        setenv("FSQL_REASONING_HTTP_ALLOW_PLAINTEXT", "1", 1);
    unsetenv("FSQL_REASONING_HTTP_MODE");
    unsetenv("FSQL_REASONING_HTTP_SYSTEM_TAG");
    if (g_response_mode_boot && *g_response_mode_boot)
        setenv("FSQL_REASONING_HTTP_RESPONSE_MODE", g_response_mode_boot, 1);
    else
        unsetenv("FSQL_REASONING_HTTP_RESPONSE_MODE");
    apply_think_env();

    ensure_reasoning_tier_ctx(&g_reason_ctx, &g_reason_loaded, "fractal_reason");
}

/* fractal_text_to_sql()'s GENERATE step: chat mode, RESPONSE_MODE=code
 * so the plugin's fenced-block extraction (including its "2+ blocks ->
 * fail, don't guess" rule) does the SQL cleanup. SYSTEM_TAG is derived,
 * not a GUC: this extension only ever targets PostgreSQL, so the major
 * version is read from the live backend's server_version_num GUC (not
 * the PG_VERSION_NUM this .so was compiled against -- always identical
 * in practice since PG_MODULE_MAGIC enforces a matching-major load, but
 * asking the running backend is the more honest source) and appended
 * with no separator, e.g. "postgresql18". */
static void
ensure_text_to_sql_ctx(void)
{
    if (g_t2s_loaded) return;
    if (!g_reasoning_plugin || !*g_reasoning_plugin) return;

    if (g_http_url   && *g_http_url)
        setenv("FSQL_REASONING_HTTP_URL",   g_http_url,   1);
    if (g_http_token && *g_http_token)
        setenv("FSQL_REASONING_HTTP_TOKEN", g_http_token, 1);
    if (g_http_model && *g_http_model)
        setenv("FSQL_REASONING_HTTP_MODEL", g_http_model, 1);
    if (g_http_allow_plain)
        setenv("FSQL_REASONING_HTTP_ALLOW_PLAINTEXT", "1", 1);
    unsetenv("FSQL_REASONING_HTTP_MODE");
    /* Hardcoded, not user-configurable. Cleaned up right after init
     * below so it can't leak into a later fractal_reason() call and
     * override that function's own RESPONSE_MODE lever. */
    setenv("FSQL_REASONING_HTTP_RESPONSE_MODE", "code", 1);

    /* missing_ok=true: server_version_num is a core GUC that always
     * exists, but a lookup failure here should degrade to the
     * un-suffixed tag, not break fractal_text_to_sql() over a cosmetic
     * prompt hint. restrict_privileged=false: this GUC has no
     * visibility restriction -- any role can already read it via
     * SHOW/current_setting(), same as this call exposes. */
    const char *ver_num_str = GetConfigOption("server_version_num", true, false);
    char system_tag[32];
    if (ver_num_str)
        snprintf(system_tag, sizeof system_tag, "postgresql%d", atoi(ver_num_str) / 10000);
    else
        snprintf(system_tag, sizeof system_tag, "postgresql");
    setenv("FSQL_REASONING_HTTP_SYSTEM_TAG", system_tag, 1);
    apply_think_env();

    ensure_reasoning_tier_ctx(&g_t2s_ctx, &g_t2s_loaded, "fractal_text_to_sql");
    unsetenv("FSQL_REASONING_HTTP_RESPONSE_MODE");
}

/* fractal_embed(): embedding mode. http_embed_url has no fallback to
 * http_url (different endpoint path, see the GUC's own comment in
 * _PG_init) -- errors clearly if unset rather than silently posting an
 * embedding-shaped body at a chat completions URL. http_embed_model
 * unset means "don't setenv MODEL at all", not "reuse http_model" --
 * letting the plugin's own embedding-mode default (text-embedding-3-
 * small) apply instead of whatever chat model is configured. */
static void
ensure_embed_ctx(void)
{
    if (g_embed_loaded) return;
    if (!g_reasoning_plugin || !*g_reasoning_plugin) return;
    if (!g_http_embed_url || !*g_http_embed_url)
        ereport(ERROR,
                (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                 errmsg("fractal_embed: fractalsql.http_embed_url is not configured"),
                 errhint("Set fractalsql.http_embed_url to the provider's "
                         "embeddings endpoint URL (e.g. .../v1/embeddings) "
                         "and reconnect.")));

    setenv("FSQL_REASONING_HTTP_URL", g_http_embed_url, 1);
    if (g_http_token && *g_http_token)
        setenv("FSQL_REASONING_HTTP_TOKEN", g_http_token, 1);
    if (g_http_embed_model && *g_http_embed_model)
        setenv("FSQL_REASONING_HTTP_MODEL", g_http_embed_model, 1);
    else
        unsetenv("FSQL_REASONING_HTTP_MODEL");
    if (g_http_allow_plain)
        setenv("FSQL_REASONING_HTTP_ALLOW_PLAINTEXT", "1", 1);
    setenv("FSQL_REASONING_HTTP_MODE", "embedding", 1);
    unsetenv("FSQL_REASONING_HTTP_SYSTEM_TAG");
    /* RESPONSE_MODE has no embedding-mode meaning -- explicit unsetenv
     * so a "code" value left behind by an interrupted text_to_sql load
     * (see ensure_reason_ctx()'s comment above) can't reach here either. */
    unsetenv("FSQL_REASONING_HTTP_RESPONSE_MODE");
    /* http_think has no embedding-mode meaning -- explicit unsetenv, not
     * apply_think_env(), since a GUC set for the chat tiers must never
     * leak into an embedding request in the same backend. */
    unsetenv("FSQL_REASONING_HTTP_THINK");
    unsetenv("FSQL_REASONING_HTTP_THINK_PROVIDER");
    unsetenv("FSQL_REASONING_HTTP_NATIVE_URL");
    unsetenv("FSQL_REASONING_HTTP_NUM_CTX");

    ensure_reasoning_tier_ctx(&g_embed_ctx, &g_embed_loaded, "fractal_embed");
}

/* ------------------------------------------------------------------ */
/* Helpers — array marshalling + JSON best_point extraction           */
/* ------------------------------------------------------------------ */

static double *
float8_array_to_doubles(ArrayType *arr, int *out_n)
{
    if (ARR_NDIM(arr) != 1 || ARR_HASNULL(arr))
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("fractalsql: query must be 1-D non-null float8[]")));
    /* Reject a non-float8 array (e.g. int8[]) before deconstruct_array
     * reinterprets the payload as float8. spi_scan_corpus's column guard
     * already catches the common case (a non-array scalar column); this
     * catches a wrong-element-type array argument reaching us directly. */
    if (ARR_ELEMTYPE(arr) != FLOAT8OID)
        ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH),
                        errmsg("fractalsql: query must be float8[], got %s",
                               format_type_be(ARR_ELEMTYPE(arr)))));
    int n = ARR_DIMS(arr)[0];
    if (n <= 0)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("fractalsql: query must be non-empty")));
    Datum *ds;
    int    n2;
    bool  *nulls;
    deconstruct_array(arr, FLOAT8OID, sizeof(float8), FLOAT8PASSBYVAL, 'd',
                      &ds, &nulls, &n2);
    double *out = palloc(n2 * sizeof(double));
    for (int i = 0; i < n2; i++) out[i] = DatumGetFloat8(ds[i]);
    *out_n = n2;
    return out;
}

static ArrayType *
doubles_to_float8_array(const double *v, int n)
{
    Datum *ds = palloc(n * sizeof(Datum));
    for (int i = 0; i < n; i++) ds[i] = Float8GetDatum(v[i]);
    return construct_array(ds, n, FLOAT8OID, sizeof(float8), FLOAT8PASSBYVAL, 'd');
}

/* fsql_extract_best_point() / fsql_parse_embedding_array() -- moved to
 * fractalsql_parse.c (a separate, postgres.h-free translation unit) so
 * a standalone libFuzzer driver can link against them directly; see
 * that file's header comment and tests/fuzz/README.md. */

/* Single SFS call. Uses query as 1-row dummy corpus; we only consume
 * best_point or the full JSON depending on caller. Returns the JSON
 * pointer (owned by g_ctx; valid until next fsql_search* call).
 *
 * "no_corpus":true tells run_search (in the vendored core) that
 * the 1-row corpus above is the dummy-self-reference convention, not
 * a real table -- routing this call through real SFS convergence
 * (sfs_converge_c) instead of the brute-force retrieval path, which
 * would otherwise treat a 1-row "corpus" containing only the query as
 * a trivial self-match and return the input unchanged. Key names here
 * (iterations/population_size/diffusion_factor/walk) must match
 * run_search's json_get_int/json_get_double keys exactly. */
static const char *
run_sfs(double *query, int dim,
        int iterations, int pop_size, int diff_factor,
        size_t *out_len)
{
    ensure_search_ctx();
    char params[160];
    snprintf(params, sizeof params,
        "{\"iterations\":%d,\"population_size\":%d,"
        "\"diffusion_factor\":%d,\"walk\":0.5,\"no_corpus\":true}",
        iterations, pop_size, diff_factor);

    const char *result_json = NULL;
    size_t      result_len  = 0;
    int rc = fsql_search_ptr(g_ctx,
                             query, /*n_rows*/ 1, (size_t) dim,
                             query, (size_t) dim,
                             /*k*/ 1,
                             params, strlen(params),
                             &result_json, &result_len);
    if (rc != 0 || !result_json) {
        const char *err = fsql_last_error(g_ctx);
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("fractalsql: fsql_search_ptr rc=%d: %s",
                        rc, err && *err ? err : "(no detail)")));
    }
    *out_len = result_len;
    return result_json;
}

/* ------------------------------------------------------------------ */
/* fractal_search — query → refined best_point as float8[].           */
/* ------------------------------------------------------------------ */

PG_FUNCTION_INFO_V1(fractal_search);

Datum
fractal_search(PG_FUNCTION_ARGS)
{
    ArrayType *query_arr = PG_GETARG_ARRAYTYPE_P(0);
    int32      iterations = PG_GETARG_INT32(1);
    int32      pop_size   = PG_GETARG_INT32(2);
    int32      diff_f     = PG_GETARG_INT32(3);

    int     dim;
    double *query = float8_array_to_doubles(query_arr, &dim);
    validate_sfs_params(dim, iterations, pop_size, diff_f);
    size_t  result_len;
    const char *result_json = run_sfs(query, dim, iterations, pop_size, diff_f, &result_len);

    double *best = palloc(dim * sizeof(double));
    int     n = fsql_extract_best_point(result_json, best, dim);
    if (n != dim)
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("fractalsql: best_point parse mismatch (got %d, expected %d)",
                        n, dim)));

    ArrayType *result = doubles_to_float8_array(best, dim);
    PG_RETURN_ARRAYTYPE_P(result);
}

/* ------------------------------------------------------------------ */
/* fractal_search_debug — full fsql_search_ptr result as jsonb.       */
/* ------------------------------------------------------------------ */

PG_FUNCTION_INFO_V1(fractal_search_debug);

Datum
fractal_search_debug(PG_FUNCTION_ARGS)
{
    ArrayType *query_arr = PG_GETARG_ARRAYTYPE_P(0);
    int32      iterations = PG_GETARG_INT32(1);
    int32      pop_size   = PG_GETARG_INT32(2);
    int32      diff_f     = PG_GETARG_INT32(3);

    int     dim;
    double *query = float8_array_to_doubles(query_arr, &dim);
    validate_sfs_params(dim, iterations, pop_size, diff_f);
    size_t  result_len;
    const char *result_json = run_sfs(query, dim, iterations, pop_size, diff_f, &result_len);

    /* Pass the JSON through PostgreSQL's jsonb_in for validation +
     * canonical-form storage. Allocates fresh in the call's memory
     * context, so there's no lifetime overlap with g_ctx. */
    char *zcopy = palloc(result_len + 1);
    memcpy(zcopy, result_json, result_len);
    zcopy[result_len] = '\0';
    Datum jb = DirectFunctionCall1(jsonb_in, CStringGetDatum(zcopy));
    PG_RETURN_DATUM(jb);
}

/* ------------------------------------------------------------------ */
/* Scout (discovery) — fractal_search_explore                         */
/*                                                                    */
/* Scans table.vector_col (a float8[] column) into a corpus once, then */
/* runs SFS in Scout mode (params return_population=true → the core    */
/* uses the min-distance-to-any-stored fitness and, with walk=0,       */
/* settles the population across distinct data basins). Returns the    */
/* final population as SETOF float8[], one row per particle.           */
/* ------------------------------------------------------------------ */

/* Bound the corpus pulled into memory — Scout is O(rows * iter * pop)
 * per call, so this caps both the allocation and the runtime.
 *
 * FSQL_EXPLORE_MAX_ROWS alone is dimension-unaware: at dim=4096 (a
 * common embedding size), 2,000,000 rows is a 64GB allocation attempt
 * (rows * dim * sizeof(double)) -- a latent OOM/DoS risk at high dim.
 * FSQL_EXPLORE_MAX_BYTES bounds the actual allocation directly; the
 * effective row cap passed to SPI_execute is whichever of the two
 * limits is smaller for the query's actual dim. */
#define FSQL_EXPLORE_MAX_ROWS  ((uint64) 2000000)
#define FSQL_EXPLORE_MAX_BYTES ((uint64) 2ULL * 1024 * 1024 * 1024)  /* 2GB */

/* Read a numeric option from the options jsonb (NULL/absent → default). */
static double
opt_num(Jsonb *opts, const char *key, double dflt)
{
    JsonbValue buf;
    if (opts == NULL || !JB_ROOT_IS_OBJECT(opts))
        return dflt;
    JsonbValue *v = getKeyJsonValueFromContainer(&opts->root, key,
                                                 (int) strlen(key), &buf);
    if (v == NULL || v->type != jbvNumeric)
        return dflt;
    return DatumGetFloat8(DirectFunctionCall1(numeric_float8,
                          NumericGetDatum(v->val.numeric)));
}

/* fsql_extract_population() -- moved to fractalsql_parse.c alongside
 * the other two hand-rolled parsers above; see that file's header
 * comment and tests/fuzz/README.md. */

/* Cached OID lookup for the fractal_vector type -- looked up once per
 * backend via the normal search_path (the extension has already
 * created the type by the time any search function runs), not once
 * per row. InvalidOid would mean "not found", which can't happen once
 * CREATE EXTENSION has run, but a fresh cache miss just means "not
 * looked up yet in this backend", so it's re-checked, not sticky. */
static Oid
fractal_vector_typeid(void)
{
    static Oid cached = InvalidOid;
    if (!OidIsValid(cached))
        cached = TypenameGetTypid("fractal_vector");
    return cached;
}

/* SPI-scan table.vector_col into a contiguous row-major corpus,
 * allocated in dst_ctx so it survives SPI_finish. Identifiers are
 * quoted (quote_identifier) to prevent SQL injection.
 *
 * Dispatches on the column's actual type: float8[] (the original
 * path, unchanged) or fractal_vector (reads the varlena payload
 * directly, widening float->double once per element -- no separate
 * array-unpack step). Either way the output is the same double*
 * buffer every downstream consumer (telemetry_topk_srf,
 * fsql_search_ptr) already expects; HNSW/SFS internals never see a
 * float. */
static double *
spi_scan_corpus_internal(const char *table, const char *col, int dim,
                          MemoryContext dst_ctx, size_t *n_rows_out,
                          char ***rowids_out)
{
    bool    want_ids = (rowids_out != NULL);
    if (SPI_connect() != SPI_OK_CONNECT)
        ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR),
                        errmsg("fractalsql: SPI_connect failed")));

    /* When the caller asks for row ids (the RAG agents, to map a search
     * result's 0-based position back to a physical row for content
     * retrieval), select ctid::text as the leading column. ctid is stable
     * for the lifetime of the single transaction the agent runs in, so the
     * captured ids remain valid for the followup content SELECT. */
    StringInfoData q;
    initStringInfo(&q);
    appendStringInfo(&q, "SELECT %s%s FROM %s",
                     want_ids ? "ctid::text AS __fsql_rid, " : "",
                     quote_identifier(col), quote_identifier(table));

    /* Dimension-aware row cap: bound the actual corpus allocation
     * (rows * dim * sizeof(double)) to FSQL_EXPLORE_MAX_BYTES, not
     * just row count, then take the smaller of that and
     * FSQL_EXPLORE_MAX_ROWS. */
    uint64 max_rows_by_bytes =
        FSQL_EXPLORE_MAX_BYTES / ((uint64) dim * sizeof(double));
    uint64 effective_row_cap = (max_rows_by_bytes < FSQL_EXPLORE_MAX_ROWS)
                             ? max_rows_by_bytes : FSQL_EXPLORE_MAX_ROWS;

    int rc = SPI_execute(q.data, true /* read-only */, effective_row_cap);
    if (rc != SPI_OK_SELECT) {
        SPI_finish();
        ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR),
                        errmsg("fractalsql: scan of %s.%s failed (rc=%d)",
                               table, col, rc)));
    }

    uint64 n = SPI_processed;
    if (n == 0) { SPI_finish(); *n_rows_out = 0; if (want_ids) *rowids_out = NULL; return NULL; }

    /* SPI_execute's row limit truncates silently -- surface it so a
     * caller scanning a corpus larger than the byte/row cap knows
     * their results are partial, not "the whole table happened to
     * have exactly this many rows." */
    if (n == effective_row_cap)
        ereport(NOTICE,
                (errmsg("fractalsql: %s.%s scan truncated at %lu rows "
                        "(dim=%d, byte cap=%lu MB) -- results are partial",
                        table, col, (unsigned long) n, dim,
                        (unsigned long) (FSQL_EXPLORE_MAX_BYTES / (1024 * 1024)))));

    double   *corpus  = (double *) MemoryContextAllocHuge(
                            dst_ctx, (Size) n * dim * sizeof(double));
    char    **rowids  = want_ids
                        ? (char **) MemoryContextAllocHuge(dst_ctx, (Size) n * sizeof(char *))
                        : NULL;
    TupleDesc tupdesc  = SPI_tuptable->tupdesc;
    /* The vector column is attr 2 when ctid::text leads, attr 1 otherwise. */
    int       vec_attr = want_ids ? 2 : 1;
    Oid       coltype  = SPI_gettypeid(tupdesc, vec_attr);
    bool      is_fvec  = (coltype == fractal_vector_typeid());
    /* Reject a non-array, non-fractal_vector column up front. Without this
     * guard the else branch below casts an arbitrary scalar Datum to an
     * ArrayType * via DatumGetArrayTypeP and runs deconstruct_array on it,
     * which corrupts memory and aborts the backend -- a crash that is NOT
     * catchable by a PL/pgSQL EXCEPTION block (it kills the whole process).
     * Pointing a search/RAG/plan_explore agent at a bigint or text "vector
     * column" is a caller error, so raise a clean ERROR instead of crashing. */
    if (!is_fvec && coltype != FLOAT8ARRAYOID) {
        SPI_finish();
        ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH),
                        errmsg("fractalsql: %s.%s vector_col must be float8[] or "
                               "fractal_vector, got %s",
                               table, col, format_type_be(coltype))));
    }
    for (uint64 r = 0; r < n; r++) {
        bool  isnull;
        Datum d = SPI_getbinval(SPI_tuptable->vals[r], tupdesc, vec_attr, &isnull);
        if (isnull) {
            SPI_finish();
            ereport(ERROR, (errcode(ERRCODE_DATA_EXCEPTION),
                            errmsg("fractalsql: NULL vector at row %lu",
                                   (unsigned long) r)));
        }
        if (want_ids) {
            bool   ridnull;
            Datum  ridd = SPI_getbinval(SPI_tuptable->vals[r], tupdesc, 1, &ridnull);
            /* text_to_cstring allocs in the SPI procedure context (freed by
             * SPI_finish), so dup into dst_ctx where the caller's rowids
             * array lives. */
            const char *s = ridnull ? "" : text_to_cstring(DatumGetTextP(ridd));
            char *dst = (char *) MemoryContextAllocHuge(dst_ctx, strlen(s) + 1);
            memcpy(dst, s, strlen(s) + 1);
            rowids[r] = dst;
        }
        if (is_fvec) {
            /* Detoast-then-cast: a packed varlena's payload does not
             * honor ALIGNMENT=double, and a fractal_vector(1536) row
             * (~6.1KB) routinely needs TOAST fetch/decompress. Free
             * the detoasted copy immediately after each row's memcpy
             * (pointer-identity check: PG_DETOAST_DATUM returns the
             * original pointer untouched when no work was needed) so
             * this loop's peak memory stays bounded across a
             * 100k-row scan instead of accumulating one detoasted
             * copy per row for the lifetime of the call. */
            FractalVector *fv = DatumGetFractalVectorP(d);
            if (fv->dim != dim) {
                SPI_finish();
                ereport(ERROR, (errcode(ERRCODE_DATA_EXCEPTION),
                                errmsg("fractalsql: %s.%s row %lu has dim %d, "
                                       "expected %d (match the query)",
                                       table, col, (unsigned long) r, fv->dim, dim)));
            }
            double *dst = corpus + (Size) r * dim;
            for (int i = 0; i < dim; i++) dst[i] = (double) fv->x[i];
            if (PointerGetDatum(fv) != d) pfree(fv);
        } else {
            int     rdim;
            double *rv = float8_array_to_doubles(DatumGetArrayTypeP(d), &rdim);
            if (rdim != dim) {
                SPI_finish();
                ereport(ERROR, (errcode(ERRCODE_DATA_EXCEPTION),
                                errmsg("fractalsql: %s.%s row %lu has dim %d, "
                                       "expected %d (match the query)",
                                       table, col, (unsigned long) r, rdim, dim)));
            }
            memcpy(corpus + (Size) r * dim, rv, (Size) dim * sizeof(double));
            /* Same bounded-peak-memory reasoning as the fractal_vector
             * branch above: rv is a throwaway per-row copy, already
             * memcpy'd into corpus. Without freeing it here, a 100k-row
             * scan accumulates one palloc'd dim-length buffer per row
             * in SPI's per-call context for the lifetime of the whole
             * scan instead of just the one row's iteration. */
            pfree(rv);
        }
    }
    SPI_finish();
    *n_rows_out = (size_t) n;
    if (want_ids) *rowids_out = rowids;
    return corpus;
}

/* Thin wrapper for callers that do not need row ids (the original 9 call
 * sites). Keeps the spi_scan_corpus(table,col,dim,ctx,&n) signature stable. */
static double *
spi_scan_corpus(const char *table, const char *col, int dim,
                MemoryContext dst_ctx, size_t *n_rows_out)
{
    return spi_scan_corpus_internal(table, col, dim, dst_ctx, n_rows_out, NULL);
}

/* Build a JSON reasoning context for the RAG-style agents: the non-vector
 * columns of the rows the Scout search returned. Passing the raw Scout
 * result_json (the top-k *vectors*) to the LLM is both useless -- an LLM
 * cannot read float embeddings -- and too large: pop_size * dim floats
 * (~130KB at pop=10/dim=768) exceeds a local model's context window and the
 * chat endpoint fails ("reasoning_vfs.generate failed"). Instead we fetch
 * the matched rows' actual content by ctid and pass that.
 *
 * rowids[r] is the ctid string captured during the corpus scan; idx[i] is a
 * 0-based position into that scan (a search result index). The context is
 * built in dst_ctx so it survives this helper's SPI_finish. */
static char *
build_retrieval_context(const char *table, const char *vector_col,
                        char **rowids, const int *idx, int got,
                        MemoryContext dst_ctx)
{
    if (got <= 0)
        return pstrdup("[]");

    MemoryContext workctx = CurrentMemoryContext;

    if (SPI_connect() != SPI_OK_CONNECT)
        ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR),
                        errmsg("fractalsql: SPI_connect failed")));

    /* Build the ctid IN-list from the search-result positions. */
    StringInfoData inlist;
    initStringInfo(&inlist);
    int listed = 0;
    for (int i = 0; i < got; i++) {
        int r = idx[i];
        if (r < 0) continue;
        const char *rid = rowids ? rowids[r] : NULL;
        if (!rid || !rid[0]) continue;
        if (listed > 0) appendStringInfoChar(&inlist, ',');
        appendStringInfoString(&inlist, quote_literal_cstr(rid));
        listed++;
    }
    if (listed == 0) { SPI_finish(); return pstrdup("[]"); }

    /* One query: each matched row as a JSON object with the vector column
     * removed, aggregated into a JSON array. to_jsonb(t) serializes the
     * whole row (including the vector, transiently) then `-' drops the
     * vector key, so the LLM never sees the embeddings. */
    StringInfoData q;
    initStringInfo(&q);
    appendStringInfo(&q,
        "SELECT COALESCE(json_agg(to_jsonb(t) - %s::text)::jsonb, '[]'::jsonb)::text "
        "FROM (SELECT * FROM %s WHERE ctid::text IN (%s)) t",
        quote_literal_cstr(vector_col),
        quote_identifier(table),
        inlist.data);
    pfree(inlist.data);

    int rc = SPI_execute(q.data, true /* read-only */, 1);
    pfree(q.data);
    if (rc != SPI_OK_SELECT || SPI_processed == 0) {
        SPI_finish();
        return pstrdup("[]");
    }

    bool    isnull;
    Datum   jd = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &isnull);
    char   *result;
    if (isnull) {
        result = pstrdup("[]");
    } else {
        const char *s = text_to_cstring(DatumGetTextP(jd));
        /* Copy into dst_ctx so the context outlives SPI_finish (the SPI
         * procedure context is freed on SPI_finish). */
        MemoryContextSwitchTo(dst_ctx);
        result = pstrdup(s);
        MemoryContextSwitchTo(workctx);
    }

    SPI_finish();
    return result;
}

PG_FUNCTION_INFO_V1(fractal_search_explore);

Datum
fractal_search_explore(PG_FUNCTION_ARGS)
{
    FuncCallContext *funcctx;

    if (SRF_IS_FIRSTCALL()) {
        MemoryContext oldctx;
        funcctx = SRF_FIRSTCALL_INIT();
        oldctx  = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

        if (PG_ARGISNULL(0) || PG_ARGISNULL(1) || PG_ARGISNULL(2))
            ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
                            errmsg("fractalsql: table_name, vector_col, "
                                   "and query are required")));

        char      *table     = text_to_cstring(PG_GETARG_TEXT_PP(0));
        char      *col       = text_to_cstring(PG_GETARG_TEXT_PP(1));
        ArrayType *query_arr = PG_GETARG_ARRAYTYPE_P(2);
        Jsonb     *opts      = PG_ARGISNULL(3) ? NULL : PG_GETARG_JSONB_P(3);

        int     dim;
        double *query = float8_array_to_doubles(query_arr, &dim);

        /* Scout defaults: iterations 15, population 50, diffusion 2,
         * walk 0.0 (walk=0 removes the cross-particle best-pull, so the
         * population spreads across distinct basins). mmr_lambda 0.5
         * matches run_search's default -- the v2.x brute-force+MMR
         * retrieval engine's relevance-vs-diversity balance for Scout's
         * full-corpus candidate pool; tunable per call to trade
         * diversity (lower lambda) for relevance (higher lambda). */
        int    iterations  = (int) opt_num(opts, "iterations",       15);
        int    pop_size    = (int) opt_num(opts, "population_size",  50);
        int    diff_f      = (int) opt_num(opts, "diffusion_factor",  2);
        double walk        =       opt_num(opts, "walk",            0.0);
        double mmr_lambda  =       opt_num(opts, "mmr_lambda",       0.5);
        validate_sfs_params(dim, iterations, pop_size, diff_f);
        if (mmr_lambda < 0.0) mmr_lambda = 0.0;
        if (mmr_lambda > 1.0) mmr_lambda = 1.0;

        size_t  n_rows = 0;
        double *corpus = spi_scan_corpus(table, col, dim,
                                         funcctx->multi_call_memory_ctx,
                                         &n_rows);
        if (n_rows == 0)
            ereport(ERROR, (errcode(ERRCODE_NO_DATA_FOUND),
                            errmsg("fractalsql: %s.%s has no rows to explore",
                                   table, col)));

        ensure_search_ctx();
        char params[256];
        snprintf(params, sizeof params,
            "{\"return_population\":true,\"max_generation\":%d,"
            "\"population_size\":%d,\"maximum_diffusion\":%d,"
            "\"walk\":%g,\"bound_clipping\":true,\"mmr_lambda\":%g}",
            iterations, pop_size, diff_f, walk, mmr_lambda);

        const char *result_json = NULL;
        size_t      result_len  = 0;
        (void) result_len;
        int rc = fsql_search_ptr(g_ctx, corpus, n_rows, (size_t) dim,
                                 query, (size_t) dim, pop_size,
                                 params, strlen(params),
                                 &result_json, &result_len);
        pfree(corpus);
        if (rc != 0 || !result_json) {
            const char *err = fsql_last_error(g_ctx);
            ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR),
                            errmsg("fractalsql: scout rc=%d: %s", rc,
                                   err && *err ? err : "(no detail)")));
        }

        /* Materialize the population as float8[] rows in the SRF's
         * multi-call context (result_json is owned by g_ctx and only
         * valid until the next fsql_search* call). */
        /* Bound the population buffer before palloc. validate_sfs_params caps
         * pop_size<=100000 and dim<=1M, so the product can reach ~800GB and
         * (uint32)(pop*dim*8) overflows on 32-bit size_t builds. Use a uint64
         * multiply and reject anything exceeding the same FSQL_EXPLORE_MAX_BYTES
         * (2GB) ceiling the corpus scan already enforces -- a population buffer
         * larger than the corpus it was sampled from is never legitimate. */
        if ((uint64) pop_size * (uint64) dim * sizeof(double) > FSQL_EXPLORE_MAX_BYTES)
            ereport(ERROR,
                    (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
                     errmsg("fractalsql: scout population buffer %d*%d*%d bytes exceeds %lu MB cap",
                            pop_size, dim, (int) sizeof(double),
                            (unsigned long) (FSQL_EXPLORE_MAX_BYTES / (1024 * 1024))),
                     errhint("Lower population_size or the query dimension in the options.")));
        double *flat = (double *) palloc((Size) pop_size * dim * sizeof(double));
        int     got  = fsql_extract_population(result_json, dim, pop_size, flat);
        Datum  *rows = (Datum *) palloc((got > 0 ? got : 1) * sizeof(Datum));
        for (int i = 0; i < got; i++)
            rows[i] = PointerGetDatum(
                          doubles_to_float8_array(flat + (Size) i * dim, dim));
        pfree(flat);

        funcctx->user_fctx = rows;
        funcctx->max_calls = got;
        MemoryContextSwitchTo(oldctx);
    }

    funcctx = SRF_PERCALL_SETUP();
    if (funcctx->call_cntr >= funcctx->max_calls)
        SRF_RETURN_DONE(funcctx);
    {
        /* Capture the row BEFORE SRF_RETURN_NEXT — the macro increments
         * call_cntr before evaluating its argument, so indexing inside
         * the macro would read one past the intended (and past the end
         * on the final row). */
        Datum  *rows = (Datum *) funcctx->user_fctx;
        Datum   row  = rows[funcctx->call_cntr];
        SRF_RETURN_NEXT(funcctx, row);
    }
}

/* ------------------------------------------------------------------ */
/* Reasoning — fractal_reason(query text, context text) → text     */
/* ------------------------------------------------------------------ */

PG_FUNCTION_INFO_V1(fractal_reason);

Datum
fractal_reason(PG_FUNCTION_ARGS)
{
    ensure_reason_ctx();   /* triggers lazy plugin load if not yet done */

    if (!g_reason_loaded)
        ereport(ERROR,
                (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                 errmsg("fractal_reason: no reasoning plugin loaded"),
                 errhint("Set fractalsql.reasoning_plugin in postgresql.conf "
                         "to the absolute path of a compiled "
                         "fractalsql-reasoning-*.so and reconnect.")));

    if (PG_ARGISNULL(0))
        ereport(ERROR,
                (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
                 errmsg("fractal_reason: query must not be NULL")));

    const char *query_str   = text_to_cstring(PG_GETARG_TEXT_PP(0));
    const char *context_str = PG_ARGISNULL(1) ? "{}" :
                              text_to_cstring(PG_GETARG_TEXT_PP(1));

    fsql_ai_response_t resp;
    memset(&resp, 0, sizeof(resp));

    int rc = fsql_dispatch_ai(g_reason_ctx,
                              query_str,   strlen(query_str),
                              context_str, strlen(context_str),
                              &resp);
    if (rc != 0 || resp.rc != 0)
    {
        int      err_rc = rc != 0 ? rc : resp.rc;
        const char *err = fsql_last_error(g_reason_ctx);
        fsql_ai_response_free(&resp);
        ereport(ERROR,
                (errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
                 errmsg("fractal_reason: dispatch failed (rc=%d): %s",
                        err_rc,
                        err && *err ? err : "(no detail)")));
    }

    guard_ai_response_len(&resp);   /* also keeps the (int) cast below sane */
    text *result = cstring_to_text_with_len(resp.summary,
                                            (int) resp.summary_len);
    fsql_ai_response_free(&resp);
    PG_RETURN_TEXT_P(result);
}

/* ------------------------------------------------------------------ */
/* Agent-tier Compositions                                            */
/* ------------------------------------------------------------------ */

PG_FUNCTION_INFO_V1(fractal_search_agent);

Datum
fractal_search_agent(PG_FUNCTION_ARGS)
{
    if (PG_ARGISNULL(0) || PG_ARGISNULL(1) || PG_ARGISNULL(2))
        ereport(ERROR,
                (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
                 errmsg("fractalsql: query, table_name, and vector_col are required")));

    const char *query_str   = text_to_cstring(PG_GETARG_TEXT_PP(0));
    const char *table_name  = text_to_cstring(PG_GETARG_TEXT_PP(1));
    const char *vector_col  = text_to_cstring(PG_GETARG_TEXT_PP(2));
    int32       pop_size    = PG_ARGISNULL(3) ? 50 : PG_GETARG_INT32(3);
    int32       iterations   = PG_ARGISNULL(4) ? 15 : PG_GETARG_INT32(4);

    ensure_search_ctx();
    ensure_reason_ctx();

    if (!g_reason_loaded)
        ereport(ERROR,
                (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                 errmsg("fractal_search_agent: no reasoning plugin loaded")));

    /* 1. Embed the natural language query */
    ensure_embed_ctx();
    fsql_ai_response_t emb_resp;
    memset(&emb_resp, 0, sizeof(emb_resp));
    int rc_emb = fsql_dispatch_ai(g_embed_ctx, query_str, strlen(query_str), "{}", 2, &emb_resp);
    if (rc_emb != 0 || emb_resp.rc != 0) {
        fsql_ai_response_free(&emb_resp);
        ereport(ERROR, (errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION), errmsg("fractal_search_agent: embedding failed")));
    }
    char *raw_emb = pnstrdup(emb_resp.summary, emb_resp.summary_len);
    fsql_ai_response_free(&emb_resp);
    double *query_vec = palloc(MAX_EMBED_DIM * sizeof(double));
    int dim = fsql_parse_embedding_array(raw_emb, query_vec, MAX_EMBED_DIM);
    if (dim <= 0) ereport(ERROR, (errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION), errmsg("fractal_search_agent: failed to parse embedding")));

    /* 2. Search for diverse context (Scout mode). Capture each row's ctid
     * alongside the corpus so the search-result positions can be mapped back
     * to physical rows for content retrieval (step 3). */
    ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
    MemoryContext  per_query_ctx = rsinfo ? rsinfo->econtext->ecxt_per_query_memory : CurrentMemoryContext;
    size_t  n_rows = 0;
    char  **rowids = NULL;
    double *corpus = spi_scan_corpus_internal(table_name, vector_col, dim,
                                              per_query_ctx, &n_rows, &rowids);
    if (n_rows == 0) ereport(ERROR, (errcode(ERRCODE_NO_DATA_FOUND), errmsg("fractalsql: no rows found in %s.%s", table_name, vector_col)));

    char params[256];
    snprintf(params, sizeof params,
        "{\"return_population\":true,\"max_generation\":%d,\"population_size\":%d,\"maximum_diffusion\":2,\"walk\":0.0,\"bound_clipping\":true,\"mmr_lambda\":0.5}",
        iterations, pop_size);

    const char *result_json = NULL;
    size_t      result_len  = 0;
    int rc_srch = fsql_search_ptr(g_ctx, corpus, n_rows, (size_t) dim, query_vec, (size_t) dim, (int) pop_size, params, strlen(params), &result_json, &result_len);
    if (rc_srch != 0 || !result_json) ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR), errmsg("fractalsql: search failed")));

    /* Extract the top-k result indices up front: they feed both the
     * source_doc_ids output column and the reasoning context. */
    int    *idx  = palloc(pop_size * sizeof(int));
    double *dist = palloc(pop_size * sizeof(double));
    int     got  = fsql_extract_topk(result_json, pop_size, idx, dist);

    /* 3. Reason over the retrieved rows' CONTENT, not the raw Scout vectors.
     * The result_json contains the top-k *embeddings* (pop_size * dim floats,
     * ~130KB at pop=10/dim=768) -- useless to an LLM and large enough to blow
     * the chat endpoint's context window. build_retrieval_context fetches the
     * matched rows' non-vector columns as a compact JSON array instead. */
    char *ctx_json = build_retrieval_context(table_name, vector_col,
                                             rowids, idx, got, per_query_ctx);

    fsql_ai_response_t reason_resp;
    memset(&reason_resp, 0, sizeof(reason_resp));
    int rc_ai = fsql_dispatch_ai(g_reason_ctx, query_str, strlen(query_str), ctx_json, strlen(ctx_json), &reason_resp);
    if (rc_ai != 0 || reason_resp.rc != 0) {
        int         err_rc = rc_ai != 0 ? rc_ai : reason_resp.rc;
        const char *err    = fsql_last_error(g_reason_ctx);
        fsql_ai_response_free(&reason_resp);
        ereport(ERROR, (errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
                        errmsg("fractalsql: search_agent reasoning failed (rc=%d): %s",
                               err_rc, err ? err : "(no detail)")));
    }

    /* 4. Build result record. heap_form_tuple is the canonical single-row
     * composite-Datum path; a tuplestore is for SRF materialization, not
     * single-record returns (an earlier version used tuplestore_get_tuple,
     * which is not a real PostgreSQL tuplestore API and failed to link). */
    TupleDesc tupdesc;
    get_call_result_type(fcinfo, NULL, &tupdesc);
    tupdesc = BlessTupleDesc(tupdesc);

    Datum values[3];
    bool nulls[3] = { false, false, false };
    values[0] = CStringGetTextDatum(reason_resp.summary);

    Datum *doc_ids_datums = palloc(got * sizeof(Datum));
    for (int i = 0; i < got; i++)
        doc_ids_datums[i] = Int64GetDatum((int64) idx[i]);

    ArrayType *ids_arr = construct_array(doc_ids_datums, got, INT8OID, sizeof(int64), INT8PASSBYVAL, 'i');
    pfree(doc_ids_datums);

    values[1] = PointerGetDatum(ids_arr);
    values[2] = Int64GetDatum(100); /* Placeholder for execution_time_ms */

    HeapTuple tuple = heap_form_tuple(tupdesc, values, nulls);

    fsql_ai_response_free(&reason_resp);
    PG_RETURN_DATUM(HeapTupleGetDatum(tuple));
}

PG_FUNCTION_INFO_V1(fractal_sql_agent);

Datum
fractal_sql_agent(PG_FUNCTION_ARGS)
{
    ensure_text_to_sql_ctx();
    if (!g_t2s_loaded) ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("fractal_sql_agent: no reasoning plugin loaded")));

    const char *question = text_to_cstring(PG_GETARG_TEXT_PP(0));
    ArrayType  *table_names_arr = PG_ARGISNULL(1) ? NULL : PG_GETARG_ARRAYTYPE_P(1);
    int32      max_retries = PG_ARGISNULL(2) ? 2 : PG_GETARG_INT32(2);
    bool       auto_execute = PG_ARGISNULL(3) ? false : PG_GETARG_BOOL(3);

    char *final_sql = NULL;
    char *feedback  = NULL;   /* last validation failure, fed back to the generator */
    bool  passed    = false;
    int   attempt   = 0;
    while (attempt < max_retries) {
        attempt++;
        final_sql = fractal_text_to_sql_internal(question, table_names_arr, feedback);
        if (final_sql == NULL)
            ereport(ERROR, (errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
                            errmsg("fractal_sql_agent: text-to-SQL generate dispatch failed")));

        /* Gate the model-generated SQL through the SAME validation pipeline
         * fractal_text_to_sql() uses -- allowlist FIRST (statement-class +
         * modifying-CTE check), then EXPLAIN. EXPLAIN alone would let a
         * smuggled second statement sail past (EXPLAIN executes its
         * argument) and would skip the text_to_sql_allowed_statements GUC,
         * so allowlist must run first. Feed the rejection reason back as
         * `feedback` so the next GENERATE attempt is prompted to correct
         * it, matching fractal_text_to_sql. */
        char *allow_err = t2s_check_allowlist(final_sql);
        if (allow_err != NULL) { feedback = allow_err; continue; }
        char *explain_err = t2s_check_explain(final_sql);
        if (explain_err != NULL) { feedback = explain_err; continue; }

        passed = true;
        break;
    }

    TupleDesc tupdesc;
    get_call_result_type(fcinfo, NULL, &tupdesc);
    tupdesc = BlessTupleDesc(tupdesc);

    Datum values[4];
    bool nulls[4] = { false, false, false, true };
    values[0] = CStringGetTextDatum(final_sql);
    /* If every attempt failed validation, do NOT claim "success": report
     * validation_failed and put the last rejection in result_json. The
     * auto_execute block below is gated on `passed` so no unvalidated SQL
     * is ever run. */
    values[1] = CStringGetTextDatum(passed ? "success" : "validation_failed");
    values[2] = Int32GetDatum(attempt);
    values[3] = (Datum) 0;
    if (!passed && feedback != NULL)
    {
        StringInfoData js;
        initStringInfo(&js);
        appendStringInfoString(&js, "{\"status\":\"validation_failed\",\"error\":");
        escape_json(&js, feedback);
        appendStringInfoChar(&js, '}');
        values[3] = DirectFunctionCall1(jsonb_in, CStringGetDatum(js.data));
        nulls[3] = false;
        pfree(js.data);
    }

    if (auto_execute && passed && final_sql) {
        /* Run the model-generated SQL inside a subtransaction so a thrown
         * ERROR (e.g. "unknown type of jsonb container", a constraint
         * violation, or any planner/executor failure) is caught here and
         * surfaced as execution_status="execution_failed" + a reason in
         * result_json -- instead of propagating up and aborting the whole
         * fractal_sql_agent call. Mirrors the t2s_check_explain pattern:
         * SPI_connect BEFORE BeginInternalSubTransaction so the connection
         * belongs to the outer SPI level and survives the inner rollback. */
        MemoryContext oldcontext = CurrentMemoryContext;
        ResourceOwner oldowner   = CurrentResourceOwner;

        if (SPI_connect() != SPI_OK_CONNECT)
            ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR),
                            errmsg("fractal_sql_agent: SPI connect failed")));

        BeginInternalSubTransaction(NULL);
        MemoryContextSwitchTo(oldcontext);

        PG_TRY();
        {
            int rc = SPI_execute(final_sql, false, 0);
            if (rc == SPI_OK_SELECT && SPI_processed > 0) {
                char buf[512];
                snprintf(buf, sizeof buf, "{\"status\":\"executed\",\"rows\":%d}",
                         (int) SPI_processed);
                /* Build a real jsonb Datum -- the result_json column is jsonb,
                 * so storing a text varlena here (CStringGetTextDatum) leaves
                 * malformed jsonb that throws "unknown type of jsonb
                 * container" when the result is rendered. */
                values[3] = DirectFunctionCall1(jsonb_in, CStringGetDatum(buf));
                nulls[3] = false;
            } else if (rc == SPI_OK_UTILITY || rc == SPI_OK_INSERT ||
                       rc == SPI_OK_UPDATE || rc == SPI_OK_DELETE) {
                values[1] = CStringGetTextDatum("executed");
            } else {
                values[1] = CStringGetTextDatum("execution_failed");
            }
            ReleaseCurrentSubTransaction();
            MemoryContextSwitchTo(oldcontext);
            CurrentResourceOwner = oldowner;
        }
        PG_CATCH();
        {
            ErrorData *edata;

            MemoryContextSwitchTo(oldcontext);
            edata = CopyErrorData();
            FlushErrorState();

            RollbackAndReleaseCurrentSubTransaction();
            MemoryContextSwitchTo(oldcontext);
            CurrentResourceOwner = oldowner;

            values[1] = CStringGetTextDatum("execution_failed");
            /* Stash the executor's error message into result_json so the
             * caller can see WHY execution failed. PG's escape_json emits a
             * full JSON string literal -- it appends the SURROUNDING
             * double-quotes itself AND escapes quotes/backslashes/control
             * chars inside -- so the prefix/suffix here must NOT add their
             * own quotes around the error field, or the field ends up
             * double-quoted ({"...error":""msg""}) and jsonb_in rejects it
             * with "invalid input syntax for type json" whenever the message
             * contains a token (e.g. syntax error at or near "x"). Verified
             * against PG16's utils/adt/json.c escape_json, which opens and
             * closes with appendStringInfoCharMacro(buf, '"'). */
            {
                StringInfoData js;
                initStringInfo(&js);
                appendStringInfoString(&js, "{\"status\":\"execution_failed\",\"error\":");
                escape_json(&js, edata->message ? edata->message : "(no message)");
                appendStringInfoChar(&js, '}');
                values[3] = DirectFunctionCall1(jsonb_in, CStringGetDatum(js.data));
                nulls[3] = false;
                pfree(js.data);
            }
            FreeErrorData(edata);
        }
        PG_END_TRY();

        SPI_finish();
    }

    HeapTuple tuple = heap_form_tuple(tupdesc, values, nulls);

    PG_RETURN_DATUM(HeapTupleGetDatum(tuple));
}

PG_FUNCTION_INFO_V1(fractal_agent_plan_explore);

Datum
fractal_agent_plan_explore(PG_FUNCTION_ARGS)
{
    const char *initial_state = text_to_cstring(PG_GETARG_TEXT_PP(0));
    const char *strategy_table = text_to_cstring(PG_GETARG_TEXT_PP(1));
    const char *vector_col = text_to_cstring(PG_GETARG_TEXT_PP(2));
    int32 max_branches = PG_GETARG_INT32(3);

    ensure_search_ctx();
    fsql_diversify_enable(g_ctx);

    /* We should embed initial_state first to use as query */
    ensure_embed_ctx();
    fsql_ai_response_t emb_resp;
    memset(&emb_resp, 0, sizeof(emb_resp));
    int rc_emb = fsql_dispatch_ai(g_embed_ctx, initial_state, strlen(initial_state), "{}", 2, &emb_resp);
    if (rc_emb != 0 || emb_resp.rc != 0) {
        fsql_ai_response_free(&emb_resp);
        ereport(ERROR, (errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION), errmsg("fractal_agent_plan_explore: embedding failed")));
    }
    char *raw_emb = pnstrdup(emb_resp.summary, emb_resp.summary_len);
    fsql_ai_response_free(&emb_resp);
    double *query_vec = palloc(MAX_EMBED_DIM * sizeof(double));
    int dim = fsql_parse_embedding_array(raw_emb, query_vec, MAX_EMBED_DIM);
    if (dim <= 0) ereport(ERROR, (errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION), errmsg("fractal_agent_plan_explore: failed to parse embedding")));

    ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
    if (rsinfo == NULL || !(rsinfo->allowedModes & SFRM_Materialize))
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                 errmsg("fractalsql: set-valued function called in context "
                        "that cannot accept a set")));
    MemoryContext  per_query_ctx = rsinfo->econtext->ecxt_per_query_memory;
    size_t  n_rows = 0;
    double *corpus = spi_scan_corpus(strategy_table, vector_col, dim, per_query_ctx, &n_rows);
    if (n_rows == 0) ereport(ERROR, (errcode(ERRCODE_NO_DATA_FOUND), errmsg("fractalsql: no rows found in %s.%s", strategy_table, vector_col)));

    /* Full Scout params (the prior minimal {"return_population":true,...} set
     * omitted max_generation/maximum_diffusion/walk/bound_clipping/mmr_lambda,
     * and fsql_search_ptr returned no result_json -- fsql_extract_topk then
     * dereferenced the NULL pointer and crashed the backend). Mirror the
     * param shape fractal_search_agent uses, which is known to populate
     * top_k. */
    char params[256];
    snprintf(params, sizeof params,
        "{\"return_population\":true,\"max_generation\":15,\"population_size\":%d,\"maximum_diffusion\":2,\"walk\":0.0,\"bound_clipping\":true,\"mmr_lambda\":0.5}",
        max_branches);
    const char *result_json = NULL;
    size_t result_len = 0;
    int rc_srch = fsql_search_ptr(g_ctx, corpus, n_rows, (size_t) dim, query_vec, (size_t) dim, (int) max_branches, params, strlen(params), &result_json, &result_len);
    if (rc_srch != 0 || !result_json) ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR), errmsg("fractalsql: plan_explore search failed (rc=%d)", rc_srch)));

    /* Set-returning function, materialized: fill a tuplestore the executor
     * drains. The tupdesc AND tuplestore MUST be allocated in per_query_ctx --
     * the executor reads them after this function returns, so creating them
     * in CurrentMemoryContext (the short-lived executor context) leaves
     * freed memory for the executor to read (use-after-free -> crash on
     * return). Match fractal_mine_topology_negatives' pattern. */
    MemoryContext oldcontext = MemoryContextSwitchTo(per_query_ctx);

    TupleDesc tupdesc;
    if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
        ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                        errmsg("fractalsql: plan_explore return type is not a composite row")));
    tupdesc = BlessTupleDesc(tupdesc);

    Tuplestorestate *tupstore = tuplestore_begin_heap(false, false, work_mem);
    rsinfo->returnMode = SFRM_Materialize;
    rsinfo->setResult = tupstore;
    rsinfo->setDesc = tupdesc;

    MemoryContextSwitchTo(oldcontext);

    int *idx = palloc(max_branches * sizeof(int));
    double *dist = palloc(max_branches * sizeof(double));
    int got = fsql_extract_topk(result_json, max_branches, idx, dist);
    /* got < 0 means the result JSON had no "top_k" array (or a NULL json,
     * now NULL-guarded in fsql_extract_topk) -- return an empty set, not a
     * crash. */
    if (got < 0) got = 0;
    for (int i = 0; i < got; i++) {
        Datum values[3];
        bool  nulls[3] = { false, false, false };
        values[0] = Int64GetDatum(idx[i]);
        /* The branch's plan_trajectory is its OWN matched strategy vector
         * (the corpus row at idx[i]), not the query vector -- so each branch
         * carries a distinct trajectory reflecting the strategy it explored.
         * idx[i] is a 0-based position into the corpus scan (bounded < n_rows). */
        values[1] = PointerGetDatum(doubles_to_float8_array(&corpus[(size_t) idx[i] * dim], dim));
        values[2] = Float8GetDatum(1.0 - dist[i]);
        /* tuplestore_putvalues dereferences the isnull array per attribute --
         * passing NULL here segfaults on the first row.
         * Pass a real all-non-NULL flags array, matching fractal_search_telemetry. */
        tuplestore_putvalues(tupstore, tupdesc, values, nulls);
    }

    PG_RETURN_DATUM(0);
}

/* Decode a single vector_col Datum (float8[] or fractal_vector) into a freshly
 * palloc'd double buffer in the caller's CurrentMemoryContext, mirroring the
 * per-row dispatch in spi_scan_corpus. The copy is important: a raw SELECT
 * Datum points into SPI's tuple memory, which is freed by SPI_finish -- so the
 * caller must copy values out before finishing the SPI connection. Returns the
 * buffer and sets *out_dim. Raises a clean ERROR on a non-vector column. */
static double *
decode_vector_datum(Datum d, Oid coltype, int *out_dim)
{
    if (coltype == fractal_vector_typeid()) {
        FractalVector *fv = DatumGetFractalVectorP(d);
        int  dim = fv->dim;
        double *out = palloc(dim * sizeof(double));
        for (int i = 0; i < dim; i++) out[i] = (double) fv->x[i];
        if (PointerGetDatum(fv) != d) pfree(fv);  /* free detoasted copy only */
        *out_dim = dim;
        return out;
    }
    if (coltype == FLOAT8ARRAYOID)
        return float8_array_to_doubles(DatumGetArrayTypeP(d), out_dim);
    ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH),
                    errmsg("fractalsql: vector_col must be float8[] or "
                           "fractal_vector, got %s", format_type_be(coltype))));
    *out_dim = 0;  /* unreachable */
    return NULL;
}

PG_FUNCTION_INFO_V1(fractal_agent_trajectory_predict);

Datum
fractal_agent_trajectory_predict(PG_FUNCTION_ARGS)
{
    const char *table_name = text_to_cstring(PG_GETARG_TEXT_PP(0));
    const char *vector_col = text_to_cstring(PG_GETARG_TEXT_PP(1));
    int64 baseline_id = PG_GETARG_INT64(2);
    int32 forecast_steps = PG_GETARG_INT32(3);

    ensure_search_ctx();

    /* 1. Read the baseline and current vectors from the table. The function
     * signature has no id_col argument, so resolve the table's primary-key
     * column from pg_catalog, read the baseline row by baseline_id, and read
     * the latest row (max PK, DESC LIMIT 1) as "current". Derive dim from the
     * baseline vector -- no more hardcoded 1536 stub, and the delta is now a
     * real computed difference instead of reading uninitialized palloc'd
     * buffers (which was UB). */
    /* SPI_connect switches CurrentMemoryContext to the SPI procedure context,
     * which SPI_finish frees. Capture the caller's executor context here and
     * switch back to it before each palloc'ing decode so baseline_vec /
     * current_vec / delta outlive SPI_finish (else use-after-free). */
    MemoryContext workctx = CurrentMemoryContext;
    if (SPI_connect() != SPI_OK_CONNECT)
        ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR),
                        errmsg("fractal_agent_trajectory_predict: SPI_connect failed")));

    StringInfoData pkq;
    initStringInfo(&pkq);
    appendStringInfo(&pkq,
        "SELECT a.attname FROM pg_index i "
        "JOIN pg_attribute a ON a.attrelid = i.indrelid "
        "AND a.attnum = ANY(i.indkey) "
        "WHERE i.indrelid = %s::regclass AND i.indisprimary "
        "ORDER BY a.attnum LIMIT 1",
        quote_literal_cstr(table_name));
    int rc = SPI_execute(pkq.data, true, 1);
    if (rc != SPI_OK_SELECT || SPI_processed == 0) {
        SPI_finish();
        ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                        errmsg("fractal_agent_trajectory_predict: table %s has no primary key",
                               table_name)));
    }
    char *pk_raw = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);
    if (pk_raw == NULL) {
        SPI_finish();
        ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR),
                        errmsg("fractal_agent_trajectory_predict: could not read PK column name")));
    }
    /* quote_identifier pallocs; do it in workctx so pk_col survives SPI_finish
     * (the error paths below call SPI_finish() then reference pk_col). */
    MemoryContextSwitchTo(workctx);
    const char *pk_col = quote_identifier(pk_raw);

    /* Baseline vector: the row whose PK == baseline_id. */
    StringInfoData bq;
    initStringInfo(&bq);
    appendStringInfo(&bq, "SELECT %s FROM %s WHERE %s = " INT64_FORMAT,
                     quote_identifier(vector_col), quote_identifier(table_name),
                     pk_col, baseline_id);
    rc = SPI_execute(bq.data, true, 1);
    if (rc != SPI_OK_SELECT || SPI_processed == 0) {
        SPI_finish();
        ereport(ERROR, (errcode(ERRCODE_NO_DATA_FOUND),
                        errmsg("fractal_agent_trajectory_predict: no row in %s with %s = "
                               INT64_FORMAT, table_name, pk_col, baseline_id)));
    }
    bool        b_isnull;
    Datum       b_d = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &b_isnull);
    Oid         b_type = SPI_gettypeid(SPI_tuptable->tupdesc, 1);
    if (b_isnull) {
        SPI_finish();
        ereport(ERROR, (errcode(ERRCODE_DATA_EXCEPTION),
                        errmsg("fractal_agent_trajectory_predict: baseline vector is NULL")));
    }
    int dim = 0;
    MemoryContextSwitchTo(workctx);  /* baseline_vec must outlive SPI_finish */
    double *baseline_vec = decode_vector_datum(b_d, b_type, &dim);

    /* Current vector: the latest row by PK. */
    StringInfoData cq;
    initStringInfo(&cq);
    appendStringInfo(&cq, "SELECT %s FROM %s ORDER BY %s DESC LIMIT 1",
                     quote_identifier(vector_col), quote_identifier(table_name), pk_col);
    rc = SPI_execute(cq.data, true, 1);
    if (rc != SPI_OK_SELECT || SPI_processed == 0) {
        SPI_finish();
        ereport(ERROR, (errcode(ERRCODE_NO_DATA_FOUND),
                        errmsg("fractal_agent_trajectory_predict: %s has no rows", table_name)));
    }
    bool        c_isnull;
    Datum       c_d = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &c_isnull);
    Oid         c_type = SPI_gettypeid(SPI_tuptable->tupdesc, 1);
    if (c_isnull) {
        SPI_finish();
        ereport(ERROR, (errcode(ERRCODE_DATA_EXCEPTION),
                        errmsg("fractal_agent_trajectory_predict: current vector is NULL")));
    }
    int c_dim = 0;
    MemoryContextSwitchTo(workctx);  /* current_vec must outlive SPI_finish */
    double *current_vec = decode_vector_datum(c_d, c_type, &c_dim);

    SPI_finish();  /* done reading; spi_scan_corpus opens its own connection */

    if (c_dim != dim) {
        ereport(ERROR, (errcode(ERRCODE_DATA_EXCEPTION),
                        errmsg("fractal_agent_trajectory_predict: baseline dim %d != current dim %d",
                               dim, c_dim)));
    }

    /* Delta = current - baseline (both buffers are filled).
     * CurrentMemoryContext was restored to workctx by SPI_finish; keep it. */
    double *delta = palloc(dim * sizeof(double));
    for (int i = 0; i < dim; i++) delta[i] = current_vec[i] - baseline_vec[i];

    /* 2. Search for predicted state */
    ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
    MemoryContext  per_query_ctx = rsinfo ? rsinfo->econtext->ecxt_per_query_memory : CurrentMemoryContext;
    size_t n_rows = 0;
    double *corpus = spi_scan_corpus(table_name, vector_col, dim, per_query_ctx, &n_rows);

    const char *result_json = NULL;
    size_t result_len = 0;
    fsql_search_ptr(g_ctx, corpus, n_rows, (size_t) dim, delta, (size_t) dim, 1, "{}", 2, &result_json, &result_len);

    int idx[1];
    double dist[1];
    int got = fsql_extract_topk(result_json, 1, idx, dist);

    if (got <= 0)
        ereport(ERROR, (errcode(ERRCODE_NO_DATA_FOUND), errmsg("fractal_agent_trajectory_predict: no predicted state found")));

    double *best_point = corpus + (idx[0] * dim);
    double drift = dist[0];
    bool risk_exceeded = (drift > 0.5); /* Threshold should ideally be a GUC */

    TupleDesc tupdesc;
    get_call_result_type(fcinfo, NULL, &tupdesc);
    tupdesc = BlessTupleDesc(tupdesc);

    Datum values[3];
    bool nulls[3] = { false, false, false };
    values[0] = PointerGetDatum(doubles_to_float8_array(best_point, dim));
    values[1] = Float8GetDatum(drift);
    values[2] = BoolGetDatum(risk_exceeded);

    HeapTuple tuple = heap_form_tuple(tupdesc, values, nulls);

    PG_RETURN_DATUM(HeapTupleGetDatum(tuple));
}

/* Detect a tight repetition cycle in a discrete-valued series: the smallest
 * period p in [1, max_p] such that series[i] == series[i+p] for every i in
 * [0, n-p). Returns the period, or 0 if no such p. Exact equality is correct
 * here because the entries are integer state hashes cast to double (well
 * within 2^53), so a real loop is bit-identical. The DFA alpha>0.9 threshold
 * in fractal_agent_detect_loop catches drift-to-chaos loops but misses clean
 * low-period toggles (a 12345<->67890 cycle gives alpha~0.1); this catches
 * those. */
static int
detect_short_period(const double *s, int n, int max_p)
{
    if (max_p > n / 2) max_p = n / 2;
    for (int p = 1; p <= max_p; p++) {
        bool ok = true;
        for (int i = 0; i < n - p; i++) {
            if (s[i] != s[i + p]) { ok = false; break; }
        }
        if (ok) return p;
    }
    return 0;
}

PG_FUNCTION_INFO_V1(fractal_agent_detect_loop);

Datum
fractal_agent_detect_loop(PG_FUNCTION_ARGS)
{
    ArrayType *log_arr = PG_GETARG_ARRAYTYPE_P(0);
    int n = ARR_DIMS(log_arr)[0];
    double *series = palloc(n * sizeof(double));
    /* Convert hashes (int64) to doubles */
    Datum *ds; bool *nulls; int n2;
    deconstruct_array(log_arr, INT8OID, sizeof(int64), INT8PASSBYVAL, 'i', &ds, &nulls, &n2);
    for (int i = 0; i < n2; i++) series[i] = (double) DatumGetInt64(ds[i]);

    double alpha;
    fsql_dimension_dfa(series, (size_t) n2, &alpha);
    double drift, r_a, b_a;
    fsql_dimension_drift(series, (size_t) n2, 16, &drift, &r_a, &b_a);

    TupleDesc tupdesc;
    get_call_result_type(fcinfo, NULL, &tupdesc);
    tupdesc = BlessTupleDesc(tupdesc);

    Datum values[3];
    bool tupnulls[3] = { false, false, false };
    /* Flag a loop if EITHER the DFA scaling exponent exceeds 0.9 (drift-to-
     * chaos / random-walk-like cycling) OR a tight discrete period was found
     * (clean toggles like 12345<->67890 that the DFA scores as low alpha). */
    int period = detect_short_period(series, n2, n2 / 4);
    values[0] = CStringGetTextDatum("monitor");
    values[1] = Float8GetDatum(alpha);
    values[2] = BoolGetDatum(alpha > 0.9 || period > 0);

    HeapTuple tuple = heap_form_tuple(tupdesc, values, tupnulls);

    PG_RETURN_DATUM(HeapTupleGetDatum(tuple));
}

PG_FUNCTION_INFO_V1(fractal_rag_agent);

Datum
fractal_rag_agent(PG_FUNCTION_ARGS)
{
    if (PG_ARGISNULL(0) || PG_ARGISNULL(1) || PG_ARGISNULL(2))
        ereport(ERROR,
                (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
                 errmsg("fractalsql: query, table_name, and vector_col are required")));

    const char *query_str   = text_to_cstring(PG_GETARG_TEXT_PP(0));
    const char *table_name  = text_to_cstring(PG_GETARG_TEXT_PP(1));
    const char *vector_col  = text_to_cstring(PG_GETARG_TEXT_PP(2));
    const char *meta_filter = PG_ARGISNULL(3) ? "{}" : text_to_cstring(PG_GETARG_TEXT_PP(3));

    ensure_search_ctx();
    ensure_reason_ctx();

    /* 1. Embed the query */
    ensure_embed_ctx();
    fsql_ai_response_t emb_resp;
    memset(&emb_resp, 0, sizeof(emb_resp));
    int rc_emb = fsql_dispatch_ai(g_embed_ctx, query_str, strlen(query_str), "{}", 2, &emb_resp);
    if (rc_emb != 0 || emb_resp.rc != 0) {
        fsql_ai_response_free(&emb_resp);
        ereport(ERROR, (errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION), errmsg("fractal_rag_agent: embedding failed")));
    }
    char *raw_emb = pnstrdup(emb_resp.summary, emb_resp.summary_len);
    fsql_ai_response_free(&emb_resp);
    double *query_vec = palloc(MAX_EMBED_DIM * sizeof(double));
    int dim = fsql_parse_embedding_array(raw_emb, query_vec, MAX_EMBED_DIM);
    if (dim <= 0) ereport(ERROR, (errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION), errmsg("fractal_rag_agent: failed to parse embedding")));

    /* 2. Hybrid search: Filter then Scout. Capture each row's ctid so the
     * search-result positions map back to physical rows for content
     * retrieval. (meta_filter is reserved for a future WHERE clause; for now
     * the whole corpus is scanned, same as fractal_search_explore.) */
    ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
    MemoryContext  per_query_ctx = rsinfo ? rsinfo->econtext->ecxt_per_query_memory : CurrentMemoryContext;
    size_t  n_rows = 0;
    char  **rowids = NULL;

    /* In a real implementation, we'd use the meta_filter in a WHERE clause here.
       For this core version, we scan the filtered corpus. */
    double *corpus = spi_scan_corpus_internal(table_name, vector_col, dim,
                                              per_query_ctx, &n_rows, &rowids);
    if (n_rows == 0) ereport(ERROR, (errcode(ERRCODE_NO_DATA_FOUND), errmsg("fractalsql: no rows found in %s.%s", table_name, vector_col)));

    int pop_size = 50;
    char params[256];
    snprintf(params, sizeof params,
        "{\"return_population\":true,\"max_generation\":15,\"population_size\":%d,\"maximum_diffusion\":2,\"walk\":0.0,\"bound_clipping\":true,\"mmr_lambda\":0.5}",
        pop_size);

    const char *result_json = NULL;
    size_t      result_len  = 0;
    int rc_srch = fsql_search_ptr(g_ctx, corpus, n_rows, (size_t) dim, query_vec, (size_t) dim, pop_size, params, strlen(params), &result_json, &result_len);
    if (rc_srch != 0 || !result_json) ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR), errmsg("fractalsql: rag search failed")));

    int    *idx  = palloc(pop_size * sizeof(int));
    double *dist = palloc(pop_size * sizeof(double));
    int     got  = fsql_extract_topk(result_json, pop_size, idx, dist);

    /* 3. Reason over the retrieved rows' CONTENT (non-vector columns), not the
     * raw Scout vectors -- see fractal_search_agent for why. */
    char *ctx_json = build_retrieval_context(table_name, vector_col,
                                             rowids, idx, got, per_query_ctx);

    fsql_ai_response_t reason_resp;
    memset(&reason_resp, 0, sizeof(reason_resp));
    int rc_ai = fsql_dispatch_ai(g_reason_ctx, query_str, strlen(query_str), ctx_json, strlen(ctx_json), &reason_resp);
    if (rc_ai != 0 || reason_resp.rc != 0) {
        int         err_rc = rc_ai != 0 ? rc_ai : reason_resp.rc;
        const char *err    = fsql_last_error(g_reason_ctx);
        fsql_ai_response_free(&reason_resp);
        ereport(ERROR, (errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
                        errmsg("fractalsql: rag_agent reasoning failed (rc=%d): %s",
                               err_rc, err ? err : "(no detail)")));
    }

    TupleDesc tupdesc;
    get_call_result_type(fcinfo, NULL, &tupdesc);
    tupdesc = BlessTupleDesc(tupdesc);

    Datum values[1];
    bool nulls[1] = { false };
    values[0] = CStringGetTextDatum(reason_resp.summary);

    HeapTuple tuple = heap_form_tuple(tupdesc, values, nulls);

    fsql_ai_response_free(&reason_resp);
    PG_RETURN_DATUM(HeapTupleGetDatum(tuple));
}

/* ------------------------------------------------------------------ */
/* Embeddings — fractal_embed(input text) → float8[]                */
/* ------------------------------------------------------------------ */

PG_FUNCTION_INFO_V1(fractal_embed);

Datum
fractal_embed(PG_FUNCTION_ARGS)
{
    ensure_embed_ctx();   /* triggers lazy plugin load if not yet done */

    if (!g_embed_loaded)
        ereport(ERROR,
                (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                 errmsg("fractal_embed: no reasoning plugin loaded"),
                 errhint("Set fractalsql.reasoning_plugin and "
                         "fractalsql.http_embed_url in postgresql.conf "
                         "and reconnect.")));

    if (PG_ARGISNULL(0))
        ereport(ERROR,
                (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
                 errmsg("fractal_embed: input must not be NULL")));

    const char *input_str = text_to_cstring(PG_GETARG_TEXT_PP(0));

    fsql_ai_response_t resp;
    memset(&resp, 0, sizeof(resp));

    /* context_json is accepted by fsql_dispatch_ai's signature but
     * ignored entirely by the plugin in embedding mode -- "{}" here,
     * same as t2s_run_review's own no-context dispatch above. */
    int rc = fsql_dispatch_ai(g_embed_ctx,
                              input_str, strlen(input_str),
                              "{}", 2,
                              &resp);
    if (rc != 0 || resp.rc != 0)
    {
        int         err_rc = rc != 0 ? rc : resp.rc;
        const char *err = fsql_last_error(g_embed_ctx);
        fsql_ai_response_free(&resp);
        ereport(ERROR,
                (errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
                 errmsg("fractal_embed: dispatch failed (rc=%d): %s",
                        err_rc, err && *err ? err : "(no detail)")));
    }

    guard_ai_response_len(&resp);
    /* Length-bounded, guaranteed NUL-terminated copy before C-string
     * parsing -- same reasoning as every other resp.summary consumer in
     * this file (summary_len is supplied but NUL-termination isn't
     * promised by the ABI). */
    char *raw = pnstrdup(resp.summary, resp.summary_len);
    fsql_ai_response_free(&resp);

    double *vec = palloc(MAX_EMBED_DIM * sizeof(double));
    int     n   = fsql_parse_embedding_array(raw, vec, MAX_EMBED_DIM);
    if (n <= 0)
        ereport(ERROR,
                (errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
                 errmsg("fractal_embed: could not parse embedding response"),
                 errdetail("Raw response: %s", raw)));

    ArrayType *result = doubles_to_float8_array(vec, n);
    PG_RETURN_ARRAYTYPE_P(result);
}

/* ------------------------------------------------------------------ */
/* Schema context builder — fractal_schema_context                 */
/*                                                                    */
/* Introspection only. No LLM call, no execution beyond read-only     */
/* catalog queries. Builds a plain-text schema description (columns,  */
/* foreign keys, comments) for use as fractal_reason() /           */
/* fractal_text_to_sql() context.                                  */
/*                                                                    */
/* Scope of this build: structure, foreign keys, table/column         */
/* comments. Distinct-value sampling for enum-like columns and        */
/* fractal_search-based table-subset ranking (for schemas with many   */
/* superficially similar tables) are deferred — see                   */
/* docs/text-to-sql-setup.md for what's missing and why.              */
/* ------------------------------------------------------------------ */

/* Resolve `table` and append its structure/FK/comment context to
 * `out`. Must be called with an open SPI connection. Returns false
 * (appending nothing) if the name doesn't resolve to a visible table —
 * caller decides whether that's an error or a skip.
 *
 * `table` is embedded as a SQL literal via quote_literal_cstr, not
 * concatenated raw — it comes from a caller-supplied text[] argument
 * in the table_names path, so treating it as trusted-shaped identifier
 * text would be a real injection hole. to_regclass() resolving it
 * against the current search_path is also what makes this agree with
 * ordinary unqualified SQL name resolution, rather than re-deriving
 * visibility rules by hand against information_schema. */
static bool
append_table_context(StringInfo out, const char *table)
{
    char *lit = quote_literal_cstr(table);
    StringInfoData q;
    initStringInfo(&q);

    /* to_regclass() alone only checks name resolution (search_path
     * visibility), NOT privilege -- pg_attribute/pg_constraint below are
     * globally-readable catalogs, so without this WHERE clause a caller
     * naming a table explicitly could read its full column/PK/FK/comment
     * structure despite having zero grants on it (has_table_privilege
     * returns NULL for a nonexistent relation too, so WHERE NULL still
     * correctly yields zero rows -- same "not found" behavior as before
     * for a table that doesn't exist or isn't visible). This must match
     * the has_table_privilege() gate the auto-discovery path below
     * already applies -- an explicit table_names[] must not be a way to
     * bypass it. */
    appendStringInfo(&q,
        "SELECT to_regclass(%s)::text "
        "WHERE has_table_privilege(to_regclass(%s), 'SELECT')", lit, lit);
    if (SPI_execute(q.data, true, 1) != SPI_OK_SELECT || SPI_processed == 0)
        return false;
    char *resolved = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);
    if (resolved == NULL)
        return false;   /* to_regclass returned NULL — not visible / doesn't exist */
    /* SPI_getvalue's result lives in SPI's per-call context; copy it
     * out before the next SPI_execute below recycles that context. */
    resolved = pstrdup(resolved);

    appendStringInfo(out, "Table: %s\n", resolved);

    /* --- table comment --- */
    resetStringInfo(&q);
    appendStringInfo(&q, "SELECT obj_description(to_regclass(%s), 'pg_class')", lit);
    if (SPI_execute(q.data, true, 1) == SPI_OK_SELECT && SPI_processed > 0)
    {
        char *comment = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);
        if (comment != NULL)
            appendStringInfo(out, "  Comment: %s\n", comment);
    }

    /* --- columns: name, type, nullability, PK membership, comment --- */
    resetStringInfo(&q);
    appendStringInfo(&q,
        "SELECT a.attname, format_type(a.atttypid, a.atttypmod), "
        "       a.attnotnull, "
        "       EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid = a.attrelid "
        "               AND i.indisprimary AND a.attnum = ANY (i.indkey)), "
        "       col_description(a.attrelid, a.attnum) "
        "FROM pg_attribute a "
        "WHERE a.attrelid = to_regclass(%s) AND a.attnum > 0 AND NOT a.attisdropped "
        "ORDER BY a.attnum", lit);
    if (SPI_execute(q.data, true, 0) != SPI_OK_SELECT)
        ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR),
                        errmsg("fractal_schema_context: column introspection failed for %s",
                               resolved)));
    appendStringInfoString(out, "  Columns:\n");
    for (uint64 i = 0; i < SPI_processed; i++)
    {
        HeapTuple tup     = SPI_tuptable->vals[i];
        TupleDesc tupdesc = SPI_tuptable->tupdesc;
        char *name    = SPI_getvalue(tup, tupdesc, 1);
        char *type    = SPI_getvalue(tup, tupdesc, 2);
        char *notnull = SPI_getvalue(tup, tupdesc, 3);
        char *ispk    = SPI_getvalue(tup, tupdesc, 4);
        char *comment = SPI_getvalue(tup, tupdesc, 5);

        appendStringInfo(out, "    %s %s", name, type);
        if (ispk != NULL && strcmp(ispk, "t") == 0)
            appendStringInfoString(out, " PK");
        if (notnull != NULL && strcmp(notnull, "t") == 0)
            appendStringInfoString(out, " NOT NULL");
        if (comment != NULL)
            appendStringInfo(out, " -- %s", comment);
        appendStringInfoChar(out, '\n');
    }

    /* --- foreign keys FROM this table. pg_get_constraintdef() reuses
     * Postgres's own tested DDL-rendering (same thing \d and pg_dump
     * use) instead of hand-reconstructing column names from conkey/
     * confkey arrays — shorter and reuses a well-tested implementation
     * instead of a hand-rolled one. Output looks like the DDL a human
     * DBA would write, e.g. "FOREIGN KEY (customer_id) REFERENCES
     * customers(id)" — a shape LLMs have seen a great deal of. --- */
    resetStringInfo(&q);
    appendStringInfo(&q,
        "SELECT pg_get_constraintdef(con.oid) "
        "FROM pg_constraint con "
        "WHERE con.contype = 'f' AND con.conrelid = to_regclass(%s) "
        "ORDER BY con.conname", lit);
    if (SPI_execute(q.data, true, 0) != SPI_OK_SELECT)
        ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR),
                        errmsg("fractal_schema_context: FK introspection failed for %s",
                               resolved)));
    if (SPI_processed > 0)
    {
        appendStringInfoString(out, "  Foreign keys:\n");
        for (uint64 i = 0; i < SPI_processed; i++)
        {
            char *def = SPI_getvalue(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 1);
            appendStringInfo(out, "    %s: %s\n", resolved, def ? def : "?");
        }
    }

    appendStringInfoChar(out, '\n');
    return true;
}

/* Shared guts of fractal_schema_context(), factored out so
 * fractal_text_to_sql() can build context directly in C without a
 * round-trip through SQL-callable-function dispatch. Opens and closes
 * its own SPI session. Returns a palloc'd, NUL-terminated cstring in
 * the caller's memory context; never returns NULL (errors instead). */
static char *
build_schema_context_cstr(ArrayType *table_names_arr)
{
    /* Captured BEFORE SPI_connect(), which switches CurrentMemoryContext
     * to its own SPI-Proc context for the duration of the connection --
     * initStringInfo(&out) below therefore allocates `out`'s buffer (and
     * every subsequent appendStringInfo growth of it, including inside
     * append_table_context) in THAT context, not the caller's, despite
     * what the comment there used to claim. SPI_finish() destroys that
     * context outright; returning out.data directly after it (the
     * previous behavior) handed the caller a dangling pointer -- a real
     * heap-use-after-free, caught by ASan on the auto-discovery path
     * (multiple tables means enough allocation churn inside the SPI
     * context to actually get reused/poisoned before the read). Fixed
     * by explicitly copying the finished string into the caller's own
     * context with MemoryContextStrdup right before SPI_finish() frees
     * everything else. */
    MemoryContext callercontext = CurrentMemoryContext;

    if (SPI_connect() != SPI_OK_CONNECT)
        ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR),
                        errmsg("fractal_schema_context: SPI_connect failed")));

    StringInfoData out;
    initStringInfo(&out);

    int n_tables = 0;

    if (table_names_arr != NULL)
    {
        /* Caller named specific tables — an unresolvable name here is
         * almost certainly a typo the caller should see, not something
         * to silently skip. */
        Datum *elems; bool *nulls; int n;
        deconstruct_array(table_names_arr, TEXTOID, -1, false, 'i',
                          &elems, &nulls, &n);
        if (n > MAX_SCHEMA_CONTEXT_TABLES)
        {
            SPI_finish();
            ereport(ERROR,
                    (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
                     errmsg("fractal_schema_context: %d tables requested, "
                            "exceeds the limit of %d",
                            n, MAX_SCHEMA_CONTEXT_TABLES),
                     errhint("Pass a smaller table_names[] scoped to the "
                             "tables the question actually needs.")));
        }
        for (int i = 0; i < n; i++)
        {
            if (nulls[i]) continue;
            char *name = TextDatumGetCString(elems[i]);
            if (!append_table_context(&out, name))
            {
                SPI_finish();
                ereport(ERROR,
                        (errcode(ERRCODE_UNDEFINED_TABLE),
                         errmsg("fractal_schema_context: table \"%s\" not found or not visible",
                                name)));
            }
            n_tables++;
        }
    }
    else
    {
        /* Auto-discover: every base table visible via the current
         * search_path that the calling role can SELECT from. No
         * ranking against a query hint yet (deferred, see above) — for
         * large schemas, pass table_names explicitly to bound this. */
        int rc = SPI_execute(
            "SELECT c.relname FROM pg_class c "
            "JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE c.relkind = 'r' "
            "  AND n.nspname = ANY (current_schemas(false)) "
            "  AND has_table_privilege(c.oid, 'SELECT') "
            "ORDER BY c.relname", true, 0);
        if (rc != SPI_OK_SELECT)
        {
            SPI_finish();
            ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR),
                            errmsg("fractal_schema_context: table discovery failed")));
        }
        /* Snapshot names before the next SPI_execute (inside
         * append_table_context) recycles this result set's context. */
        int    n = (int) SPI_processed;
        char **names = palloc(n * sizeof(char *));
        for (int i = 0; i < n; i++)
            names[i] = pstrdup(SPI_getvalue(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 1));

        for (int i = 0; i < n; i++)
        {
            /* Auto-discovered names always resolve (pg_class just
             * showed us this one) barring a concurrent DROP racing
             * this call — skip that case rather than erroring, same
             * spirit as ordinary MVCC-snapshot drift elsewhere. */
            if (append_table_context(&out, names[i]))
                n_tables++;
        }
    }

    /* Copy into the caller's context BEFORE SPI_finish() frees out.data's
     * actual backing buffer (see this function's own header comment). */
    char *result = MemoryContextStrdup(callercontext, out.data);

    SPI_finish();

    if (n_tables == 0)
        ereport(ERROR,
                (errcode(ERRCODE_NO_DATA_FOUND),
                 errmsg("fractal_schema_context: no visible tables found"),
                 errhint("Pass table_names explicitly, or check that the "
                         "calling role has SELECT on at least one table.")));

    return result;
}

PG_FUNCTION_INFO_V1(fractal_schema_context);

Datum
fractal_schema_context(PG_FUNCTION_ARGS)
{
    ArrayType *table_names_arr = PG_ARGISNULL(0) ? NULL : PG_GETARG_ARRAYTYPE_P(0);
    /* query_hint (arg 1) is accepted for forward compatibility with the
     * fractal_search-based table-subset ranking described in
     * docs/text-to-sql-setup.md, but is not used by this build — see
     * that doc for what's deferred and why. */

    char *ctx = build_schema_context_cstr(table_names_arr);
    PG_RETURN_TEXT_P(cstring_to_text(ctx));
}


static T2SAllowedStmts
t2s_allowed_stmts_mode(void)
{
    if (g_t2s_allowed_stmts != NULL &&
        strcmp(g_t2s_allowed_stmts, "select_insert_update") == 0)
        return T2S_ALLOW_SELECT_INSERT_UPDATE;
    return T2S_ALLOW_SELECT;
}

/* Reject a candidate that embeds a data-modifying CTE, e.g.
 *   WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d
 * Such a statement's top-level node is a SelectStmt, so it passes the
 * statement-type check, yet it writes when executed. The authoritative
 * signal is Query.hasModifyingCTE, set during parse analysis --
 * inspecting the raw parse tree does NOT work here (PG's
 * raw_expression_tree_walker does not descend into CTE query bodies).
 *
 * Runs in its own internal subtransaction: parse analysis resolves
 * catalog objects and can ereport (e.g. unknown column) -- caught and
 * returned as retry feedback, same shape as the EXPLAIN check. Only
 * called for select mode (select_insert_update already permits writes).
 * Returns NULL if read-only, else a palloc'd rejection reason (in the
 * caller's context, surviving the subtransaction). */
static char *
t2s_check_readonly(const char *sql)
{
    MemoryContext oldcontext = CurrentMemoryContext;
    ResourceOwner oldowner   = CurrentResourceOwner;
    char         *result     = NULL;
    bool          analyzed   = false;
    bool          modifying  = false;

    BeginInternalSubTransaction(NULL);
    MemoryContextSwitchTo(oldcontext);
    PG_TRY();
    {
        List    *pt = raw_parser(sql, RAW_PARSE_DEFAULT);
        /* caller already verified exactly one statement on this same sql */
        RawStmt *rs = (RawStmt *) linitial(pt);
        /* PG15 renamed parse_analyze() -> parse_analyze_fixedparams()
         * (identical args; the older one takes Oid* vs const Oid*, moot
         * with NULL). Guard so the extension still builds on PG14. */
#if PG_VERSION_NUM >= 150000
        Query   *q  = parse_analyze_fixedparams(rs, sql, NULL, 0, NULL);
#else
        Query   *q  = parse_analyze(rs, sql, NULL, 0, NULL);
#endif

        modifying = q->hasModifyingCTE;
        analyzed  = true;

        ReleaseCurrentSubTransaction();
        MemoryContextSwitchTo(oldcontext);
        CurrentResourceOwner = oldowner;
    }
    PG_CATCH();
    {
        ErrorData *edata;

        MemoryContextSwitchTo(oldcontext);
        edata = CopyErrorData();
        FlushErrorState();

        RollbackAndReleaseCurrentSubTransaction();
        MemoryContextSwitchTo(oldcontext);
        CurrentResourceOwner = oldowner;

        result = psprintf("SQL does not analyze: %s", edata->message);
        FreeErrorData(edata);
    }
    PG_END_TRY();

    if (!analyzed)
        return result;
    if (modifying)
        return pstrdup(
            "statement embeds a data-modifying CTE (e.g. WITH ... AS "
            "(DELETE/UPDATE/INSERT ... RETURNING) ...), which "
            "fractalsql.text_to_sql_allowed_statements = \"select\" does "
            "not permit -- it would modify data when executed");
    return NULL;
}

/* Statement-shape allowlist, via the backend's own raw_parser:
 *   - must parse
 *   - must be exactly one statement (no stacked-statement injection)
 *   - must be an allowed statement type per
 *     fractalsql.text_to_sql_allowed_statements. DDL/utility commands
 *     (CREATE, DROP, GRANT, ...) and DELETE parse to node tags that are
 *     simply not in the allowed set, so they're rejected here without a
 *     separate "is this a utility statement" test.
 * Returns NULL if `sql` passes, else a palloc'd human-readable reason
 * suitable for feeding straight back into the next GENERATE retry.
 *
 * raw_parser() ereport(ERROR)s on a syntax error, so the parse runs
 * inside an internal subtransaction (same pattern as t2s_check_explain
 * below) -- a malformed candidate is caught as retry feedback rather
 * than aborting the caller's transaction. Only lexing/parsing happens
 * here; no catalog lookups, no planning, no execution. */
static char *
t2s_check_allowlist(const char *sql)
{
    MemoryContext oldcontext = CurrentMemoryContext;
    ResourceOwner oldowner   = CurrentResourceOwner;
    char         *result     = NULL;   /* NULL == pass */
    List         *parsetree  = NIL;
    bool          parsed_ok  = false;

    BeginInternalSubTransaction(NULL);
    MemoryContextSwitchTo(oldcontext);   /* parsetree allocs land in the
                                          * caller's context, so they
                                          * survive ReleaseCurrentSub-
                                          * Transaction below */
    PG_TRY();
    {
        parsetree = raw_parser(sql, RAW_PARSE_DEFAULT);
        parsed_ok = true;
        ReleaseCurrentSubTransaction();
        MemoryContextSwitchTo(oldcontext);
        CurrentResourceOwner = oldowner;
    }
    PG_CATCH();
    {
        ErrorData *edata;

        MemoryContextSwitchTo(oldcontext);
        edata = CopyErrorData();
        FlushErrorState();

        RollbackAndReleaseCurrentSubTransaction();
        MemoryContextSwitchTo(oldcontext);
        CurrentResourceOwner = oldowner;

        result = psprintf("SQL does not parse: %s", edata->message);
        FreeErrorData(edata);
    }
    PG_END_TRY();

    if (!parsed_ok)
        return result;   /* the parse-error message from PG_CATCH */

    if (list_length(parsetree) != 1)
        return psprintf(
            "expected exactly one SQL statement, found %d -- "
            "fractal_text_to_sql only returns a single statement",
            list_length(parsetree));

    {
        RawStmt        *rs   = (RawStmt *) linitial(parsetree);
        NodeTag         tag  = nodeTag(rs->stmt);
        T2SAllowedStmts mode = t2s_allowed_stmts_mode();
        bool            ok;

        if (mode == T2S_ALLOW_SELECT)
            ok = (tag == T_SelectStmt);
        else
            ok = (tag == T_SelectStmt ||
                  tag == T_InsertStmt ||
                  tag == T_UpdateStmt);

        if (!ok)
        {
            /* CreateCommandTag + GetCommandTagName render a readable
             * name ("SELECT", "DROP TABLE", ...) for the retry feedback,
             * using the backend's own command-tag machinery. */
            const char *tagname = GetCommandTagName(CreateCommandTag(rs->stmt));
            return psprintf(
                "statement type \"%s\" is not permitted -- "
                "fractalsql.text_to_sql_allowed_statements is set to \"%s\"",
                tagname,
                g_t2s_allowed_stmts ? g_t2s_allowed_stmts : "select");
        }

        /* Top-level type is allowed, but in select mode a data-modifying
         * CTE (WITH d AS (DELETE/UPDATE/INSERT ... RETURNING) SELECT ...)
         * has a top-level SelectStmt and would slip past the type check
         * while still writing when executed. t2s_check_readonly catches
         * that via parse analysis. (select_insert_update mode already
         * permits writes, so modifying CTEs are allowed there -- the
         * execution role's grants remain the table-level gate.) */
        if (mode == T2S_ALLOW_SELECT)
        {
            char *ro = t2s_check_readonly(sql);
            if (ro != NULL)
                return ro;
        }
    }

    return NULL;
}

/* Mechanical validation: does `sql` actually EXPLAIN? Runs inside an
 * internal subtransaction (the C-level equivalent of a SAVEPOINT /
 * ROLLBACK TO SAVEPOINT pair) so a planner error -- a bad column name,
 * a type mismatch -- is caught as data and fed back to the next
 * GENERATE retry, instead of aborting the whole calling transaction.
 *
 * Plain EXPLAIN (no ANALYZE) never executes the statement regardless
 * of statement type, so this never touches data even for INSERT/
 * UPDATE candidates -- the subtransaction wrapper's remaining job is
 * catching the planner error itself, plus guarding against a
 * mislabeled-IMMUTABLE function getting constant-folded and invoked
 * during planning (the risk documented in the text-to-sql design
 * notes; real security still rests on execution-role grants, not on
 * this check).
 *
 * Returns NULL if `sql` EXPLAINs cleanly, else a palloc'd copy of the
 * planner's error message.
 *
 * Manages its own SPI connection. SPI_connect happens BEFORE
 * BeginInternalSubTransaction on purpose: a connection opened outside
 * the inner subtransaction belongs to the outer transaction level, so
 * AtEOSubXact_SPI leaves it intact when the inner subtransaction rolls
 * back, and it's still valid for the SPI_finish after PG_END_TRY. The
 * err_msg is pstrdup'd into oldcontext (the caller's context) so it
 * survives SPI_finish. */
static char *
t2s_check_explain(const char *sql)
{
    MemoryContext oldcontext = CurrentMemoryContext;
    ResourceOwner oldowner   = CurrentResourceOwner;
    char         *err_msg    = NULL;
    char         *explain_sql = psprintf("EXPLAIN %s", sql);

    if (SPI_connect() != SPI_OK_CONNECT)
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("fractal_text_to_sql: SPI_connect failed for EXPLAIN")));

    BeginInternalSubTransaction(NULL);
    MemoryContextSwitchTo(oldcontext);

    PG_TRY();
    {
        int rc = SPI_execute(explain_sql, false, 0);
        if (rc != SPI_OK_UTILITY)
            ereport(ERROR,
                    (errcode(ERRCODE_INTERNAL_ERROR),
                     errmsg("EXPLAIN returned unexpected SPI code %d", rc)));

        ReleaseCurrentSubTransaction();
        MemoryContextSwitchTo(oldcontext);
        CurrentResourceOwner = oldowner;
    }
    PG_CATCH();
    {
        ErrorData *edata;

        MemoryContextSwitchTo(oldcontext);
        edata = CopyErrorData();
        FlushErrorState();

        RollbackAndReleaseCurrentSubTransaction();
        MemoryContextSwitchTo(oldcontext);
        CurrentResourceOwner = oldowner;

        err_msg = pstrdup(edata->message);
        FreeErrorData(edata);
    }
    PG_END_TRY();

    SPI_finish();
    return err_msg;
}

/* Ask the model to self-review its own candidate against the original
 * question. Gated behind fractalsql.text_to_sql_use_review (default
 * off -- see the GUC registration comment in _PG_init for why: this is
 * just a second fsql_dispatch_ai call with a critique-shaped prompt,
 * not a distinct security mechanism, so the cost is pure LLM-call
 * latency/spend, not safety). Returns true (PASS) or false (FAIL,
 * with *critique_out set to the model's explanation for retry
 * feedback). */
static bool
t2s_run_review(const char *question, const char *candidate_sql, char **critique_out)
{
    StringInfoData      prompt;
    fsql_ai_response_t  resp;
    char                *review_text;
    char                *p;
    bool                 passed;

    /* Review is "just a second fractal_reason()-shaped call with a
     * critique prompt" (see this function's own header comment above),
     * so it shares fractal_reason()'s own ctx -- a plain PASS/FAIL-then-
     * explain text judgment, not SQL generation. It must NOT use
     * g_t2s_ctx (RESPONSE_MODE=code): the code-mode extractor would try
     * to pull a fenced block out of this response and, on the rare
     * occasion the model quotes the candidate SQL back inside its
     * explanation, could return just that quoted fragment instead of
     * the leading "PASS"/"FAIL" the pg_strncasecmp check below expects. */
    ensure_reason_ctx();
    if (!g_reason_loaded)
        ereport(ERROR,
                (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                 errmsg("fractal_text_to_sql: no reasoning plugin loaded for review")));

    initStringInfo(&prompt);
    appendStringInfo(&prompt,
        "Original request: %s\n\n"
        "Candidate SQL:\n%s\n\n"
        "Does this candidate correctly and completely answer the request? "
        "Answer PASS or FAIL on the first line, then explain briefly.",
        question, candidate_sql);

    memset(&resp, 0, sizeof(resp));
    int rc = fsql_dispatch_ai(g_reason_ctx,
                              prompt.data, strlen(prompt.data),
                              "{}", 2,
                              &resp);
    if (rc != 0 || resp.rc != 0)
    {
        int          err_rc = rc != 0 ? rc : resp.rc;
        const char  *err = fsql_last_error(g_reason_ctx);
        fsql_ai_response_free(&resp);
        ereport(ERROR,
                (errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
                 errmsg("fractal_text_to_sql: review dispatch failed (rc=%d): %s",
                        err_rc, err && *err ? err : "(no detail)")));
    }

    guard_ai_response_len(&resp);
    /* Length-bounded copy: the ABI supplies summary_len but does not
     * promise NUL-termination (see the matching note in the GENERATE
     * step); pg_strncasecmp/isspace below would over-read a
     * non-terminated buffer if we pstrdup'd blindly. */
    review_text = pnstrdup(resp.summary, resp.summary_len);
    fsql_ai_response_free(&resp);

    p = review_text;
    while (*p && isspace((unsigned char) *p))
        p++;
    passed = (pg_strncasecmp(p, "PASS", 4) == 0);

    *critique_out = review_text;
    return passed;
}

static char *
fractal_text_to_sql_internal(const char *question, ArrayType *table_names, char *feedback)
{
    char *schema_ctx = build_schema_context_cstr(table_names);
    StringInfoData prompt;
    initStringInfo(&prompt);
    appendStringInfo(&prompt,
        "Write a single PostgreSQL %s statement that answers this "
        "question. Return ONLY the SQL, wrapped in a ```sql fenced "
        "code block, with no other explanation.\n\nQuestion: %s\n",
        t2s_allowed_stmts_mode() == T2S_ALLOW_SELECT
            ? "SELECT" : "SELECT, INSERT, or UPDATE",
        question);

    if (feedback != NULL)
        appendStringInfo(&prompt,
            "\nYour previous attempt was rejected for this reason: %s\n\n"
            "Write a corrected statement.\n",
            feedback);

    fsql_ai_response_t gen_resp;
    memset(&gen_resp, 0, sizeof(gen_resp));
    /* Some plugins check RESPONSE_MODE at generate time, not just at
     * load, so assert it again right around the dispatch call. */
    setenv("FSQL_REASONING_HTTP_RESPONSE_MODE", "code", 1);
    int rc = fsql_dispatch_ai(g_t2s_ctx,
                              prompt.data, strlen(prompt.data),
                              schema_ctx, strlen(schema_ctx),
                              &gen_resp);
    unsetenv("FSQL_REASONING_HTTP_RESPONSE_MODE");
    if (rc != 0 || gen_resp.rc != 0) {
        fsql_ai_response_free(&gen_resp);
        return NULL;
    }

    guard_ai_response_len(&gen_resp);
    char *candidate = pnstrdup(gen_resp.summary, gen_resp.summary_len);
    fsql_ai_response_free(&gen_resp);

    return candidate;
}

/* Best-effort audit-chain provenance (fractalsql_ledger kind=2) for a
 * successful text_to_sql attempt. Silent no-op when enterprise isn't
 * loaded or the write fails -- text_to_sql is a community feature and
 * must keep working regardless; the audit record is a bonus when
 * licensed, not a requirement. */
static void
t2s_audit_log_best_effort(const char *question, const char *sql, int attempt)
{
    if (!ensure_enterprise_lib())
        return;

    StringInfoData js;
    initStringInfo(&js);
    appendStringInfoString(&js, "{\"type\":\"text_to_sql\",\"entry\":{\"question\":");
    escape_json(&js, question);
    appendStringInfoString(&js, ",\"generated_sql\":");
    escape_json(&js, sql);
    appendStringInfo(&js, ",\"attempt\":%d,\"allowed_statements\":", attempt);
    escape_json(&js, g_t2s_allowed_stmts ? g_t2s_allowed_stmts : "select");
    appendStringInfoString(&js, "}}");

    (void) ledger_write_entry(NULL, 2, js.data, js.len);
}

PG_FUNCTION_INFO_V1(fractal_text_to_sql);

Datum
fractal_text_to_sql(PG_FUNCTION_ARGS)
{
    ensure_text_to_sql_ctx();

    if (!g_t2s_loaded)
        ereport(ERROR,
                (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                 errmsg("fractal_text_to_sql: no reasoning plugin loaded"),
                 errhint("Set fractalsql.reasoning_plugin in postgresql.conf "
                         "to the absolute path of a compiled "
                         "fractalsql-reasoning-*.so and reconnect.")));

    if (PG_ARGISNULL(0))
        ereport(ERROR,
                (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
                 errmsg("fractal_text_to_sql: question must not be NULL")));

    const char *question = text_to_cstring(PG_GETARG_TEXT_PP(0));
    ArrayType  *table_names_arr = PG_ARGISNULL(1) ? NULL : PG_GETARG_ARRAYTYPE_P(1);

    char *schema_ctx = build_schema_context_cstr(table_names_arr);

    char *last_sql  = NULL;
    char *feedback  = NULL;   /* what was wrong last attempt, fed back into the next GENERATE */

    for (int attempt = 1; attempt <= g_t2s_max_attempts; attempt++)
    {
        /* ---- GENERATE ---- */
        char *candidate = fractal_text_to_sql_internal(question, table_names_arr, feedback);
        if (candidate == NULL) {
            ereport(ERROR, (errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
                            errmsg("fractal_text_to_sql: generate dispatch failed")));
        }
        last_sql = candidate;

        /* ---- ALLOWLIST (raw_parser) ---- */
        char *allow_err = t2s_check_allowlist(candidate);
        if (allow_err != NULL)
        {
            feedback = allow_err;
            if (attempt == g_t2s_max_attempts)
                ereport(ERROR,
                        (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                         errmsg("fractal_text_to_sql: exhausted %d attempt(s), "
                                "last rejection: %s",
                                g_t2s_max_attempts, feedback),
                         errdetail("Last candidate SQL: %s", last_sql)));
            continue;
        }

        /* ---- REVIEW (optional, default off) ---- */
        if (g_t2s_use_review)
        {
            char *critique = NULL;
            bool  passed = t2s_run_review(question, candidate, &critique);
            if (!passed)
            {
                feedback = critique;
                if (attempt == g_t2s_max_attempts)
                    ereport(ERROR,
                            (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                             errmsg("fractal_text_to_sql: exhausted %d attempt(s), "
                                    "last review verdict: %s",
                                    g_t2s_max_attempts, feedback),
                             errdetail("Last candidate SQL: %s", last_sql)));
                continue;
            }
        }

        /* ---- EXPLAIN (mandatory) ---- */
        char *explain_err = t2s_check_explain(candidate);
        if (explain_err != NULL)
        {
            feedback = explain_err;
            if (attempt == g_t2s_max_attempts)
                ereport(ERROR,
                        (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                         errmsg("fractal_text_to_sql: exhausted %d attempt(s), "
                                "last EXPLAIN error: %s",
                                g_t2s_max_attempts, feedback),
                         errdetail("Last candidate SQL: %s", last_sql)));
            continue;
        }

        /* ---- RETURN. Never auto-executed -- see the header comment
         * on this section. ---- */
        t2s_audit_log_best_effort(question, candidate, attempt);
        PG_RETURN_TEXT_P(cstring_to_text(candidate));
    }

    /* Unreachable: the loop above always either returns or ereport(ERROR)s
     * on the final attempt. g_t2s_max_attempts is GUC-bounded to >= 1. */
    ereport(ERROR,
            (errcode(ERRCODE_INTERNAL_ERROR),
             errmsg("fractal_text_to_sql: unreachable retry-loop exit")));
    PG_RETURN_NULL();
}

/* ------------------------------------------------------------------ */
/* v2.x additions -- Diversify/Repulsion controls, feedback,          */
/* fractal-dimension analysis, portfolio optimization, domain-        */
/* specific geometry. All operate on g_ctx (same sovereign ctx used   */
/* by fractal_search/fractal_search_explore) unless noted.            */
/* ------------------------------------------------------------------ */

static size_t *
int4_array_to_sizet(ArrayType *arr, int *out_n)
{
    if (ARR_NDIM(arr) != 1 || ARR_HASNULL(arr))
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("fractalsql: index array must be 1-D non-null int4[]")));
    Datum *ds;
    int    n;
    bool  *nulls;
    deconstruct_array(arr, INT4OID, sizeof(int32), true, 'i', &ds, &nulls, &n);
    size_t *out = palloc(n * sizeof(size_t));
    for (int i = 0; i < n; i++) {
        int32 v = DatumGetInt32(ds[i]);
        if (v < 0)
            ereport(ERROR,
                    (errcode(ERRCODE_DATA_EXCEPTION),
                     errmsg("fractalsql: index array entries must be >= 0 (got %d)", v)));
        out[i] = (size_t) v;
    }
    *out_n = n;
    return out;
}

/* Parse a C JSON string through PostgreSQL's own jsonb_in, matching
 * fractal_search_debug's existing pattern -- simpler and more
 * robust than hand-building JsonbValue trees for these small,
 * fixed-shape result documents. */
static Datum
cstring_json_to_jsonb(const char *json_cstr)
{
    return DirectFunctionCall1(jsonb_in, CStringGetDatum(json_cstr));
}

/* ----- Diversify / Repulsion controls --------------------------- */

PG_FUNCTION_INFO_V1(fractal_diversify_enable);
Datum
fractal_diversify_enable(PG_FUNCTION_ARGS)
{
    ensure_search_ctx();
    int rc = fsql_diversify_enable(g_ctx);
    if (rc != FSQL_OK)
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("fractalsql: fsql_diversify_enable rc=%d: %s",
                        rc, fsql_last_error(g_ctx))));
    PG_RETURN_VOID();
}

PG_FUNCTION_INFO_V1(fractal_diversify_disable);
Datum
fractal_diversify_disable(PG_FUNCTION_ARGS)
{
    ensure_search_ctx();
    int rc = fsql_diversify_disable(g_ctx);
    if (rc != FSQL_OK)
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("fractalsql: fsql_diversify_disable rc=%d: %s",
                        rc, fsql_last_error(g_ctx))));
    PG_RETURN_VOID();
}

PG_FUNCTION_INFO_V1(fractal_diversify_set_params);
Datum
fractal_diversify_set_params(PG_FUNCTION_ARGS)
{
    ensure_search_ctx();

    fsql_diversify_params_t p;
    int rc = fsql_diversify_get_params(g_ctx, &p);
    if (rc != FSQL_OK)
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("fractalsql: fsql_diversify_get_params rc=%d: %s",
                        rc, fsql_last_error(g_ctx))));

    /* Only override fields the caller actually supplied -- NULL args
     * (the default) leave the core's current value in place. */
    if (!PG_ARGISNULL(0)) p.window_n               = (uint32_t) PG_GETARG_INT32(0);
    if (!PG_ARGISNULL(1)) p.stall_threshold        = PG_GETARG_FLOAT8(1);
    if (!PG_ARGISNULL(2)) p.repulsion_sigma        = PG_GETARG_FLOAT8(2);
    if (!PG_ARGISNULL(3)) p.repulsion_weight       = PG_GETARG_FLOAT8(3);
    if (!PG_ARGISNULL(4)) p.max_shadows_considered = (uint32_t) PG_GETARG_INT32(4);
    if (!PG_ARGISNULL(5)) p.tail_buffer_cap        = (uint32_t) PG_GETARG_INT32(5);

    rc = fsql_diversify_set_params(g_ctx, &p);
    if (rc != FSQL_OK)
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("fractalsql: fsql_diversify_set_params rc=%d: %s",
                        rc, fsql_last_error(g_ctx))));
    PG_RETURN_VOID();
}

PG_FUNCTION_INFO_V1(fractal_detect_collapse);
Datum
fractal_detect_collapse(PG_FUNCTION_ARGS)
{
    ensure_search_ctx();
    double dq = fsql_diversify_current_dq(g_ctx);
    PG_RETURN_FLOAT8(dq);
}

/* Session-level Diversify diagnostics: current D_q, whether the
 * monitor is enabled, and its rolling p99 overhead. NOT a per-result
 * "this candidate was penalized by shadow X" trace -- the core ABI
 * doesn't currently surface per-candidate shadow attribution at that
 * granularity (repulsion re-ranking happens inside fsql_search_ptr's
 * dispatch and isn't exposed as separate inspectable state). Scoped
 * honestly rather than overclaiming; per-candidate explain is a real
 * possible future core addition. */
PG_FUNCTION_INFO_V1(fractal_explain_result);
Datum
fractal_explain_result(PG_FUNCTION_ARGS)
{
    ensure_search_ctx();
    fsql_diversify_params_t p;
    int rc = fsql_diversify_get_params(g_ctx, &p);
    bool enabled = (rc == FSQL_OK);
    double dq = fsql_diversify_current_dq(g_ctx);
    double overhead = fsql_diversify_overhead_p99_us(g_ctx);

    char buf[256];
    snprintf(buf, sizeof buf,
        "{\"dq\":%s,\"diversify_enabled\":%s,\"overhead_p99_us\":%s}",
        isnan(dq) ? "null" : psprintf("%.6f", dq),
        enabled ? "true" : "false",
        isnan(overhead) ? "null" : psprintf("%.6f", overhead));
    PG_RETURN_DATUM(cstring_json_to_jsonb(buf));
}

/* ----- Feedback -------------------------------------------------- */

static fsql_engagement_kind_t
parse_engagement_kind(const char *kind)
{
    if (strcmp(kind, "dwell") == 0)    return FSQL_ENGAGE_DWELL;
    if (strcmp(kind, "positive") == 0) return FSQL_ENGAGE_POSITIVE;
    if (strcmp(kind, "negative") == 0) return FSQL_ENGAGE_NEGATIVE;
    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("fractalsql: kind must be one of 'dwell', 'positive', 'negative' (got '%s')",
                    kind)));
    return FSQL_ENGAGE_DWELL; /* unreachable */
}

PG_FUNCTION_INFO_V1(fractal_feedback_report);
Datum
fractal_feedback_report(PG_FUNCTION_ARGS)
{
    int64 result_handle = PG_GETARG_INT64(0);
    char *kind_str       = text_to_cstring(PG_GETARG_TEXT_PP(1));
    int32 dwell_ms       = PG_ARGISNULL(2) ? 0 : PG_GETARG_INT32(2);

    if (result_handle < 0)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("fractalsql: result_handle must be >= 0")));

    ensure_search_ctx();
    fsql_engagement_kind_t kind = parse_engagement_kind(kind_str);
    int rc = fsql_feedback_report(g_ctx, (uint64_t) result_handle, kind,
                                  (uint32_t) dwell_ms);
    if (rc != FSQL_OK)
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("fractalsql: fsql_feedback_report rc=%d: %s",
                        rc, fsql_last_error(g_ctx))));
    PG_RETURN_VOID();
}

/* Convenience wrapper: negative-engagement feedback report, no dwell.
 * Inert until fractal_diversify_enable() has been called on this
 * session -- documented, not silently misleading. */
PG_FUNCTION_INFO_V1(fractal_isolate_background);
Datum
fractal_isolate_background(PG_FUNCTION_ARGS)
{
    int64 result_handle = PG_GETARG_INT64(0);
    if (result_handle < 0)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("fractalsql: result_handle must be >= 0")));

    ensure_search_ctx();
    int rc = fsql_feedback_report(g_ctx, (uint64_t) result_handle,
                                  FSQL_ENGAGE_NEGATIVE, 0);
    if (rc != FSQL_OK)
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("fractalsql: fsql_feedback_report rc=%d: %s",
                        rc, fsql_last_error(g_ctx))));
    PG_RETURN_VOID();
}

/* ----- Fractal Dimension Analysis --------------------------------- */

PG_FUNCTION_INFO_V1(fractal_dimension_dfa);
Datum
fractal_dimension_dfa(PG_FUNCTION_ARGS)
{
    int     n;
    double *series = float8_array_to_doubles(PG_GETARG_ARRAYTYPE_P(0), &n);
    double  alpha;
    int rc = fsql_dimension_dfa(series, (size_t) n, &alpha);
    if (rc != FSQL_OK)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("fractalsql: fractal_dimension_dfa rc=%d "
                        "(series needs >= 16 points)", rc)));
    PG_RETURN_FLOAT8(alpha);
}

PG_FUNCTION_INFO_V1(fractal_dimension_boxcount);
Datum
fractal_dimension_boxcount(PG_FUNCTION_ARGS)
{
    int     flat_n;
    double *points = float8_array_to_doubles(PG_GETARG_ARRAYTYPE_P(0), &flat_n);
    int32   dim     = PG_GETARG_INT32(1);
    if (dim <= 0 || flat_n % dim != 0)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("fractalsql: points length (%d) must be a positive "
                        "multiple of dim (%d)", flat_n, dim)));
    size_t n_points = (size_t) (flat_n / dim);

    double dimension;
    int rc = fsql_dimension_boxcount(points, n_points, (size_t) dim, &dimension);
    if (rc != FSQL_OK)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("fractalsql: fractal_dimension_boxcount rc=%d "
                        "(need >= 8 points, non-degenerate bounding box)", rc)));
    PG_RETURN_FLOAT8(dimension);
}

PG_FUNCTION_INFO_V1(fractal_dimension_drift);
Datum
fractal_dimension_drift(PG_FUNCTION_ARGS)
{
    int     n;
    double *series = float8_array_to_doubles(PG_GETARG_ARRAYTYPE_P(0), &n);
    int32   window  = PG_GETARG_INT32(1);
    if (window <= 0)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("fractalsql: window must be > 0")));

    double drift, recent_alpha, baseline_alpha;
    int rc = fsql_dimension_drift(series, (size_t) n, (size_t) window,
                                  &drift, &recent_alpha, &baseline_alpha);
    if (rc != FSQL_OK)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("fractalsql: fractal_dimension_drift rc=%d "
                        "(need n >= window + 16, window >= 16)", rc)));

    char buf[256];
    snprintf(buf, sizeof buf,
        "{\"drift\":%.10f,\"recent_alpha\":%.10f,\"baseline_alpha\":%.10f}",
        drift, recent_alpha, baseline_alpha);
    PG_RETURN_DATUM(cstring_json_to_jsonb(buf));
}

/* ----- Portfolio Optimization -------------------------------------- */

/* diffusion_mode text -> the FSQL_SFS_DIFFUSE_* int the core expects
 * (include/sfs_core_c.h). Same enum-from-text convention as
 * parse_engagement_kind above. */
static int
parse_diffusion_mode(const char *mode)
{
    if (strcmp(mode, "gaussian") == 0) return 0; /* FSQL_SFS_DIFFUSE_GAUSSIAN */
    if (strcmp(mode, "levy") == 0)     return 1; /* FSQL_SFS_DIFFUSE_LEVY */
    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("fractalsql: diffusion_mode must be 'gaussian' or 'levy' (got '%s')",
                    mode)));
    return 0; /* unreachable */
}

/* Best-effort audit-chain provenance (fractalsql_ledger kind=2) for a
 * portfolio decision. inputs_hash covers mu+cov so the decision's inputs
 * are verifiable later without duplicating a potentially large
 * covariance matrix into the ledger. Silent no-op when enterprise isn't
 * loaded or the write fails -- portfolio optimization is a community
 * feature and must keep working regardless. */
static void
portfolio_audit_log_best_effort(const double *mu, const double *cov,
                                int n_assets, int k, int64 seed,
                                double sharpe, const double *weights)
{
    if (!ensure_enterprise_lib())
        return;

    uint8_t hash[32];
    {
        size_t   mu_bytes  = (size_t) n_assets * sizeof(double);
        size_t   cov_bytes = (size_t) n_assets * n_assets * sizeof(double);
        uint8_t *buf = (uint8_t *) palloc(mu_bytes + cov_bytes);
        memcpy(buf, mu, mu_bytes);
        memcpy(buf + mu_bytes, cov, cov_bytes);
        fsql_sha256(buf, mu_bytes + cov_bytes, hash);
        pfree(buf);
    }
    char hash_hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(hash_hex + i * 2, 3, "%02x", hash[i]);

    StringInfoData js;
    initStringInfo(&js);
    appendStringInfo(&js,
        "{\"type\":\"portfolio_optimize\",\"entry\":{"
        "\"seed\":%lld,\"n_assets\":%d,\"k\":%d,\"sharpe\":%.10f,"
        "\"inputs_hash\":\"%s\",\"weights\":[",
        (long long) seed, n_assets, k, sharpe, hash_hex);
    for (int i = 0; i < n_assets; i++)
        appendStringInfo(&js, "%s%.10f", i > 0 ? "," : "", weights[i]);
    appendStringInfoString(&js, "]}}");

    (void) ledger_write_entry(NULL, 2, js.data, js.len);
}

/* Same provenance pattern as portfolio_audit_log_best_effort, for the
 * multimodal (n_found candidates) result. */
static void
portfolio_multimodal_audit_log_best_effort(const double *mu, const double *cov,
                                           int n_assets, int k, int n_restarts,
                                           int64 seed, int n_found,
                                           const double *sharpes, const double *weights)
{
    if (!ensure_enterprise_lib())
        return;

    uint8_t hash[32];
    {
        size_t   mu_bytes  = (size_t) n_assets * sizeof(double);
        size_t   cov_bytes = (size_t) n_assets * n_assets * sizeof(double);
        uint8_t *buf = (uint8_t *) palloc(mu_bytes + cov_bytes);
        memcpy(buf, mu, mu_bytes);
        memcpy(buf + mu_bytes, cov, cov_bytes);
        fsql_sha256(buf, mu_bytes + cov_bytes, hash);
        pfree(buf);
    }
    char hash_hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(hash_hex + i * 2, 3, "%02x", hash[i]);

    StringInfoData js;
    initStringInfo(&js);
    appendStringInfo(&js,
        "{\"type\":\"portfolio_optimize_multimodal\",\"entry\":{"
        "\"seed\":%lld,\"n_assets\":%d,\"k\":%d,\"n_restarts\":%d,\"n_found\":%d,"
        "\"inputs_hash\":\"%s\",\"candidates\":[",
        (long long) seed, n_assets, k, n_restarts, n_found, hash_hex);
    for (int c = 0; c < n_found; c++)
    {
        appendStringInfo(&js, "%s{\"sharpe\":%.10f,\"weights\":[",
                         c > 0 ? "," : "", sharpes[c]);
        for (int i = 0; i < n_assets; i++)
            appendStringInfo(&js, "%s%.10f", i > 0 ? "," : "",
                             weights[(size_t) c * n_assets + i]);
        appendStringInfoString(&js, "]}");
    }
    appendStringInfoString(&js, "]}}");

    (void) ledger_write_entry(NULL, 2, js.data, js.len);
}

PG_FUNCTION_INFO_V1(fractal_optimize_portfolio);
Datum
fractal_optimize_portfolio(PG_FUNCTION_ARGS)
{
    int     n_assets;
    double *mu  = float8_array_to_doubles(PG_GETARG_ARRAYTYPE_P(0), &n_assets);
    int     cov_n;
    double *cov = float8_array_to_doubles(PG_GETARG_ARRAYTYPE_P(1), &cov_n);
    int32   k    = PG_GETARG_INT32(2);
    int64   seed = PG_ARGISNULL(3) ? 0 : PG_GETARG_INT64(3);
    bool    use_obl = PG_ARGISNULL(4) ? false : PG_GETARG_BOOL(4);
    int     diffusion_mode = PG_ARGISNULL(5) ? 0 :
        parse_diffusion_mode(text_to_cstring(PG_GETARG_TEXT_PP(5)));

    /* Both sides widened to int64 before multiplying: n_assets and cov_n
     * are plain int, so n_assets * n_assets alone can overflow 32 bits
     * for a large n_assets and wrap to a small or negative number. That
     * would let an attacker pick an n_assets whose square wraps to a
     * small value, then supply a cov array of only that small size
     * instead of the true n_assets^2 the check is meant to require. The
     * optimizer below then reads cov as an n_assets x n_assets matrix,
     * running far past the actual buffer. */
    if ((int64) cov_n != (int64) n_assets * n_assets)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("fractalsql: cov length (%d) must be n_assets^2 "
                        "(n_assets=%d, expected %lld)",
                        cov_n, n_assets, (long long) n_assets * n_assets)));
    if (k <= 0 || k > n_assets)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("fractalsql: k must satisfy 1 <= k <= n_assets (%d)", n_assets)));

    double *weights = palloc(n_assets * sizeof(double));
    double  sharpe;
    int rc = fsql_optimize_portfolio_ex(mu, cov, (size_t) n_assets, (size_t) k,
                                        (uint64_t) seed, use_obl, diffusion_mode,
                                        weights, &sharpe);
    if (rc != FSQL_OK)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("fractalsql: fractal_optimize_portfolio rc=%d", rc)));

    portfolio_audit_log_best_effort(mu, cov, n_assets, (int) k, seed, sharpe, weights);

    StringInfoData out;
    initStringInfo(&out);
    appendStringInfo(&out, "{\"sharpe\":%.10f,\"weights\":[", sharpe);
    for (int i = 0; i < n_assets; i++)
        appendStringInfo(&out, "%s%.10f", i > 0 ? "," : "", weights[i]);
    appendStringInfoString(&out, "]}");
    PG_RETURN_DATUM(cstring_json_to_jsonb(out.data));
}

/* Enterprise-gated capability (see ensure_enterprise_lib's optional 9th
 * symbol above): same search as fractal_optimize_portfolio, run
 * n_restarts times with different derived seeds, diverse-selected. */
PG_FUNCTION_INFO_V1(fractal_optimize_portfolio_multimodal);
Datum
fractal_optimize_portfolio_multimodal(PG_FUNCTION_ARGS)
{
    ensure_search_ctx();
    if (!ensure_enterprise_lib())
        enterprise_not_loaded_error();
    if (!g_ent_optimize_portfolio_multimodal)
        ereport(ERROR,
                (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                 errmsg("fractalsql: fractal_optimize_portfolio_multimodal "
                        "not available in this enterprise library"),
                 errhint("This enterprise core build predates portfolio "
                         "multimodal support -- upgrade fractalsql.enterprise_lib.")));

    int     n_assets;
    double *mu  = float8_array_to_doubles(PG_GETARG_ARRAYTYPE_P(0), &n_assets);
    int     cov_n;
    double *cov = float8_array_to_doubles(PG_GETARG_ARRAYTYPE_P(1), &cov_n);
    int32   k             = PG_GETARG_INT32(2);
    int32   n_restarts    = PG_ARGISNULL(3) ? 8    : PG_GETARG_INT32(3);
    float8  overlap_thr   = PG_ARGISNULL(4) ? 0.15 : PG_GETARG_FLOAT8(4);
    float8  quality_frac  = PG_ARGISNULL(5) ? 0.90 : PG_GETARG_FLOAT8(5);
    int64   seed          = PG_ARGISNULL(6) ? 0    : PG_GETARG_INT64(6);
    bool    use_obl       = PG_ARGISNULL(7) ? false : PG_GETARG_BOOL(7);
    int     diffusion_mode = PG_ARGISNULL(8) ? 0 :
        parse_diffusion_mode(text_to_cstring(PG_GETARG_TEXT_PP(8)));

    /* Both sides widened to int64 before multiplying: n_assets and cov_n
     * are plain int, so n_assets * n_assets alone can overflow 32 bits
     * for a large n_assets and wrap to a small or negative number. That
     * would let an attacker pick an n_assets whose square wraps to a
     * small value, then supply a cov array of only that small size
     * instead of the true n_assets^2 the check is meant to require. The
     * optimizer below then reads cov as an n_assets x n_assets matrix,
     * running far past the actual buffer. */
    if ((int64) cov_n != (int64) n_assets * n_assets)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("fractalsql: cov length (%d) must be n_assets^2 "
                        "(n_assets=%d, expected %lld)",
                        cov_n, n_assets, (long long) n_assets * n_assets)));
    if (k <= 0 || k > n_assets)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("fractalsql: k must satisfy 1 <= k <= n_assets (%d)", n_assets)));
    if (n_restarts <= 0 || n_restarts > 64)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("fractalsql: n_restarts must satisfy 1 <= n_restarts <= 64")));

    double *weights = palloc((size_t) n_restarts * n_assets * sizeof(double));
    double *sharpes = palloc((size_t) n_restarts * sizeof(double));
    int     n_found = 0;
    int     rc;

    if (g_ent_optimize_portfolio_multimodal_ex) {
        rc = g_ent_optimize_portfolio_multimodal_ex(
            mu, cov, (size_t) n_assets, (size_t) k, n_restarts,
            overlap_thr, quality_frac, (uint64_t) seed,
            use_obl, diffusion_mode,
            weights, sharpes, &n_found);
    } else if (use_obl || diffusion_mode != 0) {
        ereport(ERROR,
                (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                 errmsg("fractalsql: use_obl/diffusion_mode "
                        "not available in this enterprise library"),
                 errhint("This enterprise core build predates portfolio "
                         "OBL/Lévy-flight support -- upgrade fractalsql.enterprise_lib, "
                         "or omit use_obl/diffusion_mode.")));
        rc = FSQL_ERR_INVALID; /* unreachable */
    } else {
        rc = g_ent_optimize_portfolio_multimodal(
            mu, cov, (size_t) n_assets, (size_t) k, n_restarts,
            overlap_thr, quality_frac, (uint64_t) seed,
            weights, sharpes, &n_found);
    }
    if (rc != FSQL_OK)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("fractalsql: fractal_optimize_portfolio_multimodal rc=%d", rc)));

    StringInfoData out;
    initStringInfo(&out);
    appendStringInfoString(&out, "{\"candidates\":[");
    for (int c = 0; c < n_found; c++)
    {
        appendStringInfo(&out, "%s{\"sharpe\":%.10f,\"weights\":[",
                         c > 0 ? "," : "", sharpes[c]);
        for (int i = 0; i < n_assets; i++)
            appendStringInfo(&out, "%s%.10f", i > 0 ? "," : "",
                             weights[(size_t) c * n_assets + i]);
        appendStringInfoString(&out, "]}");
    }
    appendStringInfo(&out, "],\"n_found\":%d}", n_found);

    portfolio_multimodal_audit_log_best_effort(mu, cov, n_assets, (int) k,
        n_restarts, seed, n_found, sharpes, weights);

    PG_RETURN_DATUM(cstring_json_to_jsonb(out.data));
}

/* Same provenance pattern as portfolio_multimodal_audit_log_best_effort,
 * for the Pareto-front (n_found candidates, return/risk pairs) result. */
static void
portfolio_multimodal_pareto_audit_log_best_effort(const double *mu, const double *cov,
                                                   int n_assets, int k, int n_restarts,
                                                   int max_front, int64 seed, int n_found,
                                                   const double *returns, const double *risks,
                                                   const double *weights)
{
    if (!ensure_enterprise_lib())
        return;

    uint8_t hash[32];
    {
        size_t   mu_bytes  = (size_t) n_assets * sizeof(double);
        size_t   cov_bytes = (size_t) n_assets * n_assets * sizeof(double);
        uint8_t *buf = (uint8_t *) palloc(mu_bytes + cov_bytes);
        memcpy(buf, mu, mu_bytes);
        memcpy(buf + mu_bytes, cov, cov_bytes);
        fsql_sha256(buf, mu_bytes + cov_bytes, hash);
        pfree(buf);
    }
    char hash_hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(hash_hex + i * 2, 3, "%02x", hash[i]);

    StringInfoData js;
    initStringInfo(&js);
    appendStringInfo(&js,
        "{\"type\":\"portfolio_optimize_multimodal_pareto\",\"entry\":{"
        "\"seed\":%lld,\"n_assets\":%d,\"k\":%d,\"n_restarts\":%d,\"max_front\":%d,"
        "\"n_found\":%d,\"inputs_hash\":\"%s\",\"candidates\":[",
        (long long) seed, n_assets, k, n_restarts, max_front, n_found, hash_hex);
    for (int c = 0; c < n_found; c++)
    {
        appendStringInfo(&js, "%s{\"return\":%.10f,\"risk\":%.10f,\"weights\":[",
                         c > 0 ? "," : "", returns[c], risks[c]);
        for (int i = 0; i < n_assets; i++)
            appendStringInfo(&js, "%s%.10f", i > 0 ? "," : "",
                             weights[(size_t) c * n_assets + i]);
        appendStringInfoString(&js, "]}");
    }
    appendStringInfoString(&js, "]}}");

    (void) ledger_write_entry(NULL, 2, js.data, js.len);
}

/* Enterprise-gated capability (see ensure_enterprise_lib's optional 10th
 * symbol above): same n_restarts search as
 * fractal_optimize_portfolio_multimodal, but scored by decomposed
 * (return, risk) instead of scalar Sharpe and reduced to a genuine non-
 * dominated Pareto front (NSGA-II crowding-distance truncation past
 * max_front) instead of the sharpe-threshold + asset-overlap selection
 * the sharpe-mode function uses. Additive alongside that function --
 * does not change its selection semantics or output shape. */
PG_FUNCTION_INFO_V1(fractal_optimize_portfolio_multimodal_pareto);
Datum
fractal_optimize_portfolio_multimodal_pareto(PG_FUNCTION_ARGS)
{
    ensure_search_ctx();
    if (!ensure_enterprise_lib())
        enterprise_not_loaded_error();
    if (!g_ent_optimize_portfolio_multimodal_pareto)
        ereport(ERROR,
                (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                 errmsg("fractalsql: fractal_optimize_portfolio_multimodal_pareto "
                        "not available in this enterprise library"),
                 errhint("This enterprise core build predates portfolio "
                         "multimodal Pareto support -- upgrade fractalsql.enterprise_lib.")));

    int     n_assets;
    double *mu  = float8_array_to_doubles(PG_GETARG_ARRAYTYPE_P(0), &n_assets);
    int     cov_n;
    double *cov = float8_array_to_doubles(PG_GETARG_ARRAYTYPE_P(1), &cov_n);
    int32   k          = PG_GETARG_INT32(2);
    int32   n_restarts = PG_ARGISNULL(3) ? 8 : PG_GETARG_INT32(3);
    int32   max_front  = PG_ARGISNULL(4) ? 8 : PG_GETARG_INT32(4);
    int64   seed       = PG_ARGISNULL(5) ? 0 : PG_GETARG_INT64(5);
    bool    use_obl    = PG_ARGISNULL(6) ? false : PG_GETARG_BOOL(6);
    int     diffusion_mode = PG_ARGISNULL(7) ? 0 :
        parse_diffusion_mode(text_to_cstring(PG_GETARG_TEXT_PP(7)));

    /* Both sides widened to int64 before multiplying: n_assets and cov_n
     * are plain int, so n_assets * n_assets alone can overflow 32 bits
     * for a large n_assets and wrap to a small or negative number. That
     * would let an attacker pick an n_assets whose square wraps to a
     * small value, then supply a cov array of only that small size
     * instead of the true n_assets^2 the check is meant to require. The
     * optimizer below then reads cov as an n_assets x n_assets matrix,
     * running far past the actual buffer. */
    if ((int64) cov_n != (int64) n_assets * n_assets)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("fractalsql: cov length (%d) must be n_assets^2 "
                        "(n_assets=%d, expected %lld)",
                        cov_n, n_assets, (long long) n_assets * n_assets)));
    if (k <= 0 || k > n_assets)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("fractalsql: k must satisfy 1 <= k <= n_assets (%d)", n_assets)));
    if (n_restarts <= 0 || n_restarts > 64)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("fractalsql: n_restarts must satisfy 1 <= n_restarts <= 64")));
    if (max_front <= 0 || max_front > n_restarts)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("fractalsql: max_front must satisfy 1 <= max_front <= n_restarts (%d)",
                        n_restarts)));

    double *weights = palloc((size_t) max_front * n_assets * sizeof(double));
    double *returns = palloc((size_t) max_front * sizeof(double));
    double *risks   = palloc((size_t) max_front * sizeof(double));
    int     n_found = 0;

    int rc = g_ent_optimize_portfolio_multimodal_pareto(
        mu, cov, (size_t) n_assets, (size_t) k, n_restarts, max_front,
        (uint64_t) seed, use_obl, diffusion_mode, weights, returns, risks, &n_found);
    if (rc != FSQL_OK)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("fractalsql: fractal_optimize_portfolio_multimodal_pareto rc=%d", rc)));

    StringInfoData out;
    initStringInfo(&out);
    appendStringInfoString(&out, "{\"candidates\":[");
    for (int c = 0; c < n_found; c++)
    {
        appendStringInfo(&out, "%s{\"return\":%.10f,\"risk\":%.10f,\"sharpe\":%.10f,\"weights\":[",
                         c > 0 ? "," : "", returns[c], risks[c],
                         risks[c] != 0.0 ? returns[c] / risks[c] : 0.0);
        for (int i = 0; i < n_assets; i++)
            appendStringInfo(&out, "%s%.10f", i > 0 ? "," : "",
                             weights[(size_t) c * n_assets + i]);
        appendStringInfoString(&out, "]}");
    }
    appendStringInfo(&out, "],\"n_found\":%d}", n_found);

    portfolio_multimodal_pareto_audit_log_best_effort(mu, cov, n_assets, (int) k,
        n_restarts, max_front, seed, n_found, returns, risks, weights);

    PG_RETURN_DATUM(cstring_json_to_jsonb(out.data));
}

/* ----- Domain-specific geometric/topological metrics ---------------- */

PG_FUNCTION_INFO_V1(fractal_vascular_network);
Datum
fractal_vascular_network(PG_FUNCTION_ARGS)
{
    int     nc_n;
    double *node_coords = float8_array_to_doubles(PG_GETARG_ARRAYTYPE_P(0), &nc_n);
    int     e_n;
    size_t *edges       = int4_array_to_sizet(PG_GETARG_ARRAYTYPE_P(1), &e_n);
    int     al_n;
    double *arc_length  = float8_array_to_doubles(PG_GETARG_ARRAYTYPE_P(2), &al_n);

    if (nc_n % 3 != 0)
        ereport(ERROR, (errcode(ERRCODE_DATA_EXCEPTION),
                        errmsg("fractalsql: node_coords length must be a multiple of 3")));
    if (e_n % 2 != 0)
        ereport(ERROR, (errcode(ERRCODE_DATA_EXCEPTION),
                        errmsg("fractalsql: edges length must be a multiple of 2")));
    if (al_n != e_n / 2)
        ereport(ERROR, (errcode(ERRCODE_DATA_EXCEPTION),
                        errmsg("fractalsql: edge_arc_length length (%d) must equal "
                               "edges length / 2 (%d)", al_n, e_n / 2)));

    double mean_tortuosity, branch_density, fractal_dimension;
    int rc = fsql_vascular_network(node_coords, (size_t) (nc_n / 3),
                                   edges, arc_length, (size_t) (e_n / 2),
                                   &mean_tortuosity, &branch_density, &fractal_dimension);
    if (rc != FSQL_OK)
        ereport(ERROR, (errcode(ERRCODE_DATA_EXCEPTION),
                        errmsg("fractalsql: fractal_vascular_network rc=%d", rc)));

    char buf[320];
    snprintf(buf, sizeof buf,
        "{\"mean_tortuosity\":%.10f,\"branch_density\":%.10f,\"fractal_dimension\":%.10f}",
        mean_tortuosity, branch_density, fractal_dimension);
    PG_RETURN_DATUM(cstring_json_to_jsonb(buf));
}

PG_FUNCTION_INFO_V1(fractal_cortical_folding);
Datum
fractal_cortical_folding(PG_FUNCTION_ARGS)
{
    int     v_n;
    double *vertices = float8_array_to_doubles(PG_GETARG_ARRAYTYPE_P(0), &v_n);
    int     f_n;
    size_t *faces    = int4_array_to_sizet(PG_GETARG_ARRAYTYPE_P(1), &f_n);

    if (v_n % 3 != 0)
        ereport(ERROR, (errcode(ERRCODE_DATA_EXCEPTION),
                        errmsg("fractalsql: vertices length must be a multiple of 3")));
    if (f_n % 3 != 0)
        ereport(ERROR, (errcode(ERRCODE_DATA_EXCEPTION),
                        errmsg("fractalsql: faces length must be a multiple of 3")));

    double mesh_area, hull_area, gi;
    int rc = fsql_cortical_folding(vertices, (size_t) (v_n / 3),
                                   faces, (size_t) (f_n / 3),
                                   &mesh_area, &hull_area, &gi);
    if (rc != FSQL_OK)
        ereport(ERROR, (errcode(ERRCODE_DATA_EXCEPTION),
                        errmsg("fractalsql: fractal_cortical_folding rc=%d "
                               "(need >= 4 non-coplanar vertices)", rc)));

    char buf[320];
    snprintf(buf, sizeof buf,
        "{\"mesh_area\":%.10f,\"hull_area\":%.10f,\"gyrification_index\":%.10f}",
        mesh_area, hull_area, gi);
    PG_RETURN_DATUM(cstring_json_to_jsonb(buf));
}

PG_FUNCTION_INFO_V1(fractal_nerve_plexus_metric);
Datum
fractal_nerve_plexus_metric(PG_FUNCTION_ARGS)
{
    int     nc_n;
    double *node_coords = float8_array_to_doubles(PG_GETARG_ARRAYTYPE_P(0), &nc_n);
    int32   dim         = PG_GETARG_INT32(1);
    int     e_n;
    size_t *edges       = int4_array_to_sizet(PG_GETARG_ARRAYTYPE_P(2), &e_n);

    if (dim <= 0 || nc_n % dim != 0)
        ereport(ERROR, (errcode(ERRCODE_DATA_EXCEPTION),
                        errmsg("fractalsql: node_coords length (%d) must be a "
                               "positive multiple of dim (%d)", nc_n, dim)));
    if (e_n % 2 != 0)
        ereport(ERROR, (errcode(ERRCODE_DATA_EXCEPTION),
                        errmsg("fractalsql: edges length must be a multiple of 2")));

    double fiber_length_density, branch_density, fractal_dimension;
    int rc = fsql_nerve_plexus_metric(node_coords, (size_t) (nc_n / dim), (size_t) dim,
                                      edges, (size_t) (e_n / 2),
                                      &fiber_length_density, &branch_density,
                                      &fractal_dimension);
    if (rc != FSQL_OK)
        ereport(ERROR, (errcode(ERRCODE_DATA_EXCEPTION),
                        errmsg("fractalsql: fractal_nerve_plexus_metric rc=%d", rc)));

    char buf[320];
    snprintf(buf, sizeof buf,
        "{\"fiber_length_density\":%.10f,\"branch_density\":%.10f,"
        "\"fractal_dimension\":%.10f}",
        fiber_length_density, branch_density, fractal_dimension);
    PG_RETURN_DATUM(cstring_json_to_jsonb(buf));
}

PG_FUNCTION_INFO_V1(fractal_morphological_complexity);
Datum
fractal_morphological_complexity(PG_FUNCTION_ARGS)
{
    int     p_n;
    double *points = float8_array_to_doubles(PG_GETARG_ARRAYTYPE_P(0), &p_n);
    int32   dim    = PG_GETARG_INT32(1);
    if (dim <= 0 || p_n % dim != 0)
        ereport(ERROR, (errcode(ERRCODE_DATA_EXCEPTION),
                        errmsg("fractalsql: points length (%d) must be a positive "
                               "multiple of dim (%d)", p_n, dim)));

    double dimension, lacunarity;
    int rc = fsql_morphological_complexity(points, (size_t) (p_n / dim), (size_t) dim,
                                           &dimension, &lacunarity);
    if (rc != FSQL_OK)
        ereport(ERROR, (errcode(ERRCODE_DATA_EXCEPTION),
                        errmsg("fractalsql: fractal_morphological_complexity rc=%d "
                               "(need >= 8 points, non-degenerate bounding box)", rc)));

    char buf[256];
    snprintf(buf, sizeof buf, "{\"dimension\":%.10f,\"lacunarity\":%.10f}",
             dimension, lacunarity);
    PG_RETURN_DATUM(cstring_json_to_jsonb(buf));
}

/* ------------------------------------------------------------------ */
/* Named feature store (Postgres-side, no core primitive needed)      */
/*                                                                    */
/* fractal_store_morphology / fractal_mine_topology_negatives were    */
/* originally scoped to a core ledger primitive that doesn't exist:   */
/* the real fsql_ledger_* API is whole-ledger admin (flush/load/      */
/* compact/reset) plus two counters, not a per-item put/get and not a */
/* shadow-vector read-back. Postgres itself is a perfectly good named */
/* feature store, so both functions are implemented entirely at this  */
/* layer instead: a plain table (fractalsql_feature_store) holding    */
/* one caller-supplied vector per doc_id, written by                  */
/* fractal_store_morphology and k-NN-scanned (plain squared-Euclidean */
/* distance, brute-force -- table is expected to hold curated         */
/* per-item features/negative examples, not a full corpus) by         */
/* fractal_mine_topology_negatives. Nothing about this depends on     */
/* core's ledger/repulsion mechanism, which is unaffected.            */
/* ------------------------------------------------------------------ */

PG_FUNCTION_INFO_V1(fractal_store_morphology);
Datum
fractal_store_morphology(PG_FUNCTION_ARGS)
{
    int64      doc_id   = PG_GETARG_INT64(0);
    ArrayType *feat_arr = PG_GETARG_ARRAYTYPE_P(1);

    if (doc_id < 0)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("fractalsql: doc_id must be >= 0")));
    /* Validation only (1-D, non-null, non-empty) -- feat_arr itself is
     * passed through to SPI unchanged below. */
    int discard_n;
    (void) float8_array_to_doubles(feat_arr, &discard_n);

    if (SPI_connect() != SPI_OK_CONNECT)
        ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR),
                        errmsg("fractalsql: SPI_connect failed")));

    Oid   argtypes[2] = { INT8OID, FLOAT8ARRAYOID };
    Datum argvals[2]  = { Int64GetDatum(doc_id), PointerGetDatum(feat_arr) };

    int rc = SPI_execute_with_args(
        "INSERT INTO fractalsql_feature_store (doc_id, features, updated_at) "
        "VALUES ($1, $2, now()) "
        "ON CONFLICT (doc_id) DO UPDATE "
        "SET features = EXCLUDED.features, updated_at = EXCLUDED.updated_at",
        2, argtypes, argvals, NULL, false, 0);
    if (rc != SPI_OK_INSERT) {
        SPI_finish();
        ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR),
                        errmsg("fractalsql: feature store upsert failed (rc=%d)", rc)));
    }
    SPI_finish();
    PG_RETURN_VOID();
}

/* Ascending by distance -- SPI/tuplestore work happens on a single
 * backend thread per connection, so a plain static-comparator qsort
 * (unlike the reentrant core C library's own top-k code) is fine here. */
typedef struct { int64 doc_id; double dist; } fsql_topo_cand_t;

static int
topo_cand_cmp(const void *a, const void *b)
{
    double da = ((const fsql_topo_cand_t *) a)->dist;
    double db = ((const fsql_topo_cand_t *) b)->dist;
    if (da < db) return -1;
    if (da > db) return 1;
    return 0;
}

PG_FUNCTION_INFO_V1(fractal_mine_topology_negatives);
Datum
fractal_mine_topology_negatives(PG_FUNCTION_ARGS)
{
    ArrayType *surrogate_arr = PG_GETARG_ARRAYTYPE_P(0);
    int32      k             = PG_GETARG_INT32(1);

    if (k <= 0)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("fractalsql: k must be > 0")));

    int     dim;
    double *surrogate = float8_array_to_doubles(surrogate_arr, &dim);

    ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
    if (rsinfo == NULL || !(rsinfo->allowedModes & SFRM_Materialize))
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                 errmsg("fractalsql: set-valued function called in context "
                        "that cannot accept a set")));

    MemoryContext per_query_ctx = rsinfo->econtext->ecxt_per_query_memory;
    MemoryContext oldcontext    = MemoryContextSwitchTo(per_query_ctx);

    TupleDesc tupdesc;
    if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
        ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                        errmsg("fractalsql: function returning record called "
                               "in context that cannot accept type record")));
    tupdesc = BlessTupleDesc(tupdesc);

    Tuplestorestate *tupstore = tuplestore_begin_heap(false, false, work_mem);
    rsinfo->returnMode = SFRM_Materialize;
    rsinfo->setResult  = tupstore;
    rsinfo->setDesc    = tupdesc;

    MemoryContextSwitchTo(oldcontext);

    if (SPI_connect() != SPI_OK_CONNECT)
        ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR),
                        errmsg("fractalsql: SPI_connect failed")));

    int rc = SPI_execute(
        "SELECT doc_id, features FROM fractalsql_feature_store", true, 0);
    if (rc != SPI_OK_SELECT) {
        SPI_finish();
        ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR),
                        errmsg("fractalsql: feature store scan failed (rc=%d)", rc)));
    }

    uint64            n     = SPI_processed;
    fsql_topo_cand_t *cands = n > 0
        ? MemoryContextAlloc(per_query_ctx, n * sizeof(fsql_topo_cand_t)) : NULL;
    uint64            kept  = 0;
    TupleDesc         rtupdesc = SPI_tuptable ? SPI_tuptable->tupdesc : NULL;

    for (uint64 r = 0; r < n; r++) {
        bool  isnull;
        Datum d_id = SPI_getbinval(SPI_tuptable->vals[r], rtupdesc, 1, &isnull);
        if (isnull) continue;
        Datum d_vec = SPI_getbinval(SPI_tuptable->vals[r], rtupdesc, 2, &isnull);
        if (isnull) continue;

        int     rdim;
        double *rv = float8_array_to_doubles(DatumGetArrayTypeP(d_vec), &rdim);
        if (rdim != dim) continue; /* mismatched dim -- skip, don't abort the scan */

        double sumsq = 0.0;
        for (int j = 0; j < dim; j++) {
            double diff = rv[j] - surrogate[j];
            sumsq += diff * diff;
        }
        cands[kept].doc_id = DatumGetInt64(d_id);
        cands[kept].dist   = sqrt(sumsq);
        kept++;
    }
    SPI_finish();

    if (kept > 0)
        qsort(cands, kept, sizeof(fsql_topo_cand_t), topo_cand_cmp);

    uint64 out_n = kept < (uint64) k ? kept : (uint64) k;
    for (uint64 i = 0; i < out_n; i++) {
        Datum values[2];
        bool  nulls[2] = { false, false };
        values[0] = Int64GetDatum(cands[i].doc_id);
        values[1] = Float8GetDatum(cands[i].dist);
        tuplestore_putvalues(tupstore, tupdesc, values, nulls);
    }

    return (Datum) 0;
}

/* ------------------------------------------------------------------ */
/* Table-backed top-k telemetry search + thin compositions            */
/*                                                                    */
/* fsql_search_ptr's result JSON always carries a "top_k" array       */
/* (idx/dist pairs) once k > 1, but nothing in this extension parsed  */
/* it out for a real corpus table -- fractal_search_explore          */
/* returns Scout's raw population, not indexed top-k results, and     */
/* fractal_search/fractal_search_debug use a single-row dummy corpus  */
/* (the query itself), not a real table. fractal_search_telemetry     */
/* closes that gap: a genuine "k nearest rows from this table, with   */
/* their row indices and distances" primitive, which the three        */
/* compositions below build on.                                       */
/*                                                                    */
/* fractal_hybrid_clinical_search deliberately does NOT take a raw    */
/* SQL predicate/filter string -- interpolating caller-supplied SQL   */
/* text into a dynamic query is exactly the class of risk this        */
/* extension's own text-to-sql pipeline goes to great lengths to      */
/* guard against (allowlisted, single-SELECT-only, gate 10's          */
/* injection-shaped-identifier tests). Instead it takes doc_ids        */
/* int8[] -- the caller computes their cohort filter with ordinary,    */
/* already-safe SQL ("SELECT array_agg(id) FROM patients WHERE ...")  */
/* and passes the result in; no dynamic SQL is ever constructed here. */
/* ------------------------------------------------------------------ */

/* Shared SRF core: given an in-memory corpus (already scanned/built
 * by the caller) and a query, run fsql_search_ptr's plain top-k mode
 * and materialize (doc_id, distance) into the tuplestore. Caller must
 * have already validated k > 0 and set up rsinfo's materialize mode
 * expectations (i.e. call from a RETURNS TABLE/SETOF record function).
 *
 * doc_id_map: NULL for the common case (corpus row i IS doc_id i, a
 * full unfiltered table scan). Non-NULL for a FILTERED/reordered
 * corpus (fractal_hybrid_clinical_search's cohort scan) -- fsql_
 * search_ptr's top_k indices are positions within whatever corpus it
 * was actually given, which are NOT the caller's true doc_ids once
 * the corpus has been filtered; doc_id_map[i] translates corpus
 * position i back to the real doc_id. Must have >= n_rows entries. */
static Datum
telemetry_topk_srf(FunctionCallInfo fcinfo,
                   const double *corpus, size_t n_rows, size_t dim,
                   const double *query, int32 k,
                   const int64 *doc_id_map)
{
    ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
    if (rsinfo == NULL || !(rsinfo->allowedModes & SFRM_Materialize))
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                 errmsg("fractalsql: set-valued function called in context "
                        "that cannot accept a set")));

    MemoryContext per_query_ctx = rsinfo->econtext->ecxt_per_query_memory;
    MemoryContext oldcontext    = MemoryContextSwitchTo(per_query_ctx);

    TupleDesc tupdesc;
    if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
        ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                        errmsg("fractalsql: function returning record called "
                               "in context that cannot accept type record")));
    tupdesc = BlessTupleDesc(tupdesc);

    Tuplestorestate *tupstore = tuplestore_begin_heap(false, false, work_mem);
    rsinfo->returnMode = SFRM_Materialize;
    rsinfo->setResult  = tupstore;
    rsinfo->setDesc    = tupdesc;

    MemoryContextSwitchTo(oldcontext);

    if (n_rows == 0)
        ereport(ERROR, (errcode(ERRCODE_NO_DATA_FOUND),
                        errmsg("fractalsql: no corpus rows to search")));

    ensure_search_ctx();
    char params[192];
    snprintf(params, sizeof params,
        "{\"max_generation\":15,\"population_size\":50,"
        "\"maximum_diffusion\":2,\"walk\":0.5,\"bound_clipping\":true}");

    const char *result_json = NULL;
    size_t      result_len  = 0;
    int rc = fsql_search_ptr(g_ctx, corpus, n_rows, dim, query, dim,
                             (int) k, params, strlen(params),
                             &result_json, &result_len);
    if (rc != 0 || !result_json) {
        const char *err = fsql_last_error(g_ctx);
        ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR),
                        errmsg("fractalsql: telemetry search rc=%d: %s",
                               rc, err && *err ? err : "(no detail)")));
    }

    int    *idx  = palloc((Size) k * sizeof(int));
    double *dist = palloc((Size) k * sizeof(double));
    int n = fsql_extract_topk(result_json, k, idx, dist);
    if (n < 0)
        ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR),
                        errmsg("fractalsql: malformed top_k in search result")));

    for (int i = 0; i < n; i++) {
        Datum values[2];
        bool  nulls[2] = { false, false };
        int64 doc_id = doc_id_map ? doc_id_map[idx[i]] : (int64) idx[i];
        values[0] = Int64GetDatum(doc_id);
        values[1] = Float8GetDatum(dist[i]);
        tuplestore_putvalues(tupstore, tupdesc, values, nulls);
    }
    return (Datum) 0;
}

PG_FUNCTION_INFO_V1(fractal_search_telemetry);
Datum
fractal_search_telemetry(PG_FUNCTION_ARGS)
{
    if (PG_ARGISNULL(0) || PG_ARGISNULL(1) || PG_ARGISNULL(2) || PG_ARGISNULL(3))
        ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
                        errmsg("fractalsql: table_name, vector_col, query, "
                               "and k are required")));

    char      *table = text_to_cstring(PG_GETARG_TEXT_PP(0));
    char      *col   = text_to_cstring(PG_GETARG_TEXT_PP(1));
    ArrayType *qarr  = PG_GETARG_ARRAYTYPE_P(2);
    int32      k     = PG_GETARG_INT32(3);
    if (k <= 0)
        ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                        errmsg("fractalsql: k must be > 0")));

    int     dim;
    double *query = float8_array_to_doubles(qarr, &dim);

    ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
    MemoryContext  per_query_ctx = rsinfo->econtext->ecxt_per_query_memory;
    size_t  n_rows = 0;
    double *corpus = spi_scan_corpus(table, col, dim, per_query_ctx, &n_rows);

    return telemetry_topk_srf(fcinfo, corpus, n_rows, (size_t) dim, query, k, NULL);
}

PG_FUNCTION_INFO_V1(fractal_hybrid_clinical_search);
Datum
fractal_hybrid_clinical_search(PG_FUNCTION_ARGS)
{
    if (PG_ARGISNULL(0) || PG_ARGISNULL(1) || PG_ARGISNULL(2) ||
        PG_ARGISNULL(3) || PG_ARGISNULL(4))
        ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
                        errmsg("fractalsql: table_name, vector_col, query, "
                               "doc_ids, and k are required")));

    char      *table    = text_to_cstring(PG_GETARG_TEXT_PP(0));
    char      *col      = text_to_cstring(PG_GETARG_TEXT_PP(1));
    ArrayType *qarr      = PG_GETARG_ARRAYTYPE_P(2);
    ArrayType *ids_arr   = PG_GETARG_ARRAYTYPE_P(3);
    int32      k         = PG_GETARG_INT32(4);
    if (k <= 0)
        ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                        errmsg("fractalsql: k must be > 0")));

    int     dim;
    double *query = float8_array_to_doubles(qarr, &dim);

    if (ARR_NDIM(ids_arr) != 1 || ARR_HASNULL(ids_arr))
        ereport(ERROR, (errcode(ERRCODE_DATA_EXCEPTION),
                        errmsg("fractalsql: doc_ids must be a 1-D non-null int8[]")));
    if (ArrayGetNItems(ARR_NDIM(ids_arr), ARR_DIMS(ids_arr)) == 0)
        ereport(ERROR, (errcode(ERRCODE_DATA_EXCEPTION),
                        errmsg("fractalsql: doc_ids must be non-empty")));
    /* ids_arr is passed straight through to SPI_execute_with_args below
     * as a bound $1 parameter -- no manual deconstruction needed. */

    /* Cohort filter: SPI-scan only the allowlisted rows via a plain
     * parameterized IN-list query (identifiers quoted, values bound
     * via SPI_execute_with_args -- no string interpolation of caller
     * data at all). */
    ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
    MemoryContext  per_query_ctx = rsinfo->econtext->ecxt_per_query_memory;

    if (SPI_connect() != SPI_OK_CONNECT)
        ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR),
                        errmsg("fractalsql: SPI_connect failed")));

    /* row_number()-based ANY-match can't be a direct WHERE predicate
     * (window functions aren't allowed there) -- number the rows in a
     * CTE first, then filter. doc_id (rn) is 0-indexed, matching this
     * extension's existing result_handle/corpus-row-index convention. */
    StringInfoData q;
    initStringInfo(&q);
    appendStringInfo(&q,
        "WITH numbered AS (SELECT %s AS v, (row_number() OVER () - 1) AS rn FROM %s) "
        "SELECT v, rn FROM numbered WHERE rn = ANY($1) ORDER BY rn",
        quote_identifier(col), quote_identifier(table));

    Oid   argtypes[1] = { INT8ARRAYOID };
    Datum argvals[1]  = { PointerGetDatum(ids_arr) };
    int rc = SPI_execute_with_args(q.data, 1, argtypes, argvals, NULL,
                                   true, 0);
    if (rc != SPI_OK_SELECT) {
        SPI_finish();
        ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR),
                        errmsg("fractalsql: cohort scan of %s.%s failed (rc=%d)",
                               table, col, rc)));
    }

    uint64 n = SPI_processed;
    if (n == 0) {
        SPI_finish();
        ereport(ERROR, (errcode(ERRCODE_NO_DATA_FOUND),
                        errmsg("fractalsql: doc_ids cohort matched no rows in %s.%s",
                               table, col)));
    }

    /* doc_id_map[i] = the REAL table doc_id (rn) for cohort-scan
     * position i -- fsql_search_ptr's top_k indices are positions
     * within this filtered/reordered corpus, not real doc_ids, so
     * telemetry_topk_srf needs this to translate them back. */
    double *corpus     = (double *) MemoryContextAllocHuge(
                            per_query_ctx, (Size) n * dim * sizeof(double));
    int64  *doc_id_map = (int64 *) MemoryContextAlloc(
                            per_query_ctx, (Size) n * sizeof(int64));
    TupleDesc tupdesc = SPI_tuptable->tupdesc;
    /* Type-dispatch, same as spi_scan_corpus -- vector_col may be
     * float8[] or fractal_vector. This scan is custom (cohort-filtered
     * via row_number()+ANY($1), not a plain "SELECT col FROM table")
     * so it can't reuse spi_scan_corpus directly, but needs the exact
     * same detoast-then-cast + per-row pfree() handling for the
     * fractal_vector branch (see spi_scan_corpus's own comment for why:
     * packed varlenas don't honor ALIGNMENT=double, and unbounded
     * per-row detoast growth is a real risk at scale). */
    bool is_fvec = (SPI_gettypeid(tupdesc, 1) == fractal_vector_typeid());
    for (uint64 r = 0; r < n; r++) {
        bool  isnull;
        Datum d = SPI_getbinval(SPI_tuptable->vals[r], tupdesc, 1, &isnull);
        if (isnull) {
            SPI_finish();
            ereport(ERROR, (errcode(ERRCODE_DATA_EXCEPTION),
                            errmsg("fractalsql: NULL vector at cohort row %lu",
                                   (unsigned long) r)));
        }
        if (is_fvec) {
            FractalVector *fv = DatumGetFractalVectorP(d);
            if (fv->dim != dim) {
                SPI_finish();
                ereport(ERROR, (errcode(ERRCODE_DATA_EXCEPTION),
                                errmsg("fractalsql: %s.%s cohort row %lu has dim %d, "
                                       "expected %d (match the query)",
                                       table, col, (unsigned long) r, fv->dim, dim)));
            }
            double *dst = corpus + (Size) r * dim;
            for (int i = 0; i < dim; i++) dst[i] = (double) fv->x[i];
            if (PointerGetDatum(fv) != d) pfree(fv);
        } else {
            int     rdim;
            double *rv = float8_array_to_doubles(DatumGetArrayTypeP(d), &rdim);
            if (rdim != dim) {
                SPI_finish();
                ereport(ERROR, (errcode(ERRCODE_DATA_EXCEPTION),
                                errmsg("fractalsql: %s.%s cohort row %lu has dim %d, "
                                       "expected %d (match the query)",
                                       table, col, (unsigned long) r, rdim, dim)));
            }
            memcpy(corpus + (Size) r * dim, rv, (Size) dim * sizeof(double));
        }

        Datum rn_d = SPI_getbinval(SPI_tuptable->vals[r], tupdesc, 2, &isnull);
        if (isnull) {
            SPI_finish();
            ereport(ERROR, (errcode(ERRCODE_DATA_EXCEPTION),
                            errmsg("fractalsql: NULL rn at cohort row %lu",
                                   (unsigned long) r)));
        }
        doc_id_map[r] = DatumGetInt64(rn_d);
    }
    SPI_finish();

    return telemetry_topk_srf(fcinfo, corpus, (size_t) n, (size_t) dim, query, k,
                              doc_id_map);
}

PG_FUNCTION_INFO_V1(fractal_search_trajectory);
Datum
fractal_search_trajectory(PG_FUNCTION_ARGS)
{
    if (PG_ARGISNULL(0) || PG_ARGISNULL(1) || PG_ARGISNULL(2) ||
        PG_ARGISNULL(3) || PG_ARGISNULL(4))
        ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
                        errmsg("fractalsql: table_name, vector_col, "
                               "baseline_vector, current_vector, and k "
                               "are required")));

    char      *table    = text_to_cstring(PG_GETARG_TEXT_PP(0));
    char      *col      = text_to_cstring(PG_GETARG_TEXT_PP(1));
    ArrayType *base_arr = PG_GETARG_ARRAYTYPE_P(2);
    ArrayType *cur_arr  = PG_GETARG_ARRAYTYPE_P(3);
    int32      k        = PG_GETARG_INT32(4);
    if (k <= 0)
        ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                        errmsg("fractalsql: k must be > 0")));

    int     base_dim, cur_dim;
    double *baseline = float8_array_to_doubles(base_arr, &base_dim);
    double *current  = float8_array_to_doubles(cur_arr, &cur_dim);
    if (base_dim != cur_dim)
        ereport(ERROR, (errcode(ERRCODE_DATA_EXCEPTION),
                        errmsg("fractalsql: baseline_vector dim (%d) must match "
                               "current_vector dim (%d)", base_dim, cur_dim)));

    /* The delta vector (current - baseline) is what actually gets
     * searched -- "what has changed" rather than "where am I", the
     * natural query shape for drift/trajectory monitoring. */
    double *delta = palloc(base_dim * sizeof(double));
    for (int i = 0; i < base_dim; i++) delta[i] = current[i] - baseline[i];

    ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
    MemoryContext  per_query_ctx = rsinfo->econtext->ecxt_per_query_memory;
    size_t  n_rows = 0;
    double *corpus = spi_scan_corpus(table, col, base_dim, per_query_ctx, &n_rows);

    return telemetry_topk_srf(fcinfo, corpus, n_rows, (size_t) base_dim, delta, k, NULL);
}

PG_FUNCTION_INFO_V1(fractal_cross_modal_search);
Datum
fractal_cross_modal_search(PG_FUNCTION_ARGS)
{
    if (PG_ARGISNULL(0) || PG_ARGISNULL(1) || PG_ARGISNULL(2) ||
        PG_ARGISNULL(3) || PG_ARGISNULL(4) || PG_ARGISNULL(5))
        ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
                        errmsg("fractalsql: table_name, vector_col, "
                               "morphology_vector, clinical_vector, "
                               "alpha_weight, and k are required")));

    char      *table   = text_to_cstring(PG_GETARG_TEXT_PP(0));
    char      *col     = text_to_cstring(PG_GETARG_TEXT_PP(1));
    ArrayType *mo_arr   = PG_GETARG_ARRAYTYPE_P(2);
    ArrayType *cl_arr   = PG_GETARG_ARRAYTYPE_P(3);
    float8     alpha    = PG_GETARG_FLOAT8(4);
    int32      k        = PG_GETARG_INT32(5);
    if (k <= 0)
        ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                        errmsg("fractalsql: k must be > 0")));
    if (alpha < 0.0 || alpha > 1.0)
        ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                        errmsg("fractalsql: alpha_weight must be in [0,1]")));

    int     mo_dim, cl_dim;
    double *morph    = float8_array_to_doubles(mo_arr, &mo_dim);
    double *clinical = float8_array_to_doubles(cl_arr, &cl_dim);

    /* Weighted concatenation, not a blend -- the two modalities keep
     * their own dimensions (dim = mo_dim + cl_dim), scaled by
     * alpha/(1-alpha) before concatenation so cosine distance in the
     * combined space reflects the requested weighting. The corpus
     * table's vector_col must already be stored in this same combined
     * shape (upstream ETL concern, not something this function can
     * validate beyond a dimension-count match against the table). */
    int combined_dim = mo_dim + cl_dim;
    double *combined = palloc((Size) combined_dim * sizeof(double));
    for (int i = 0; i < mo_dim; i++) combined[i] = morph[i] * alpha;
    for (int i = 0; i < cl_dim; i++) combined[mo_dim + i] = clinical[i] * (1.0 - alpha);

    ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
    MemoryContext  per_query_ctx = rsinfo->econtext->ecxt_per_query_memory;
    size_t  n_rows = 0;
    double *corpus = spi_scan_corpus(table, col, combined_dim, per_query_ctx, &n_rows);

    return telemetry_topk_srf(fcinfo, corpus, n_rows, (size_t) combined_dim, combined, k, NULL);
}

/* fractal_vector overloads of the two functions above. Arithmetic
 * (sub / weighted-concat) runs in core's float32 fsql_vector_* module
 * against the varlenas' payload directly -- no float8[] unpack/repack
 * -- then widens to double ONCE at this boundary, immediately before
 * the same spi_scan_corpus/telemetry_topk_srf call the float8[]
 * versions use. HNSW/SFS internals never see a float. */

PG_FUNCTION_INFO_V1(fractal_search_trajectory_fv);
Datum
fractal_search_trajectory_fv(PG_FUNCTION_ARGS)
{
    if (PG_ARGISNULL(0) || PG_ARGISNULL(1) || PG_ARGISNULL(2) ||
        PG_ARGISNULL(3) || PG_ARGISNULL(4))
        ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
                        errmsg("fractalsql: table_name, vector_col, "
                               "baseline_vector, current_vector, and k "
                               "are required")));

    char           *table = text_to_cstring(PG_GETARG_TEXT_PP(0));
    char           *col   = text_to_cstring(PG_GETARG_TEXT_PP(1));
    FractalVector  *base  = PG_GETARG_FRACTALVEC_P(2);
    FractalVector  *cur   = PG_GETARG_FRACTALVEC_P(3);
    int32           k     = PG_GETARG_INT32(4);
    if (k <= 0)
        ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                        errmsg("fractalsql: k must be > 0")));
    if (base->dim != cur->dim)
        ereport(ERROR, (errcode(ERRCODE_DATA_EXCEPTION),
                        errmsg("fractalsql: baseline_vector dim (%d) must match "
                               "current_vector dim (%d)", base->dim, cur->dim)));

    int    dim    = base->dim;
    float4 *delta_f = (float4 *) palloc(dim * sizeof(float4));
    fsql_vector_sub(cur->x, base->x, (size_t) dim, delta_f);

    double *delta = (double *) palloc(dim * sizeof(double));
    for (int i = 0; i < dim; i++) delta[i] = (double) delta_f[i];

    ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
    MemoryContext  per_query_ctx = rsinfo->econtext->ecxt_per_query_memory;
    size_t  n_rows = 0;
    double *corpus = spi_scan_corpus(table, col, dim, per_query_ctx, &n_rows);

    return telemetry_topk_srf(fcinfo, corpus, n_rows, (size_t) dim, delta, k, NULL);
}

PG_FUNCTION_INFO_V1(fractal_cross_modal_search_fv);
Datum
fractal_cross_modal_search_fv(PG_FUNCTION_ARGS)
{
    if (PG_ARGISNULL(0) || PG_ARGISNULL(1) || PG_ARGISNULL(2) ||
        PG_ARGISNULL(3) || PG_ARGISNULL(4) || PG_ARGISNULL(5))
        ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
                        errmsg("fractalsql: table_name, vector_col, "
                               "morphology_vector, clinical_vector, "
                               "alpha_weight, and k are required")));

    char          *table    = text_to_cstring(PG_GETARG_TEXT_PP(0));
    char          *col      = text_to_cstring(PG_GETARG_TEXT_PP(1));
    FractalVector *morph    = PG_GETARG_FRACTALVEC_P(2);
    FractalVector *clinical = PG_GETARG_FRACTALVEC_P(3);
    float8         alpha    = PG_GETARG_FLOAT8(4);
    int32          k        = PG_GETARG_INT32(5);
    if (k <= 0)
        ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                        errmsg("fractalsql: k must be > 0")));
    if (alpha < 0.0 || alpha > 1.0)
        ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                        errmsg("fractalsql: alpha_weight must be in [0,1]")));

    int combined_dim = morph->dim + clinical->dim;
    float4 *combined_f = (float4 *) palloc((Size) combined_dim * sizeof(float4));
    fsql_vector_weighted_concat(morph->x, (size_t) morph->dim, (float4) alpha,
                                clinical->x, (size_t) clinical->dim, (float4) (1.0 - alpha),
                                combined_f);

    double *combined = (double *) palloc((Size) combined_dim * sizeof(double));
    for (int i = 0; i < combined_dim; i++) combined[i] = (double) combined_f[i];

    ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
    MemoryContext  per_query_ctx = rsinfo->econtext->ecxt_per_query_memory;
    size_t  n_rows = 0;
    double *corpus = spi_scan_corpus(table, col, combined_dim, per_query_ctx, &n_rows);

    return telemetry_topk_srf(fcinfo, corpus, n_rows, (size_t) combined_dim, combined, k, NULL);
}

/* ------------------------------------------------------------------ */
/* Edition + version metadata                                         */
/* ------------------------------------------------------------------ */

PG_FUNCTION_INFO_V1(fractal_edition);
Datum
fractal_edition(PG_FUNCTION_ARGS)
{
    PG_RETURN_TEXT_P(cstring_to_text(FSQL_EDITION));
}

PG_FUNCTION_INFO_V1(fractal_version);
Datum
fractal_version(PG_FUNCTION_ARGS)
{
    PG_RETURN_TEXT_P(cstring_to_text(FSQL_VERSION));
}

/* ------------------------------------------------------------------ */
/* Enterprise: QTL ledger + CISO audit (runtime-gated)                 */
/* ------------------------------------------------------------------ */
/* Each wrapper ensures the search ctx (which carries the Postgres-backed
 * storage VFS the ledger persists through) then the enterprise library.
 * If the library is not loaded the function raises a clear "enterprise
 * tier not loaded" error. The symbols are dlsym'd from the enterprise
 * core library, never referenced from the community archive (which does
 * not compile them on a clean build). */

PG_FUNCTION_INFO_V1(fractal_ledger_flush);
Datum
fractal_ledger_flush(PG_FUNCTION_ARGS)
{
    ensure_search_ctx();
    if (!ensure_enterprise_lib())
        enterprise_not_loaded_error();
    int rc = g_ent_ledger_flush(g_ctx);
    if (rc != FSQL_OK)
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("fractalsql: fsql_ledger_flush rc=%d: %s",
                        rc, fsql_last_error(g_ctx))));
    PG_RETURN_VOID();
}

PG_FUNCTION_INFO_V1(fractal_ledger_load);

/*
 * O(1) load-time check (storage seam). Before the enterprise core
 * decodes the persisted blob, verify only the LATEST row for this kind:
 * its entry_hash recomputes correctly from its own blob/mac (structural
 * integrity, unconditional -- no key required), and its prev_hash matches
 * the entry_hash of the row immediately before it (the chain link to the
 * rest of history is intact). If a ledger key is configured, the MAC is
 * also verified. This is intentionally O(1), NOT a full chain walk: it
 * catches "the current blob was tampered" plus "the row right before
 * this one was rewritten or deleted," but not tampering further back
 * in history -- that is
 * fractal_ledger_verify()'s job (O(n), on demand, not run on every load).
 * Runs entirely in the open extension -- the core is never handed
 * tampered bytes. No row yet => empty start; the core load returns
 * ESTORAGE_UNAVAILABLE and the wrapper treats that as OK.
 * ERRCODE_INTERNAL_ERROR is used for every rejection so callers can catch
 * it as PL/pgSQL `internal_error` (mirroring the core's
 * FSQL_ELEDGER_INTEGRITY surfacing).
 */
static void
ledger_verify_latest(void)
{
    if (SPI_connect() != SPI_OK_CONNECT)
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("fractalsql: ledger verify: SPI_connect failed")));
    if (!ledger_ensure_table())
    {
        SPI_finish();
        return;                         /* no table => empty ledger, let core decide */
    }

    Oid   argtypes[1] = { INT4OID };
    Datum values[1]    = { Int32GetDatum(1) };     /* the ledger's kind = 1 stream */
    char  nulls[1]     = { ' ' };

    int rc = SPI_execute_with_args(
        "SELECT blob, mac, prev_hash, entry_hash FROM fractalsql_ledger "
        "WHERE kind = $1 ORDER BY id DESC LIMIT 2",
        1, argtypes, values, nulls, true, 2);
    if (rc != SPI_OK_SELECT)
    {
        SPI_finish();
        return;                         /* read error -- the core load surfaces it */
    }
    if (SPI_processed == 0)
    {
        SPI_finish();
        return;                         /* no persisted blob yet -- empty start */
    }

    bool  blob_isnull, mac_isnull, prev_isnull, hash_isnull;
    Datum blob_d = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &blob_isnull);
    Datum mac_d  = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 2, &mac_isnull);
    Datum prev_d = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 3, &prev_isnull);
    Datum hash_d = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 4, &hash_isnull);
    if (blob_isnull || prev_isnull || hash_isnull)
    {
        SPI_finish();
        return;                         /* defensive -- core handles a null blob */
    }

    const char *key = g_enterprise_ledger_key;
    bool require_mac = (key && key[0] != '\0');

    if (require_mac && mac_isnull)
    {
        SPI_finish();
        /* A key is configured but the persisted blob predates it (no tag).
         * Refuse rather than silently trusting an unauthenticated blob. */
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("fractalsql: ledger MAC verification failed -- "
                        "the persisted blob has no MAC (it was written before "
                        "fractalsql.enterprise_ledger_key was set)"),
                 errhint("Re-flush the ledger (fractal_ledger_flush) with the "
                         "key configured to authenticate it, or unset "
                         "fractalsql.enterprise_ledger_key for structural-only "
                         "validation.")));
    }

    /* Copy out of SPI's context (reset on SPI_finish) into the caller's
     * context, the same pattern as ledger_read_entry above. */
    bytea         *blob = DatumGetByteaPCopy(blob_d);
    size_t         blob_len  = VARSIZE(blob) - VARHDRSZ;
    const uint8_t *blob_data = (const uint8_t *) VARDATA(blob);

    bytea *prev = DatumGetByteaPCopy(prev_d);
    bytea *hash = DatumGetByteaPCopy(hash_d);
    if (VARSIZE(prev) - VARHDRSZ != 32 || VARSIZE(hash) - VARHDRSZ != 32)
    {
        SPI_finish();
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("fractalsql: ledger chain verification failed -- "
                        "stored prev_hash/entry_hash is not 32 bytes"),
                 errhint("The persisted row is corrupt or was written by an "
                         "incompatible version. Re-flush to start a fresh "
                         "chain.")));
    }

    uint8_t mac_bytes[32];
    bool    have_mac = !mac_isnull;
    if (have_mac)
    {
        bytea *mac = DatumGetByteaPCopy(mac_d);
        if (VARSIZE(mac) - VARHDRSZ != 32)
        {
            SPI_finish();
            ereport(ERROR,
                    (errcode(ERRCODE_INTERNAL_ERROR),
                     errmsg("fractalsql: ledger MAC verification failed -- "
                            "stored MAC is %zu bytes, expected 32",
                            (size_t) (VARSIZE(mac) - VARHDRSZ)),
                     errhint("The persisted blob is tampered or was written by "
                             "an incompatible version. Re-flush to re-tag it.")));
        }
        memcpy(mac_bytes, VARDATA(mac), 32);

        if (require_mac)
        {
            uint8_t tag[32];
            fsql_hmac_sha256((const uint8_t *) key, strlen(key),
                             blob_data, blob_len, tag);
            if (memcmp(tag, mac_bytes, 32) != 0)
            {
                SPI_finish();
                ereport(ERROR,
                        (errcode(ERRCODE_INTERNAL_ERROR),
                         errmsg("fractalsql: ledger MAC verification failed -- "
                                "the persisted QTL blob is tampered (HMAC mismatch)"),
                         errhint("A byte in the blob changed after it was tagged, "
                                 "or the blob was re-encoded/replaced without the "
                                 "key. Set fractalsql.enterprise_ledger_key to the "
                                 "key used at flush, or re-flush to re-tag it.")));
            }
        }
    }

    /* Structural chain check -- unconditional, no key required: recompute
     * entry_hash = SHA256(prev_hash || blob || mac) and compare to the
     * stored value. Catches a byte-flip in blob or mac that the (optional)
     * HMAC check above cannot -- including when no key is configured at
     * all. */
    uint8_t recomputed[32];
    {
        size_t   buflen = 32 + blob_len + (have_mac ? 32 : 0);
        uint8_t *buf    = (uint8_t *) palloc(buflen);
        memcpy(buf, VARDATA(prev), 32);
        memcpy(buf + 32, blob_data, blob_len);
        if (have_mac) memcpy(buf + 32 + blob_len, mac_bytes, 32);
        fsql_sha256(buf, buflen, recomputed);
        pfree(buf);
    }
    if (memcmp(recomputed, VARDATA(hash), 32) != 0)
    {
        SPI_finish();
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("fractalsql: ledger chain verification failed -- "
                        "the latest entry's hash does not match its stored "
                        "blob/mac (structural tamper, independent of any MAC "
                        "key)"),
                 errhint("Run fractal_ledger_verify() to locate exactly where "
                         "the chain diverges, or re-flush to start a fresh "
                         "chain.")));
    }

    /* Chain-link check: the latest row's prev_hash must equal the
     * entry_hash of the row immediately before it -- otherwise a row was
     * rewritten, reordered, or (with the prior row now missing entirely)
     * deleted between them. A single-row ledger (genesis) instead checks
     * prev_hash is the all-zero sentinel. */
    if (SPI_processed >= 2)
    {
        bool  prior_isnull;
        Datum prior_hash_d = SPI_getbinval(SPI_tuptable->vals[1],
                                           SPI_tuptable->tupdesc, 4, &prior_isnull);
        bytea *prior_hash = prior_isnull ? NULL : DatumGetByteaPCopy(prior_hash_d);
        if (prior_hash == NULL || VARSIZE(prior_hash) - VARHDRSZ != 32 ||
            memcmp(VARDATA(prev), VARDATA(prior_hash), 32) != 0)
        {
            SPI_finish();
            ereport(ERROR,
                    (errcode(ERRCODE_INTERNAL_ERROR),
                     errmsg("fractalsql: ledger chain verification failed -- "
                            "the latest entry's prev_hash does not match its "
                            "predecessor's entry_hash (a row was rewritten, "
                            "reordered, or deleted)"),
                     errhint("Run fractal_ledger_verify() to locate exactly "
                             "where the chain diverges.")));
        }
    }
    else
    {
        uint8_t zero[32];
        memset(zero, 0, 32);
        if (memcmp(VARDATA(prev), zero, 32) != 0)
        {
            SPI_finish();
            ereport(ERROR,
                    (errcode(ERRCODE_INTERNAL_ERROR),
                     errmsg("fractalsql: ledger chain verification failed -- "
                            "the sole entry's prev_hash is not the genesis "
                            "sentinel (an earlier row was deleted)")));
        }
    }

    SPI_finish();
    /* Chain verified -- fall through to the core load, which decodes the
     * now-authenticated blob. */
}

Datum
fractal_ledger_load(PG_FUNCTION_ARGS)
{
    ensure_search_ctx();
    if (!ensure_enterprise_lib())
        enterprise_not_loaded_error();
    ledger_verify_latest();              /* authenticate the chain tip before decode */
    int rc = g_ent_ledger_load(g_ctx);
    /* FSQL_ESTORAGE_UNAVAILABLE (no persisted ledger yet) is NOT an error:
     * the ledger simply starts empty. */
    if (rc != FSQL_OK && rc != FSQL_ESTORAGE_UNAVAILABLE)
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("fractalsql: fsql_ledger_load rc=%d: %s",
                        rc, fsql_last_error(g_ctx))));
    PG_RETURN_VOID();
}

PG_FUNCTION_INFO_V1(fractal_ledger_compact);
Datum
fractal_ledger_compact(PG_FUNCTION_ARGS)
{
    ensure_search_ctx();
    if (!ensure_enterprise_lib())
        enterprise_not_loaded_error();
    int rc = g_ent_ledger_compact(g_ctx);
    if (rc != FSQL_OK)
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("fractalsql: fsql_ledger_compact rc=%d: %s",
                        rc, fsql_last_error(g_ctx))));
    PG_RETURN_VOID();
}

PG_FUNCTION_INFO_V1(fractal_ledger_reset_soft);
Datum
fractal_ledger_reset_soft(PG_FUNCTION_ARGS)
{
    ensure_search_ctx();
    if (!ensure_enterprise_lib())
        enterprise_not_loaded_error();
    int rc = g_ent_ledger_reset_soft(g_ctx);
    if (rc != FSQL_OK)
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("fractalsql: fsql_ledger_reset_soft rc=%d: %s",
                        rc, fsql_last_error(g_ctx))));
    PG_RETURN_VOID();
}

PG_FUNCTION_INFO_V1(fractal_ledger_reset_hard);
Datum
fractal_ledger_reset_hard(PG_FUNCTION_ARGS)
{
    ensure_search_ctx();
    if (!ensure_enterprise_lib())
        enterprise_not_loaded_error();
    int rc = g_ent_ledger_reset_hard(g_ctx);
    if (rc != FSQL_OK)
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("fractalsql: fsql_ledger_reset_hard rc=%d: %s",
                        rc, fsql_last_error(g_ctx))));
    PG_RETURN_VOID();
}

PG_FUNCTION_INFO_V1(fractal_ledger_truth_count);
Datum
fractal_ledger_truth_count(PG_FUNCTION_ARGS)
{
    ensure_search_ctx();
    if (!ensure_enterprise_lib())
        enterprise_not_loaded_error();
    size_t n = 0;
    int rc = g_ent_ledger_truth_count(g_ctx, &n);
    if (rc != FSQL_OK)
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("fractalsql: fsql_ledger_truth_count rc=%d: %s",
                        rc, fsql_last_error(g_ctx))));
    PG_RETURN_INT64((int64) n);
}

PG_FUNCTION_INFO_V1(fractal_ledger_shadow_count);
Datum
fractal_ledger_shadow_count(PG_FUNCTION_ARGS)
{
    ensure_search_ctx();
    if (!ensure_enterprise_lib())
        enterprise_not_loaded_error();
    size_t n = 0;
    int rc = g_ent_ledger_shadow_count(g_ctx, &n);
    if (rc != FSQL_OK)
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("fractalsql: fsql_ledger_shadow_count rc=%d: %s",
                        rc, fsql_last_error(g_ctx))));
    PG_RETURN_INT64((int64) n);
}

/*
 * Full-chain audit (storage seam, O(n)). Unlike ledger_verify_latest
 * (called on every fractal_ledger_load, O(1), tip-only), this walks the
 * ENTIRE persisted chain for kind=1: every entry_hash recomputes from its
 * own (prev_hash, blob, mac), every prev_hash matches its predecessor's
 * entry_hash, and the id sequence has no gaps (a gap means a row was
 * deleted). It is a pure read-only forensic query -- does not touch
 * g_ctx or the enterprise core (no ensure_search_ctx/ensure_enterprise_lib),
 * so it works even when the enterprise library isn't currently loaded, and
 * it returns a structured jsonb report rather than raising, since a CISO
 * running this wants a diagnosis, not a thrown exception.
 */
PG_FUNCTION_INFO_V1(fractal_ledger_verify);
Datum
fractal_ledger_verify(PG_FUNCTION_ARGS)
{
    bool        empty       = false;
    bool        failed      = false;
    int64       fail_id     = 0;
    const char *fail_reason = NULL;
    uint64      n           = 0;
    int32       kind        = PG_ARGISNULL(0) ? 1 : PG_GETARG_INT32(0);

    if (SPI_connect() != SPI_OK_CONNECT)
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("fractalsql: fractal_ledger_verify: SPI_connect failed")));

    if (!ledger_ensure_table())
    {
        SPI_finish();
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("fractalsql: fractal_ledger_verify: could not access "
                        "fractalsql_ledger")));
    }

    Oid   argtypes[1] = { INT4OID };
    Datum values[1]    = { Int32GetDatum(kind) };
    char  nulls[1]     = { ' ' };

    int rc = SPI_execute_with_args(
        "SELECT id, blob, mac, prev_hash, entry_hash FROM fractalsql_ledger "
        "WHERE kind = $1 ORDER BY id ASC",
        1, argtypes, values, nulls, true, 0);
    if (rc != SPI_OK_SELECT)
    {
        SPI_finish();
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("fractalsql: fractal_ledger_verify: read failed")));
    }

    n = SPI_processed;
    if (n == 0)
        empty = true;
    else
    {
        uint8_t expect_prev[32];
        int64   expect_id = -1;
        memset(expect_prev, 0, 32);

        for (uint64 i = 0; i < n; i++)
        {
            bool  isnull;
            Datum id_d   = SPI_getbinval(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 1, &isnull);
            int64 row_id = isnull ? -1 : DatumGetInt64(id_d);

            Datum blob_d = SPI_getbinval(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 2, &isnull);
            bool  blob_isnull = isnull;
            Datum mac_d  = SPI_getbinval(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 3, &isnull);
            bool  mac_isnull = isnull;
            Datum prev_d = SPI_getbinval(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 4, &isnull);
            bool  prev_isnull = isnull;
            Datum hash_d = SPI_getbinval(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 5, &isnull);
            bool  hash_isnull = isnull;

            if (blob_isnull || prev_isnull || hash_isnull)
            {
                failed = true; fail_id = row_id;
                fail_reason = "malformed row (unexpected NULL)";
                break;
            }

            bytea *blob = DatumGetByteaPCopy(blob_d);
            bytea *prev = DatumGetByteaPCopy(prev_d);
            bytea *hash = DatumGetByteaPCopy(hash_d);
            bytea *mac  = mac_isnull ? NULL : DatumGetByteaPCopy(mac_d);

            if (VARSIZE(prev) - VARHDRSZ != 32 || VARSIZE(hash) - VARHDRSZ != 32 ||
                (mac != NULL && VARSIZE(mac) - VARHDRSZ != 32))
            {
                failed = true; fail_id = row_id;
                fail_reason = "malformed row (bad hash/mac length)";
                break;
            }

            /* Sequence-gap check: after the first row, every id must be
             * exactly one more than the previous -- a gap means a row was
             * deleted, visible even though we never saw the missing row. */
            if (expect_id >= 0 && row_id != expect_id)
            {
                failed = true; fail_id = row_id;
                fail_reason = "sequence gap (a row was deleted)";
                break;
            }

            /* Chain-link check: this row's prev_hash must equal the
             * previous row's entry_hash (all-zero sentinel for the first
             * row). */
            if (memcmp(VARDATA(prev), expect_prev, 32) != 0)
            {
                failed = true; fail_id = row_id;
                fail_reason = "chain-link break (prev_hash mismatch)";
                break;
            }

            /* Structural check: entry_hash must recompute from this row's
             * own (prev_hash, blob, mac). */
            size_t   blob_len = VARSIZE(blob) - VARHDRSZ;
            size_t   buflen   = 32 + blob_len + (mac ? 32 : 0);
            uint8_t *buf      = (uint8_t *) palloc(buflen);
            memcpy(buf, expect_prev, 32);
            memcpy(buf + 32, VARDATA(blob), blob_len);
            if (mac) memcpy(buf + 32 + blob_len, VARDATA(mac), 32);
            uint8_t recomputed[32];
            fsql_sha256(buf, buflen, recomputed);
            pfree(buf);

            if (memcmp(recomputed, VARDATA(hash), 32) != 0)
            {
                failed = true; fail_id = row_id;
                fail_reason = "entry_hash mismatch (blob or mac tampered)";
                break;
            }

            memcpy(expect_prev, VARDATA(hash), 32);
            expect_id = row_id + 1;
        }
    }

    SPI_finish();

    /* Build the report entirely OUTSIDE the SPI-managed span: everything
     * tracked above is a plain C scalar or a string literal, never a
     * palloc'd pointer, so there is nothing here SPI_finish() could have
     * invalidated. */
    StringInfoData json;
    initStringInfo(&json);
    if (empty)
        appendStringInfoString(&json, "{\"ok\": true, \"rows_verified\": 0}");
    else if (failed)
        appendStringInfo(&json,
            "{\"ok\": false, \"first_failure_id\": %lld, \"reason\": \"%s\"}",
            (long long) fail_id, fail_reason);
    else
        appendStringInfo(&json,
            "{\"ok\": true, \"rows_verified\": %llu}", (unsigned long long) n);

    PG_RETURN_DATUM(DirectFunctionCall1(jsonb_in, CStringGetDatum(json.data)));
}

/* General decision-audit chain: kind=2 in fractalsql_ledger, a second
 * independent chain alongside kind=1's QTL Truth/Shadow blobs, same
 * ledger_write_entry/fractal_ledger_verify(2) machinery. For provenance
 * records (text_to_sql, portfolio decisions, agent decisions) -- not
 * QTL-encoded, just JSON: {"type": entry_type, "entry": payload}. Query
 * back directly: SELECT id, updated, convert_from(blob,'UTF8')::jsonb
 * FROM fractalsql_ledger WHERE kind = 2 ORDER BY id. */
PG_FUNCTION_INFO_V1(fractal_audit_log);
Datum
fractal_audit_log(PG_FUNCTION_ARGS)
{
    ensure_search_ctx();
    if (!ensure_enterprise_lib())
        enterprise_not_loaded_error();

    char  *type_str    = text_to_cstring(PG_GETARG_TEXT_PP(0));
    Jsonb *payload      = PG_GETARG_JSONB_P(1);
    char  *payload_str = DatumGetCString(DirectFunctionCall1(jsonb_out, JsonbPGetDatum(payload)));

    StringInfoData js;
    initStringInfo(&js);
    appendStringInfoString(&js, "{\"type\":");
    escape_json(&js, type_str);
    appendStringInfoString(&js, ",\"entry\":");
    appendStringInfoString(&js, payload_str);
    appendStringInfoChar(&js, '}');

    int rc = ledger_write_entry(NULL, 2, js.data, js.len);
    if (rc != FSQL_OK)
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("fractalsql: fractal_audit_log: write failed rc=%d", rc)));
    PG_RETURN_VOID();
}

PG_FUNCTION_INFO_V1(fractal_audit_unpack);
Datum
fractal_audit_unpack(PG_FUNCTION_ARGS)
{
    bytea *blob = PG_GETARG_BYTEA_PP(0);
    size_t      blob_len  = VARSIZE_ANY_EXHDR(blob);
    const void *blob_data = VARDATA_ANY(blob);

    /* audit_unpack is a pure decode of a QTL blob -- it does not touch
     * g_ctx, so no ensure_search_ctx(). It only needs the enterprise lib. */
    if (!ensure_enterprise_lib())
        enterprise_not_loaded_error();

    size_t cap = 8192;
    char  *buf;
    int    rc;
    for (;;)
    {
        buf = palloc(cap);
        size_t need = cap;
        rc = g_ent_audit_unpack(blob_data, blob_len, buf, &need);
        if (rc == FSQL_OK)
            break;
        pfree(buf);
        if (rc == FSQL_ETRUNCATED)
        {
            /* The engine reports the required capacity in *json_cap. */
            cap = (need > cap) ? need : (cap * 2);
            continue;
        }
        ereport(ERROR,
                (errcode(ERRCODE_INTERNAL_ERROR),
                 errmsg("fractalsql: fsql_audit_unpack rc=%d", rc)));
    }

    /* Parse the JSON array the engine produced into jsonb for
     * queryability (the CISO audit view is a JSON array of
     * {"epoch","doc_id","signal"} entries; [] for an empty ledger). */
    PG_RETURN_DATUM(DirectFunctionCall1(jsonb_in, CStringGetDatum(buf)));
}
