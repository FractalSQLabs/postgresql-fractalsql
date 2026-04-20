# FractalSQL — PostgreSQL extension build
#
# The LuaJIT optimizer core ships as pre-compiled stripped bytecode
# (include/sfs_core_bc.h). No Lua parser is invoked at build time or at
# runtime. If a Lua source happens to be present in lua/, the Makefile
# will rebuild the bytecode from it; otherwise the shipped header is
# used as-is.
#
# Build: make
# Ship:  sudo make install && psql -c 'CREATE EXTENSION fractalsql;'

MODULE_big = fractalsql
EXTENSION  = fractalsql
DATA       = sql/fractalsql--1.0.sql
PGFILEDESC = "fractalsql - Stochastic Fractal Search via LuaJIT"

OBJS = src/fractalsql.o

# --- LuaJIT discovery -------------------------------------------------------
LUAJIT         ?= luajit
LUAJIT_CFLAGS  := $(shell pkg-config --cflags luajit 2>/dev/null)
LUAJIT_LIBS    := $(shell pkg-config --libs   luajit 2>/dev/null)

ifeq ($(strip $(LUAJIT_CFLAGS)),)
  $(warning pkg-config for luajit failed; using default /usr paths)
  LUAJIT_CFLAGS := -I/usr/include/luajit-2.1
  LUAJIT_LIBS   := -lluajit-5.1
endif

PG_CPPFLAGS = $(LUAJIT_CFLAGS) -Iinclude
SHLIB_LINK  = $(LUAJIT_LIBS)

# --- PGXS -------------------------------------------------------------------
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

# --- Bytecode (re)generation ------------------------------------------------
#
# If a Lua source is present under lua/, (re)generate the bytecode
# header from it. In a bytecode-only checkout the rule is inert and
# the shipped include/sfs_core_bc.h is used directly.
#
# luajit -b  — bytecode output mode
#        -s  — strip debug info (line numbers, local names, chunk name)
#        -n  — embedded symbol name -> luaJIT_BC_sfs_core
ifneq ($(wildcard lua/sfs_core.lua),)
  include/sfs_core_bc.h: lua/sfs_core.lua
	$(LUAJIT) -b -s -n sfs_core $< $@
  EXTRA_CLEAN = include/sfs_core_bc.h
endif

# The C source depends on the header. When the header is shipped,
# make uses the existing file. When a Lua source is present, the
# rule above regenerates it on source change.
src/fractalsql.o: include/sfs_core_bc.h

# --- Benchmark -------------------------------------------------------------
#
# `make bench` runs the HNSW-vs-Scout-Mode head-to-head at demo scale
# (dim=128, 100k vectors; completes in ~2 minutes end-to-end).
#
# `make bench-full` runs the same benchmark at dim=768. HNSW index build
# at this scale takes 10-20 minutes; see bench/README.md.
#
# Both targets assume the extension is installed in a local PG and that
# Python deps from bench/requirements.txt are available.
PYTHON ?= python3

.PHONY: bench bench-full bench-data bench-run

bench: bench-data bench-run

bench-data:
	$(PYTHON) bench/data_gen.py

bench-run:
	$(PYTHON) bench/head_to_head.py

bench-full:
	$(PYTHON) bench/data_gen.py --dim 768
	$(PYTHON) bench/head_to_head.py
