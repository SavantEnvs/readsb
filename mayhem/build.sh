#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# readsb is one daemon binary (plain GNU Makefile, objects written in-tree). The fuzz build compiles
# the same object list as upstream's `readsb:` rule, with upstream's defines, into mayhem/build/fuzz
# (gitignored), so it never collides with the oracle build in step 3.
#
# Engine: AFL (afl-clang-fast, Mayhemfile `afl: true`). readsb is a multi-threaded daemon with global
# state and static protocol readers, so every input runs in its own process: an AFL target is its own
# reproducer (no -standalone), and the project itself is instrumented, not just the driver.
OBJS="readsb argp anet interactive mode_ac mode_s comm_b json_out net_io crc demod_2400
      uat2esnt/uat2esnt uat2esnt/uat_decode stats cpr icao_filter track util fasthash convert
      sdr_ifile sdr_beast sdr ais_charset globe_index geomag receiver aircraft api threadpool"
VER="$(cat "$SRC/version")"
DEFS=(-std=c11 -fno-common -D_GNU_SOURCE -D_DEFAULT_SOURCE -DDISABLE_INTERACTIVE
      "-DMODES_READSB_VERSION=\"$VER mayhem\"" "-DREADSB_SHORT_VERSION=\"$VER\""
      "-DREADSB_SHORT_COMMIT=\"mayhem\"" -Wno-format-truncation)
LIBS=(-pthread -lm -lrt -lzstd -lz)

# build_tree <outdir> <cc> <cflags...>: compile every readsb object, plus readsb.c again with its
# main() renamed to readsb_main for the network driver.
build_tree() {
  local out="$1" cc="$2"; shift 2
  mkdir -p "$out/uat2esnt"
  local pids=() o
  for o in $OBJS; do
    "$cc" "${DEFS[@]}" "$@" ${FILE_FLAGS[$o]:-} -c "$SRC/$o.c" -o "$out/$o.o" & pids+=($!)
    if [ "${#pids[@]}" -ge "$MAYHEM_JOBS" ]; then wait "${pids[0]}"; pids=("${pids[@]:1}"); fi
  done
  "$cc" "${DEFS[@]}" "$@" -Dmain=readsb_main -c "$SRC/readsb.c" -o "$out/readsb_main.o" & pids+=($!)
  for o in "${pids[@]}"; do wait "$o"; done
}
lib_objs() { local o; for o in $OBJS; do [ "$o" = readsb ] || echo "$1/$o.o"; done; }

# Per-file UBSan relaxation (docs/rules/c.md): demod_2400.c tests `valid_df_*_bitset & (1 << df)`
# with df up to 31, a signed `1 << 31` that UBSan's shift-base check reports on practically every IQ
# input, which would make the ifile target abort before demodulating anything. Only shift-base, only
# on that file; ASan and the rest of UBSan stay halting.
declare -A FILE_FLAGS=([demod_2400]="")

# 1+2) Sanitized, AFL-instrumented build of the project + the network driver.
F="$SRC/mayhem/build/fuzz"
FUZZ_CFLAGS=(-O1 $SANITIZER_FLAGS $DEBUG_FLAGS)
[ -z "$SANITIZER_FLAGS" ] || FILE_FLAGS[demod_2400]="-fno-sanitize=shift-base"
build_tree "$F" afl-clang-fast "${FUZZ_CFLAGS[@]}"
FILE_FLAGS[demod_2400]=""
afl-clang-fast++ $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$F/lsan_off.o"
afl-clang-fast "${DEFS[@]}" "${FUZZ_CFLAGS[@]}" -c "$SRC/mayhem/readsb_netfuzz.c" -o "$F/readsb_netfuzz.o"
# readsb itself (file input: --device-type ifile)
afl-clang-fast "${FUZZ_CFLAGS[@]}" "$F/readsb.o" $(lib_objs "$F") "$F/lsan_off.o" "${LIBS[@]}" \
  -o "$SRC/readsb-fuzz"
# readsb driven through its own network input services
afl-clang-fast "${FUZZ_CFLAGS[@]}" "$F/readsb_netfuzz.o" "$F/readsb_main.o" $(lib_objs "$F") \
  "$F/lsan_off.o" "${LIBS[@]}" -o "$SRC/readsb-netfuzz"

# 3) Oracle build with the project's NORMAL flags: upstream's own unit tests (make cprtests crctests,
#    in-tree, gitignored) and the same driver around an unsanitized readsb for the decode tests.
make -C "$SRC" -j"$MAYHEM_JOBS" cprtests crctests CC="$CC" OPTIMIZE="$COVERAGE_FLAGS"
T="$SRC/mayhem/build/oracle"
build_tree "$T" "$CC" -W -Wall -O2 -g $COVERAGE_FLAGS
"$CC" "${DEFS[@]}" -O2 -g $COVERAGE_FLAGS -c "$SRC/mayhem/readsb_netfuzz.c" -o "$T/readsb_netfuzz.o"
"$CC" -O2 -g $COVERAGE_FLAGS "$T/readsb_netfuzz.o" "$T/readsb_main.o" $(lib_objs "$T") "${LIBS[@]}" \
  -o "$T/readsb-nettest"
"$CC" -O2 -g $COVERAGE_FLAGS "$T/readsb.o" $(lib_objs "$T") "${LIBS[@]}" -o "$T/readsb"
echo "build.sh: built $SRC/readsb-fuzz $SRC/readsb-netfuzz $T/readsb-nettest"
