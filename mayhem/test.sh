#!/usr/bin/env bash
#
# mayhem/test.sh — RUN readsb's functional checks (all built by mayhem/build.sh with normal flags):
#   * upstream's own unit tests: `cprtests` (CPR position decoding known answers) and `crctests 1 2`
#     (Mode S CRC syndrome table), i.e. `make test`;
#   * known-answer decode tests: real readsb (unsanitized, mayhem/build/oracle) fed the committed
#     sample inputs through each input service, asserting the decoded fields readsb prints
#     (ICAO address, callsign, CPR-decoded position, CRC repair) — a no-op readsb prints nothing.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

O="$SRC/mayhem/build/oracle"
NET="$O/readsb-nettest"
M="$SRC/mayhem"
for b in ./cprtests ./crctests "$NET" "$O/readsb"; do
  [ -x "$b" ] || { echo "test.sh: missing $b — run mayhem/build.sh first" >&2; emit_ctrf readsb-tests 0 1; exit 1; }
done

passed=0 failed=0
check() { # check <name> <output> <fixed string>...
  local name="$1" out="$2"; shift 2
  local s
  for s in "$@"; do
    if ! grep -qF -- "$s" <<<"$out"; then
      echo "FAIL $name: expected '$s'"; failed=$((failed+1)); return
    fi
  done
  echo "PASS $name"; passed=$((passed+1))
}

# upstream unit tests: every case prints PASS/FAIL; all must pass and there must be cases
out=$(./cprtests 2>&1); rc=$?
np=$(grep -c ': *PASS' <<<"$out"); nf=$(grep -c 'FAIL' <<<"$out")
echo "cprtests: $np passed, $nf failed (rc=$rc)"
passed=$((passed+np)); failed=$((failed+nf))
[ "$rc" -eq 0 ] && [ "$np" -gt 0 ] || failed=$((failed+1))

check crctests "$(./crctests 1 2 2>&1)" "107 entries for 1-bit errors (107 possible, 100% coverage)" "Flagged 0 collisions for removal."

check raw-df17 "$("$NET" listen --net-ri-port "$M/readsb-raw/testsuite/df17.txt" 2>&1)" \
  "ICAO Address:  4840D6" "Ident:         KLM1023" "CPR latitude:    52.265780 (74158)" \
  "CPR longitude:    3.938913 (50194)" "hex:  4840d6   CRC: 000001 fixed bits: 1 decode: ok"
check raw-short "$("$NET" listen --net-ri-port "$M/readsb-raw/testsuite/ts_sig_short.txt" 2>&1)" \
  "AA:4840D6" "AA:40621D"
check beast "$("$NET" listen --net-bi-port "$M/readsb-beast/testsuite/beast.bin" 2>&1)" \
  "Ident:         KLM1023" "CPR latitude:    52.265780"
# PROXY v1 header: the receiver id is derived from the proxied source address (1.2.3.4)
check beast-proxy "$("$NET" listen --net-bi-port "$M/readsb-beast/testsuite/proxy_beast.bin" --net-ingest --net-receiver-id 2>&1)" \
  "Ident:         KLM1023" "receiverId: db96e141-83d0-bca2" "CPR latitude:  (74158)"
check sbs "$("$NET" listen --net-sbs-in-port "$M/readsb-sbs/testsuite/sbs.txt" 2>&1)" \
  "SBS  addr: 4840d6" "Ident:         KLM1023" "Latitude:      52.265780" "Longitude:     3.938913"
check asterix "$("$NET" listen --net-asterix-in-port "$M/readsb-asterix/testsuite/cat021.bin" 2>&1)" \
  "hex:  4840d6" "Ident:         KLM1023" "hex:  40621d" "Baro altitude:              38000 ft"
check uat "$("$NET" listen --net-uat-in-port "$M/readsb-uat/testsuite/uat.txt" 2>&1)" \
  "AA:A78BEA" "CPR latitude:    37.575151 (20729)" "CPR longitude: -121.983828 (54156)"
check planefinder "$("$NET" connect planefinder_in "$M/readsb-planefinder/testsuite/pf.bin" 2>&1)" \
  "Ident:         KLM1023" "AA:40621D"
# Kinetic (BaseStation) inbound: readKineticCommand's DLE/STX scan finds the 0x17 login frame
# (plain, after a skipped non-login frame, and with a 10 10 escape inside) and logs the client in
for k in login other_then_login escaped_login; do
  check "kinetic-$k" "$("$NET" listen --net-kinetic-port "$M/readsb-kinetic/testsuite/$k.bin" 2>&1)" \
    "Kinetic client logged in"
done
check ifile-iq "$("$O/readsb" --device-type ifile --ifile "$M/readsb-ifile/testsuite/df17_uc8.iq" 2>&1)" \
  "ICAO Address:  4840D6" "Ident:         KLM1023" "ICAO Address:  40621D"

emit_ctrf readsb-tests "$passed" "$failed"
