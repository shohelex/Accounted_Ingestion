#!/bin/bash
# Model-check the TLC configurations and compare each outcome with the one its .cfg expects.
#
#   bash tla/run_tlc.sh              # every configuration
#   bash tla/run_tlc.sh accounted    # one module: ingest, accounted, chain, period, logs or maker
#   bash tla/run_tlc.sh NoCAA        # one configuration
#
# Needs Java 11+; fetches tla2tools.jar into tla/tools/ on first use. Logs go to tla/results/.
# Each .cfg states "\* MODULE: <name>" and "\* EXPECT: OK" or "\* EXPECT: FAIL <property> ...".
# Exits 1 if any outcome is not the expected one.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
TOOLS="$HERE/tools"; JAR="$TOOLS/tla2tools.jar"
JAR_URL=https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar
JAR_SHA256=936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88
mkdir -p "$TOOLS" "$HERE/results"
if [ ! -f "$JAR" ]; then
  echo "fetching tla2tools.jar (v1.7.4) ..."
  curl -fsSL -o "$JAR.part" "$JAR_URL" || exit 1
  echo "$JAR_SHA256  $JAR.part" | sha256sum -c --quiet - || { rm -f "$JAR.part"; exit 1; }
  mv "$JAR.part" "$JAR"
fi
WORKERS=${WORKERS:-auto}
HEAP=${HEAP:-4g}
# TLC's state files (a few GB for Contract) go to METADIR.
META=${METADIR:-$HERE/states}
cd "$HERE"
header() { grep -m1 -oE "^\\\\\* $1: .*" "$2" | sed "s/^\\\\\* $1: //"; }
configs_of() { for f in *.cfg; do [ "$(header MODULE "$f")" = "$1" ] && echo "${f%.cfg}"; done; }
CONFIGS=""
for a in ${*:-ingest accounted chain period logs maker}; do
  case "$a" in
    ingest) CONFIGS="$CONFIGS $(configs_of Ingest)";;
    accounted) CONFIGS="$CONFIGS $(configs_of Accounted)";;
    chain) CONFIGS="$CONFIGS $(configs_of AccountedChain)";;
    period) CONFIGS="$CONFIGS $(configs_of Period)";;
    logs) CONFIGS="$CONFIGS $(configs_of AccountedLogs)";;
    maker) CONFIGS="$CONFIGS $(configs_of MakerTiming)";;
    *) CONFIGS="$CONFIGS $a";;
  esac
done
bad=0
for cfg in $CONFIGS; do
  log="results/$cfg.log"
  expect=$(header EXPECT "$cfg.cfg")
  module=$(header MODULE "$cfg.cfg")
  if [ -z "$expect" ] || [ -z "$module" ]; then
    echo "$cfg: no EXPECT or MODULE line in $cfg.cfg (run make_cfgs.py)"; bad=1; continue
  fi
  java -XX:+UseParallelGC -Xmx$HEAP -cp "$JAR" tlc2.TLC -workers "$WORKERS" -config "$cfg.cfg" \
       -metadir "$META/$cfg" -deadlock -cleanup "$module.tla" > "$log" 2>&1
  states=$(grep -oE "[0-9,]+ states generated, [0-9,]+ distinct states found" "$log" | tail -1)
  depth=$(grep -oE "depth of the complete state graph search is [0-9]+" "$log" | grep -oE "[0-9]+$" | tail -1)
  took=$(grep -oE "Finished in [0-9a-z ]+" "$log" | tail -1 | sed 's/ at *$//')
  steps=$(grep -cE "^State [0-9]+:" "$log")
  props=$(awk '/^PROPERTIES/{p=1;next} /^[A-Z_]+/{p=0} p{print $1}' "$cfg.cfg" | tr '\n' ' ' | sed 's/ *$//')
  if grep -q "Model checking completed. No error has been found" "$log"; then
    got="OK"; what="no error ($states; depth $depth; $took)"
  elif grep -qE "Invariant [A-Za-z]+ is violated" "$log"; then
    inv=$(grep -oE "Invariant [A-Za-z]+ is violated" "$log" | head -1 | awk '{print $2}')
    got="FAIL $inv"; what="invariant $inv violated, counterexample of $steps states ($states)"
  elif grep -q "Temporal properties were violated" "$log"; then
    # TLC does not name the temporal property; the config lists which ones were checked.
    got="FAIL {$props}"; what="temporal property violated (checked: $props), counterexample of $steps states ($states)"
  else
    got="ERROR"; what="TLC did not finish cleanly; see $log"
  fi
  verdict="UNEXPECTED"
  if [ "$expect" = "OK" ]; then
    [ "$got" = "OK" ] && verdict="as expected"
  elif [ "${got%% *}" = "FAIL" ]; then
    name="${got#FAIL }"
    if [ "${name#\{}" != "$name" ]; then
      # temporal: expected iff every checked property is among the expected ones
      verdict="as expected"
      for p in $props; do case " ${expect#FAIL } " in *" $p "*) ;; *) verdict="UNEXPECTED";; esac; done
    else
      case " ${expect#FAIL } " in *" $name "*) verdict="as expected";; esac
    fi
  fi
  echo "$cfg: $what -- expected $expect: $verdict"
  if [ "$verdict" != "as expected" ]; then
    bad=1
    [ "$got" = "ERROR" ] && tail -5 "$log"
  fi
done
exit $bad
