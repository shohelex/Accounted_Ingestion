#!/bin/bash
# Trace validation: check the traces in tla/traces, recorded from the storage code, against the
# TLA+ models.
#
#   bash tla/run_traces.sh
#
# For each trace TLC is asked to show that its last observation is unreachable; the counterexample
# is a model behaviour through every observation in order, one model step each (ACCEPTED).
# The negative controls from mutate_trace.py must be rejected. Exits 1 otherwise.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
JAR="$HERE/tools/tla2tools.jar"
[ -f "$JAR" ] || { echo "run tla/run_tlc.sh once first (it fetches tla2tools.jar)"; exit 1; }
META=${METADIR:-$HERE/states}
mkdir -p "$HERE/results"
# TLC resolves EXTENDS next to the root module
cp "$HERE/Ingest.tla" "$HERE/Accounted.tla" "$HERE/traces/"
cd "$HERE/traces"
bad=0
for cfg in Trace_*.cfg; do
  name="${cfg%.cfg}"; log="$HERE/results/$name.log"
  java -XX:+UseParallelGC -Xmx${HEAP:-2g} -cp "$JAR" tlc2.TLC -workers "${WORKERS:-2}" -config "$cfg" \
       -metadir "$META/$name" -deadlock -cleanup "$name.tla" > "$log" 2>&1
  obs=$(grep -cE "^    \[(treeCount|log)" "$name.tla")
  states=$(grep -oE "[0-9,]+ distinct states found" "$log" | tail -1)
  if grep -q "Invariant TraceNotAccepted is violated" "$log"; then
    steps=$(grep -cE "^State [0-9]+:" "$log")
    echo "$name: ACCEPTED ($obs observations matched by a model behaviour of $steps states; $states)"
  elif grep -q "Model checking completed. No error has been found" "$log"; then
    echo "$name: REJECTED: the model has no behaviour through these $obs observations ($states)"; bad=1
  else
    echo "$name: TLC did not finish cleanly; see $log"; tail -5 "$log"; bad=1
  fi
done
# Negative controls: recorded traces altered to what wrong code would do. Each must be rejected.
${PYTHON:-python} "$HERE/mutate_trace.py" "$HERE/traces" > /dev/null || { echo "could not build the controls"; bad=1; }
for cfg in Control_*.cfg; do
  [ -f "$cfg" ] || continue
  name="${cfg%.cfg}"; log="$HERE/results/$name.log"
  java -XX:+UseParallelGC -Xmx${HEAP:-2g} -cp "$JAR" tlc2.TLC -workers "${WORKERS:-2}" -config "$cfg" \
       -metadir "$META/$name" -deadlock -cleanup "$name.tla" > "$log" 2>&1
  states=$(grep -oE "[0-9,]+ distinct states found" "$log" | tail -1)
  if grep -q "Model checking completed. No error has been found" "$log"; then
    echo "$name: rejected, as it must be ($states)"
  else
    echo "$name: NOT REJECTED: the validator accepted a wrong trace; see $log"; bad=1
  fi
done
rm -f "$HERE/traces/Ingest.tla" "$HERE/traces/Accounted.tla" "$HERE"/traces/Control_*
exit $bad
