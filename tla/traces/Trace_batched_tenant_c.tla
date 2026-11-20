---- MODULE Trace_batched_tenant_c ----
\* Recorded from the storage code: 9 observations of Ingest's variables. TLC must find the last
\* observation reachable through all the others, in order (the invariant below is violated).
EXTENDS Ingest

VARIABLE idx

Trace == <<
    [treeCount |-> 0, anchors |-> {}, tip |-> 0, tipSigned |-> TRUE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 2, anchors |-> {}, tip |-> 0, tipSigned |-> TRUE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 4, anchors |-> {}, tip |-> 0, tipSigned |-> TRUE, pending |-> {4}, storeUp |-> TRUE],
    [treeCount |-> 4, anchors |-> {[n |-> 4, prev |-> 0]}, tip |-> 4, tipSigned |-> TRUE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 6, anchors |-> {[n |-> 4, prev |-> 0]}, tip |-> 4, tipSigned |-> TRUE, pending |-> {6}, storeUp |-> TRUE],
    [treeCount |-> 6, anchors |-> {[n |-> 4, prev |-> 0], [n |-> 6, prev |-> 4]}, tip |-> 6, tipSigned |-> TRUE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 7, anchors |-> {[n |-> 4, prev |-> 0], [n |-> 6, prev |-> 4]}, tip |-> 6, tipSigned |-> TRUE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 7, anchors |-> {[n |-> 4, prev |-> 0], [n |-> 6, prev |-> 4]}, tip |-> 6, tipSigned |-> TRUE, pending |-> {7}, storeUp |-> TRUE],
    [treeCount |-> 7, anchors |-> {[n |-> 4, prev |-> 0], [n |-> 6, prev |-> 4], [n |-> 7, prev |-> 6]}, tip |-> 7, tipSigned |-> TRUE, pending |-> {}, storeUp |-> TRUE]
>>

Seen(o) == /\ treeCount = o.treeCount /\ anchors = o.anchors /\ tip = o.tip
           /\ tipSigned = o.tipSigned /\ pending = o.pending /\ storeUp = o.storeUp

\* Events are numbered and accepted in order: the test does not observe the queue, and without
\* this TLC would try every order in which they could have arrived.
AcceptInOrder == LET e == Cardinality(acked) + 1 IN e \in Events /\ Accept(e)
Step == AcceptInOrder \/ NextOther

TraceInit == Init /\ idx = 1 /\ Seen(Trace[1])

TraceNext ==
    \/ /\ Step                                   \* a step the test cannot see
       /\ UNCHANGED << treeCount, anchors, tip, tipSigned, pending, storeUp >>
       /\ idx' = idx
    \/ /\ idx < Len(Trace)                       \* one step, to exactly the next observation
       /\ Step
       /\ treeCount' = Trace[idx + 1].treeCount /\ anchors' = Trace[idx + 1].anchors
       /\ tip' = Trace[idx + 1].tip /\ tipSigned' = Trace[idx + 1].tipSigned
       /\ pending' = Trace[idx + 1].pending /\ storeUp' = Trace[idx + 1].storeUp
       /\ idx' = idx + 1

TraceSpec == TraceInit /\ [][TraceNext]_<< vars, idx >>

TraceNotAccepted == idx < Len(Trace)
====
