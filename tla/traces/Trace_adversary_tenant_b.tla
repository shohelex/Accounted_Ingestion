---- MODULE Trace_adversary_tenant_b ----
\* Recorded from the storage code: 10 observations of Ingest's variables. TLC must find the last
\* observation reachable through all the others, in order (the invariant below is violated).
EXTENDS Ingest

VARIABLE idx

Trace == <<
    [treeCount |-> 0, anchors |-> {}, tip |-> 0, tipSigned |-> TRUE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 1, anchors |-> {}, tip |-> 0, tipSigned |-> TRUE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 2, anchors |-> {}, tip |-> 0, tipSigned |-> TRUE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 3, anchors |-> {}, tip |-> 0, tipSigned |-> TRUE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 4, anchors |-> {}, tip |-> 0, tipSigned |-> TRUE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 5, anchors |-> {}, tip |-> 0, tipSigned |-> TRUE, pending |-> {5}, storeUp |-> TRUE],
    [treeCount |-> 5, anchors |-> {[n |-> 5, prev |-> 0]}, tip |-> 5, tipSigned |-> TRUE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 5, anchors |-> {[n |-> 5, prev |-> 0]}, tip |-> 5, tipSigned |-> FALSE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 5, anchors |-> {[n |-> 5, prev |-> 0]}, tip |-> 5, tipSigned |-> FALSE, pending |-> {5}, storeUp |-> TRUE],
    [treeCount |-> 5, anchors |-> {[n |-> 5, prev |-> 0]}, tip |-> 5, tipSigned |-> TRUE, pending |-> {}, storeUp |-> TRUE]
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
