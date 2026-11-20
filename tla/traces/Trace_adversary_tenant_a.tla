---- MODULE Trace_adversary_tenant_a ----
\* Recorded from the storage code: 25 observations of Ingest's variables. TLC must find the last
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
    [treeCount |-> 5, anchors |-> {[n |-> 5, prev |-> 0]}, tip |-> 16, tipSigned |-> FALSE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 6, anchors |-> {[n |-> 5, prev |-> 0]}, tip |-> 16, tipSigned |-> FALSE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 7, anchors |-> {[n |-> 5, prev |-> 0]}, tip |-> 16, tipSigned |-> FALSE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 8, anchors |-> {[n |-> 5, prev |-> 0]}, tip |-> 16, tipSigned |-> FALSE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 9, anchors |-> {[n |-> 5, prev |-> 0]}, tip |-> 16, tipSigned |-> FALSE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 10, anchors |-> {[n |-> 5, prev |-> 0]}, tip |-> 16, tipSigned |-> FALSE, pending |-> {10}, storeUp |-> TRUE],
    [treeCount |-> 10, anchors |-> {[n |-> 5, prev |-> 0], [n |-> 10, prev |-> 5]}, tip |-> 10, tipSigned |-> TRUE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 11, anchors |-> {[n |-> 5, prev |-> 0], [n |-> 10, prev |-> 5]}, tip |-> 10, tipSigned |-> TRUE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 12, anchors |-> {[n |-> 5, prev |-> 0], [n |-> 10, prev |-> 5]}, tip |-> 10, tipSigned |-> TRUE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 13, anchors |-> {[n |-> 5, prev |-> 0], [n |-> 10, prev |-> 5]}, tip |-> 10, tipSigned |-> TRUE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 13, anchors |-> {[n |-> 5, prev |-> 0], [n |-> 10, prev |-> 5]}, tip |-> 10, tipSigned |-> TRUE, pending |-> {13}, storeUp |-> TRUE],
    [treeCount |-> 13, anchors |-> {[n |-> 5, prev |-> 0], [n |-> 10, prev |-> 5], [n |-> 13, prev |-> 10]}, tip |-> 13, tipSigned |-> TRUE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 14, anchors |-> {[n |-> 5, prev |-> 0], [n |-> 10, prev |-> 5], [n |-> 13, prev |-> 10]}, tip |-> 13, tipSigned |-> TRUE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 15, anchors |-> {[n |-> 5, prev |-> 0], [n |-> 10, prev |-> 5], [n |-> 13, prev |-> 10]}, tip |-> 13, tipSigned |-> TRUE, pending |-> {15}, storeUp |-> TRUE],
    [treeCount |-> 15, anchors |-> {[n |-> 5, prev |-> 0], [n |-> 10, prev |-> 5], [n |-> 13, prev |-> 10], [n |-> 15, prev |-> 13]}, tip |-> 15, tipSigned |-> TRUE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 15, anchors |-> {[n |-> 5, prev |-> 0], [n |-> 10, prev |-> 5], [n |-> 13, prev |-> 10], [n |-> 15, prev |-> 13]}, tip |-> 16, tipSigned |-> FALSE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 15, anchors |-> {[n |-> 5, prev |-> 0], [n |-> 10, prev |-> 5], [n |-> 13, prev |-> 10], [n |-> 15, prev |-> 13]}, tip |-> 16, tipSigned |-> FALSE, pending |-> {15}, storeUp |-> TRUE],
    [treeCount |-> 15, anchors |-> {[n |-> 5, prev |-> 0], [n |-> 10, prev |-> 5], [n |-> 13, prev |-> 10], [n |-> 15, prev |-> 13]}, tip |-> 15, tipSigned |-> TRUE, pending |-> {}, storeUp |-> TRUE]
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
