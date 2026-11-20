---- MODULE Trace_outage_tenant_b ----
\* Recorded from the storage code: 33 observations of Ingest's variables. TLC must find the last
\* observation reachable through all the others, in order (the invariant below is violated).
EXTENDS Ingest

VARIABLE idx

Trace == <<
    [treeCount |-> 0, anchors |-> {}, tip |-> 0, tipSigned |-> TRUE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 1, anchors |-> {}, tip |-> 0, tipSigned |-> TRUE, pending |-> {1}, storeUp |-> TRUE],
    [treeCount |-> 1, anchors |-> {[n |-> 1, prev |-> 0]}, tip |-> 1, tipSigned |-> TRUE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 2, anchors |-> {[n |-> 1, prev |-> 0]}, tip |-> 1, tipSigned |-> TRUE, pending |-> {2}, storeUp |-> TRUE],
    [treeCount |-> 2, anchors |-> {[n |-> 1, prev |-> 0], [n |-> 2, prev |-> 1]}, tip |-> 2, tipSigned |-> TRUE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 3, anchors |-> {[n |-> 1, prev |-> 0], [n |-> 2, prev |-> 1]}, tip |-> 2, tipSigned |-> TRUE, pending |-> {3}, storeUp |-> TRUE],
    [treeCount |-> 3, anchors |-> {[n |-> 1, prev |-> 0], [n |-> 2, prev |-> 1], [n |-> 3, prev |-> 2]}, tip |-> 3, tipSigned |-> TRUE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 4, anchors |-> {[n |-> 1, prev |-> 0], [n |-> 2, prev |-> 1], [n |-> 3, prev |-> 2]}, tip |-> 3, tipSigned |-> TRUE, pending |-> {4}, storeUp |-> TRUE],
    [treeCount |-> 4, anchors |-> {[n |-> 1, prev |-> 0], [n |-> 2, prev |-> 1], [n |-> 3, prev |-> 2], [n |-> 4, prev |-> 3]}, tip |-> 4, tipSigned |-> TRUE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 5, anchors |-> {[n |-> 1, prev |-> 0], [n |-> 2, prev |-> 1], [n |-> 3, prev |-> 2], [n |-> 4, prev |-> 3]}, tip |-> 4, tipSigned |-> TRUE, pending |-> {5}, storeUp |-> TRUE],
    [treeCount |-> 5, anchors |-> {[n |-> 1, prev |-> 0], [n |-> 2, prev |-> 1], [n |-> 3, prev |-> 2], [n |-> 4, prev |-> 3], [n |-> 5, prev |-> 4]}, tip |-> 5, tipSigned |-> TRUE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 5, anchors |-> {[n |-> 1, prev |-> 0], [n |-> 2, prev |-> 1], [n |-> 3, prev |-> 2], [n |-> 4, prev |-> 3], [n |-> 5, prev |-> 4]}, tip |-> 5, tipSigned |-> TRUE, pending |-> {}, storeUp |-> FALSE],
    [treeCount |-> 6, anchors |-> {[n |-> 1, prev |-> 0], [n |-> 2, prev |-> 1], [n |-> 3, prev |-> 2], [n |-> 4, prev |-> 3], [n |-> 5, prev |-> 4]}, tip |-> 5, tipSigned |-> TRUE, pending |-> {6}, storeUp |-> FALSE],
    [treeCount |-> 7, anchors |-> {[n |-> 1, prev |-> 0], [n |-> 2, prev |-> 1], [n |-> 3, prev |-> 2], [n |-> 4, prev |-> 3], [n |-> 5, prev |-> 4]}, tip |-> 5, tipSigned |-> TRUE, pending |-> {6, 7}, storeUp |-> FALSE],
    [treeCount |-> 8, anchors |-> {[n |-> 1, prev |-> 0], [n |-> 2, prev |-> 1], [n |-> 3, prev |-> 2], [n |-> 4, prev |-> 3], [n |-> 5, prev |-> 4]}, tip |-> 5, tipSigned |-> TRUE, pending |-> {6, 7, 8}, storeUp |-> FALSE],
    [treeCount |-> 8, anchors |-> {[n |-> 1, prev |-> 0], [n |-> 2, prev |-> 1], [n |-> 3, prev |-> 2], [n |-> 4, prev |-> 3], [n |-> 5, prev |-> 4]}, tip |-> 5, tipSigned |-> TRUE, pending |-> {6, 7, 8}, storeUp |-> TRUE],
    [treeCount |-> 9, anchors |-> {[n |-> 1, prev |-> 0], [n |-> 2, prev |-> 1], [n |-> 3, prev |-> 2], [n |-> 4, prev |-> 3], [n |-> 5, prev |-> 4]}, tip |-> 5, tipSigned |-> TRUE, pending |-> {6, 7, 8, 9}, storeUp |-> TRUE],
    [treeCount |-> 9, anchors |-> {[n |-> 1, prev |-> 0], [n |-> 2, prev |-> 1], [n |-> 3, prev |-> 2], [n |-> 4, prev |-> 3], [n |-> 5, prev |-> 4], [n |-> 6, prev |-> 5]}, tip |-> 6, tipSigned |-> TRUE, pending |-> {7, 8, 9}, storeUp |-> TRUE],
    [treeCount |-> 9, anchors |-> {[n |-> 1, prev |-> 0], [n |-> 2, prev |-> 1], [n |-> 3, prev |-> 2], [n |-> 4, prev |-> 3], [n |-> 5, prev |-> 4], [n |-> 6, prev |-> 5], [n |-> 7, prev |-> 6]}, tip |-> 7, tipSigned |-> TRUE, pending |-> {8, 9}, storeUp |-> TRUE],
    [treeCount |-> 9, anchors |-> {[n |-> 1, prev |-> 0], [n |-> 2, prev |-> 1], [n |-> 3, prev |-> 2], [n |-> 4, prev |-> 3], [n |-> 5, prev |-> 4], [n |-> 6, prev |-> 5], [n |-> 7, prev |-> 6], [n |-> 8, prev |-> 7]}, tip |-> 8, tipSigned |-> TRUE, pending |-> {9}, storeUp |-> TRUE],
    [treeCount |-> 9, anchors |-> {[n |-> 1, prev |-> 0], [n |-> 2, prev |-> 1], [n |-> 3, prev |-> 2], [n |-> 4, prev |-> 3], [n |-> 5, prev |-> 4], [n |-> 6, prev |-> 5], [n |-> 7, prev |-> 6], [n |-> 8, prev |-> 7], [n |-> 9, prev |-> 8]}, tip |-> 9, tipSigned |-> TRUE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 10, anchors |-> {[n |-> 1, prev |-> 0], [n |-> 2, prev |-> 1], [n |-> 3, prev |-> 2], [n |-> 4, prev |-> 3], [n |-> 5, prev |-> 4], [n |-> 6, prev |-> 5], [n |-> 7, prev |-> 6], [n |-> 8, prev |-> 7], [n |-> 9, prev |-> 8]}, tip |-> 9, tipSigned |-> TRUE, pending |-> {10}, storeUp |-> TRUE],
    [treeCount |-> 10, anchors |-> {[n |-> 1, prev |-> 0], [n |-> 2, prev |-> 1], [n |-> 3, prev |-> 2], [n |-> 4, prev |-> 3], [n |-> 5, prev |-> 4], [n |-> 6, prev |-> 5], [n |-> 7, prev |-> 6], [n |-> 8, prev |-> 7], [n |-> 9, prev |-> 8], [n |-> 10, prev |-> 9]}, tip |-> 10, tipSigned |-> TRUE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 11, anchors |-> {[n |-> 1, prev |-> 0], [n |-> 2, prev |-> 1], [n |-> 3, prev |-> 2], [n |-> 4, prev |-> 3], [n |-> 5, prev |-> 4], [n |-> 6, prev |-> 5], [n |-> 7, prev |-> 6], [n |-> 8, prev |-> 7], [n |-> 9, prev |-> 8], [n |-> 10, prev |-> 9]}, tip |-> 10, tipSigned |-> TRUE, pending |-> {11}, storeUp |-> TRUE],
    [treeCount |-> 11, anchors |-> {[n |-> 1, prev |-> 0], [n |-> 2, prev |-> 1], [n |-> 3, prev |-> 2], [n |-> 4, prev |-> 3], [n |-> 5, prev |-> 4], [n |-> 6, prev |-> 5], [n |-> 7, prev |-> 6], [n |-> 8, prev |-> 7], [n |-> 9, prev |-> 8], [n |-> 10, prev |-> 9], [n |-> 11, prev |-> 10]}, tip |-> 11, tipSigned |-> TRUE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 12, anchors |-> {[n |-> 1, prev |-> 0], [n |-> 2, prev |-> 1], [n |-> 3, prev |-> 2], [n |-> 4, prev |-> 3], [n |-> 5, prev |-> 4], [n |-> 6, prev |-> 5], [n |-> 7, prev |-> 6], [n |-> 8, prev |-> 7], [n |-> 9, prev |-> 8], [n |-> 10, prev |-> 9], [n |-> 11, prev |-> 10]}, tip |-> 11, tipSigned |-> TRUE, pending |-> {12}, storeUp |-> TRUE],
    [treeCount |-> 12, anchors |-> {[n |-> 1, prev |-> 0], [n |-> 2, prev |-> 1], [n |-> 3, prev |-> 2], [n |-> 4, prev |-> 3], [n |-> 5, prev |-> 4], [n |-> 6, prev |-> 5], [n |-> 7, prev |-> 6], [n |-> 8, prev |-> 7], [n |-> 9, prev |-> 8], [n |-> 10, prev |-> 9], [n |-> 11, prev |-> 10], [n |-> 12, prev |-> 11]}, tip |-> 12, tipSigned |-> TRUE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 13, anchors |-> {[n |-> 1, prev |-> 0], [n |-> 2, prev |-> 1], [n |-> 3, prev |-> 2], [n |-> 4, prev |-> 3], [n |-> 5, prev |-> 4], [n |-> 6, prev |-> 5], [n |-> 7, prev |-> 6], [n |-> 8, prev |-> 7], [n |-> 9, prev |-> 8], [n |-> 10, prev |-> 9], [n |-> 11, prev |-> 10], [n |-> 12, prev |-> 11]}, tip |-> 12, tipSigned |-> TRUE, pending |-> {13}, storeUp |-> TRUE],
    [treeCount |-> 13, anchors |-> {[n |-> 1, prev |-> 0], [n |-> 2, prev |-> 1], [n |-> 3, prev |-> 2], [n |-> 4, prev |-> 3], [n |-> 5, prev |-> 4], [n |-> 6, prev |-> 5], [n |-> 7, prev |-> 6], [n |-> 8, prev |-> 7], [n |-> 9, prev |-> 8], [n |-> 10, prev |-> 9], [n |-> 11, prev |-> 10], [n |-> 12, prev |-> 11], [n |-> 13, prev |-> 12]}, tip |-> 13, tipSigned |-> TRUE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 14, anchors |-> {[n |-> 1, prev |-> 0], [n |-> 2, prev |-> 1], [n |-> 3, prev |-> 2], [n |-> 4, prev |-> 3], [n |-> 5, prev |-> 4], [n |-> 6, prev |-> 5], [n |-> 7, prev |-> 6], [n |-> 8, prev |-> 7], [n |-> 9, prev |-> 8], [n |-> 10, prev |-> 9], [n |-> 11, prev |-> 10], [n |-> 12, prev |-> 11], [n |-> 13, prev |-> 12]}, tip |-> 13, tipSigned |-> TRUE, pending |-> {14}, storeUp |-> TRUE],
    [treeCount |-> 14, anchors |-> {[n |-> 1, prev |-> 0], [n |-> 2, prev |-> 1], [n |-> 3, prev |-> 2], [n |-> 4, prev |-> 3], [n |-> 5, prev |-> 4], [n |-> 6, prev |-> 5], [n |-> 7, prev |-> 6], [n |-> 8, prev |-> 7], [n |-> 9, prev |-> 8], [n |-> 10, prev |-> 9], [n |-> 11, prev |-> 10], [n |-> 12, prev |-> 11], [n |-> 13, prev |-> 12], [n |-> 14, prev |-> 13]}, tip |-> 14, tipSigned |-> TRUE, pending |-> {}, storeUp |-> TRUE],
    [treeCount |-> 15, anchors |-> {[n |-> 1, prev |-> 0], [n |-> 2, prev |-> 1], [n |-> 3, prev |-> 2], [n |-> 4, prev |-> 3], [n |-> 5, prev |-> 4], [n |-> 6, prev |-> 5], [n |-> 7, prev |-> 6], [n |-> 8, prev |-> 7], [n |-> 9, prev |-> 8], [n |-> 10, prev |-> 9], [n |-> 11, prev |-> 10], [n |-> 12, prev |-> 11], [n |-> 13, prev |-> 12], [n |-> 14, prev |-> 13]}, tip |-> 14, tipSigned |-> TRUE, pending |-> {15}, storeUp |-> TRUE],
    [treeCount |-> 15, anchors |-> {[n |-> 1, prev |-> 0], [n |-> 2, prev |-> 1], [n |-> 3, prev |-> 2], [n |-> 4, prev |-> 3], [n |-> 5, prev |-> 4], [n |-> 6, prev |-> 5], [n |-> 7, prev |-> 6], [n |-> 8, prev |-> 7], [n |-> 9, prev |-> 8], [n |-> 10, prev |-> 9], [n |-> 11, prev |-> 10], [n |-> 12, prev |-> 11], [n |-> 13, prev |-> 12], [n |-> 14, prev |-> 13], [n |-> 15, prev |-> 14]}, tip |-> 15, tipSigned |-> TRUE, pending |-> {}, storeUp |-> TRUE]
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
