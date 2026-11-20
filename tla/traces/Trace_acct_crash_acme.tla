---- MODULE Trace_acct_crash_acme ----
\* Recorded from the storage code: 12 observations of Accounted's variables. TLC must find the last
\* observation reachable through all the others, in order (the invariant below is violated).
EXTENDS Accounted

VARIABLE idx

Trace == <<
    [log |-> <<>>, anchored |-> <<>>, committed |-> 0],
    [log |-> <<[pos |-> 1, kind |-> "EVENT", sub |-> 1, ref |-> 0, content |-> TRUE]>>, anchored |-> <<>>, committed |-> 0],
    [log |-> <<[pos |-> 1, kind |-> "EVENT", sub |-> 1, ref |-> 0, content |-> TRUE], [pos |-> 2, kind |-> "DUP", sub |-> 2, ref |-> 1, content |-> TRUE]>>, anchored |-> <<>>, committed |-> 0],
    [log |-> <<[pos |-> 1, kind |-> "EVENT", sub |-> 1, ref |-> 0, content |-> TRUE], [pos |-> 2, kind |-> "DUP", sub |-> 2, ref |-> 1, content |-> TRUE], [pos |-> 3, kind |-> "EVENT", sub |-> 3, ref |-> 0, content |-> TRUE]>>, anchored |-> <<>>, committed |-> 0],
    [log |-> <<[pos |-> 1, kind |-> "EVENT", sub |-> 1, ref |-> 0, content |-> TRUE], [pos |-> 2, kind |-> "DUP", sub |-> 2, ref |-> 1, content |-> TRUE], [pos |-> 3, kind |-> "EVENT", sub |-> 3, ref |-> 0, content |-> TRUE]>>, anchored |-> <<[pos |-> 1, kind |-> "EVENT", sub |-> 1, ref |-> 0, content |-> TRUE], [pos |-> 2, kind |-> "DUP", sub |-> 2, ref |-> 1, content |-> TRUE], [pos |-> 3, kind |-> "EVENT", sub |-> 3, ref |-> 0, content |-> TRUE]>>, committed |-> 0],
    [log |-> <<[pos |-> 1, kind |-> "EVENT", sub |-> 1, ref |-> 0, content |-> TRUE], [pos |-> 2, kind |-> "DUP", sub |-> 2, ref |-> 1, content |-> TRUE], [pos |-> 3, kind |-> "EVENT", sub |-> 3, ref |-> 0, content |-> TRUE]>>, anchored |-> <<[pos |-> 1, kind |-> "EVENT", sub |-> 1, ref |-> 0, content |-> TRUE], [pos |-> 2, kind |-> "DUP", sub |-> 2, ref |-> 1, content |-> TRUE], [pos |-> 3, kind |-> "EVENT", sub |-> 3, ref |-> 0, content |-> TRUE]>>, committed |-> 3],
    [log |-> <<[pos |-> 1, kind |-> "EVENT", sub |-> 1, ref |-> 0, content |-> TRUE], [pos |-> 2, kind |-> "DUP", sub |-> 2, ref |-> 1, content |-> TRUE], [pos |-> 3, kind |-> "EVENT", sub |-> 3, ref |-> 0, content |-> TRUE], [pos |-> 4, kind |-> "EVENT", sub |-> 4, ref |-> 0, content |-> TRUE]>>, anchored |-> <<[pos |-> 1, kind |-> "EVENT", sub |-> 1, ref |-> 0, content |-> TRUE], [pos |-> 2, kind |-> "DUP", sub |-> 2, ref |-> 1, content |-> TRUE], [pos |-> 3, kind |-> "EVENT", sub |-> 3, ref |-> 0, content |-> TRUE]>>, committed |-> 3],
    [log |-> <<[pos |-> 1, kind |-> "EVENT", sub |-> 1, ref |-> 0, content |-> TRUE], [pos |-> 2, kind |-> "DUP", sub |-> 2, ref |-> 1, content |-> TRUE], [pos |-> 3, kind |-> "EVENT", sub |-> 3, ref |-> 0, content |-> TRUE]>>, anchored |-> <<[pos |-> 1, kind |-> "EVENT", sub |-> 1, ref |-> 0, content |-> TRUE], [pos |-> 2, kind |-> "DUP", sub |-> 2, ref |-> 1, content |-> TRUE], [pos |-> 3, kind |-> "EVENT", sub |-> 3, ref |-> 0, content |-> TRUE]>>, committed |-> 3],
    [log |-> <<[pos |-> 1, kind |-> "EVENT", sub |-> 1, ref |-> 0, content |-> TRUE], [pos |-> 2, kind |-> "DUP", sub |-> 2, ref |-> 1, content |-> TRUE], [pos |-> 3, kind |-> "EVENT", sub |-> 3, ref |-> 0, content |-> TRUE], [pos |-> 4, kind |-> "EVENT", sub |-> 4, ref |-> 0, content |-> TRUE]>>, anchored |-> <<[pos |-> 1, kind |-> "EVENT", sub |-> 1, ref |-> 0, content |-> TRUE], [pos |-> 2, kind |-> "DUP", sub |-> 2, ref |-> 1, content |-> TRUE], [pos |-> 3, kind |-> "EVENT", sub |-> 3, ref |-> 0, content |-> TRUE]>>, committed |-> 3],
    [log |-> <<[pos |-> 1, kind |-> "EVENT", sub |-> 1, ref |-> 0, content |-> TRUE], [pos |-> 2, kind |-> "DUP", sub |-> 2, ref |-> 1, content |-> TRUE], [pos |-> 3, kind |-> "EVENT", sub |-> 3, ref |-> 0, content |-> TRUE], [pos |-> 4, kind |-> "EVENT", sub |-> 4, ref |-> 0, content |-> TRUE], [pos |-> 5, kind |-> "EVENT", sub |-> 5, ref |-> 0, content |-> TRUE]>>, anchored |-> <<[pos |-> 1, kind |-> "EVENT", sub |-> 1, ref |-> 0, content |-> TRUE], [pos |-> 2, kind |-> "DUP", sub |-> 2, ref |-> 1, content |-> TRUE], [pos |-> 3, kind |-> "EVENT", sub |-> 3, ref |-> 0, content |-> TRUE]>>, committed |-> 3],
    [log |-> <<[pos |-> 1, kind |-> "EVENT", sub |-> 1, ref |-> 0, content |-> TRUE], [pos |-> 2, kind |-> "DUP", sub |-> 2, ref |-> 1, content |-> TRUE], [pos |-> 3, kind |-> "EVENT", sub |-> 3, ref |-> 0, content |-> TRUE], [pos |-> 4, kind |-> "EVENT", sub |-> 4, ref |-> 0, content |-> TRUE], [pos |-> 5, kind |-> "EVENT", sub |-> 5, ref |-> 0, content |-> TRUE]>>, anchored |-> <<[pos |-> 1, kind |-> "EVENT", sub |-> 1, ref |-> 0, content |-> TRUE], [pos |-> 2, kind |-> "DUP", sub |-> 2, ref |-> 1, content |-> TRUE], [pos |-> 3, kind |-> "EVENT", sub |-> 3, ref |-> 0, content |-> TRUE], [pos |-> 4, kind |-> "EVENT", sub |-> 4, ref |-> 0, content |-> TRUE], [pos |-> 5, kind |-> "EVENT", sub |-> 5, ref |-> 0, content |-> TRUE]>>, committed |-> 3],
    [log |-> <<[pos |-> 1, kind |-> "EVENT", sub |-> 1, ref |-> 0, content |-> TRUE], [pos |-> 2, kind |-> "DUP", sub |-> 2, ref |-> 1, content |-> TRUE], [pos |-> 3, kind |-> "EVENT", sub |-> 3, ref |-> 0, content |-> TRUE], [pos |-> 4, kind |-> "EVENT", sub |-> 4, ref |-> 0, content |-> TRUE], [pos |-> 5, kind |-> "EVENT", sub |-> 5, ref |-> 0, content |-> TRUE]>>, anchored |-> <<[pos |-> 1, kind |-> "EVENT", sub |-> 1, ref |-> 0, content |-> TRUE], [pos |-> 2, kind |-> "DUP", sub |-> 2, ref |-> 1, content |-> TRUE], [pos |-> 3, kind |-> "EVENT", sub |-> 3, ref |-> 0, content |-> TRUE], [pos |-> 4, kind |-> "EVENT", sub |-> 4, ref |-> 0, content |-> TRUE], [pos |-> 5, kind |-> "EVENT", sub |-> 5, ref |-> 0, content |-> TRUE]>>, committed |-> 5]
>>

Seen(o) == log = o.log /\ anchored = o.anchored /\ committed = o.committed

TraceInit == Init /\ idx = 1 /\ Seen(Trace[1])

TraceNext ==
    \/ /\ Next                                   \* a step the test cannot see
       /\ UNCHANGED << log, anchored, committed >>
       /\ idx' = idx
    \/ /\ idx < Len(Trace)                       \* one step, to exactly the next observation
       /\ Next
       /\ log' = Trace[idx + 1].log /\ anchored' = Trace[idx + 1].anchored
       /\ committed' = Trace[idx + 1].committed
       /\ idx' = idx + 1

TraceSpec == TraceInit /\ [][TraceNext]_<< vars, idx >>

TraceNotAccepted == idx < Len(Trace)
====
