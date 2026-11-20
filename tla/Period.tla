------------------------------- MODULE Period -------------------------------
(***************************************************************************)
(* The time clause of the contract: the period statements and the judge    *)
(* that decides complaints about late events.                              *)
(*                                                                         *)
(* Time is counted in periods. At the end of each period the promisor      *)
(* posts one statement for it on the public log: per partition, "ok" (a    *)
(* HEAD for that partition) or "stall", and per tenant, in the tenant's    *)
(* opening, "ok", "stall" or "held" (stalled only by a co-tenant over its  *)
(* fair share). A dishonest promisor may instead post nothing, post after  *)
(* the deadline ("late"), leave a partition out ("missing"), or claim "ok" *)
(* while behind. An event is due at the end of the period it is submitted  *)
(* in and is accounted in some period, or never; the environment decides   *)
(* when, which is how an outage enters the model. The stall budget is per  *)
(* tenant: a STALL of the tenant's partition is charged to the tenant      *)
(* unless its opening says ok or held; held stalls count toward the        *)
(* per-event bound only.                                                   *)
(*                                                                         *)
(* The judge (J below) is applied to every event at every moment, with     *)
(* the public log as it stands. Each switch weakens one rule of the judge  *)
(* or of the statement maker, and makes TLC produce the failure the rule   *)
(* prevents. SlowSend breaks the send bound (a record may reach the        *)
(* broker after its due statement read the committed offset);              *)
(* PartitionFromComplaint lets the complainant name the partition instead  *)
(* of the judge computing the tenant's partition from the contract.        *)
(*                                                                         *)
(* That an outage and a withheld write give identical evidence is a        *)
(* statement about pairs of executions, not an invariant; the model shows  *)
(* its consequence instead: the judge never looks at why an event is late, *)
(* only at what was posted and when.                                       *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    NE,                  \* events 1..NE
    NParts,              \* partitions 1..NParts; event e is in partition ((e-1) % NParts) + 1
    NP,                  \* periods 0..NP-1
    E,                   \* stall budget: per event, and per tenant per window
    WE,                  \* budget window, in periods
    Honest,              \* the promisor runs the statement-maker rule
    MakerIgnoresW,       \* the honest maker posts "ok" whatever the backlog
    NoBudget,            \* the judge has no stall budget
    LateAccepted,        \* the judge counts a statement posted after the deadline as a stall
    PartialHeadAccepted, \* the judge takes a HEAD that leaves the partition out as covering it
    SilenceExcused,      \* the judge counts a missing statement as a stall
    CoTenants,           \* events 1..NE/2 are tenant 1's and the others tenant 2's (else each
                         \* event is its own tenant)
    NoHeld,              \* the judge charges a held stall to the tenant's window
    HeldFree,            \* the judge does not count a held stall toward the per-event bound
    SlowSend,            \* the send bound is broken: an acknowledged record may reach the
                         \* broker after the statement of its due period has read the committed
                         \* offset and the high watermark
    PartitionFromComplaint \* the judge takes the partition from the complaint's claimed
                         \* position instead of computing the tenant's partition from the contract

Events == 1..NE
Parts == 1..NParts
Periods == 0..(NP - 1)
None == 1000                 \* not a period
Part(e) == ((e - 1) % NParts) + 1
Tenant(e) == IF CoTenants THEN (IF e * 2 <= NE THEN 1 ELSE 2) ELSE e
Tenants == { Tenant(e) : e \in Events }

VARIABLES
    now,    \* the current period; statements for 0..now-1 are past their deadline
    due,    \* [e -> the period whose statement must first account e, or None: not submitted]
    acc,    \* [e -> the period in which e was accounted (anchored under a head), or None]
    stmt,   \* sequence: stmt[j+1] is what was posted for period j
    landed  \* [e -> e's record is in the broker] (at once unless SlowSend)

vars == << now, due, acc, stmt, landed >>

S(j) == stmt[j + 1]
Behind(e, j) == due[e] # None /\ due[e] <= j /\ (acc[e] = None \/ acc[e] > j)
\* What the honest maker can see: a record behind that is in the broker.
Seen(e, j) == landed[e] /\ Behind(e, j)

\* A statement is [on |-> "timely" | "late" | "none", st |-> [Parts -> "ok" | "stall" | "missing"],
\* ten |-> [Tenants -> "ok" | "stall" | "held"]]: ten is what each tenant's opening says.
Late(t, p, j) == Cardinality({ e \in Events : Tenant(e) = t /\ Part(e) = p /\ Seen(e, j) })
Active(p, j) == { t \in Tenants : Late(t, p, j) > 0 }
Total(p, j) == Cardinality({ e \in Events : Part(e) = p /\ Seen(e, j) })
\* Over its fair share: more than 5/4 of 1/k of the partition's late records, for k active tenants
\* (a slack of 1/4, the contract's default).
Over(t, p, j) == Cardinality(Active(p, j)) > 1 /\ Late(t, p, j) * Cardinality(Active(p, j)) * 4 > Total(p, j) * 5
TenPart(t) == CHOOSE p \in Parts : \E e \in Events : Tenant(e) = t /\ Part(e) = p
HonestTen(t) ==
    LET p == TenPart(t) IN
    IF Late(t, p, now) = 0 THEN "ok"
    ELSE IF ~Over(t, p, now) /\ \E u \in Tenants : Over(u, p, now) THEN "held"
    ELSE "stall"
HonestStmt ==
    [on |-> "timely",
     st |-> [p \in Parts |-> IF ~MakerIgnoresW /\ \E e \in Events : Part(e) = p /\ Seen(e, now)
                               THEN "stall" ELSE "ok"],
     ten |-> [t \in Tenants |-> IF MakerIgnoresW THEN "ok" ELSE HonestTen(t)]]
\* A dishonest promisor's openings say one thing for every tenant. The judge's verdict for an event
\* reads only its own tenant's entries, and the properties are per event, so this still gives each
\* event every sequence of openings its tenant can see.
\* Openings are read only for a partition the statement stalls, so they vary only then.
StallMaps == { f \in [Parts -> {"ok", "stall", "missing"}] : \E p \in Parts : f[p] = "stall" }
AnyStmt ==
    { [on |-> "timely", st |-> f, ten |-> [t \in Tenants |-> x]] :
          f \in StallMaps, x \in {"ok", "stall", "held"} }
    \cup { [on |-> "timely", st |-> f, ten |-> [t \in Tenants |-> "stall"]] :
          f \in [Parts -> {"ok", "stall", "missing"}] \ StallMaps }
    \cup { [on |-> "late", st |-> [p \in Parts |-> "stall"], ten |-> [t \in Tenants |-> "stall"]],
           [on |-> "none", st |-> [p \in Parts |-> "missing"], ten |-> [t \in Tenants |-> "stall"]] }

(***************************************************************************)
(* Actions                                                                 *)
(***************************************************************************)
Init ==
    /\ now = 0 /\ stmt = << >>
    /\ due = [e \in Events |-> None] /\ acc = [e \in Events |-> None]
    /\ landed = [e \in Events |-> FALSE]

Submit(e) ==
    /\ now < NP /\ due[e] = None
    /\ due' = [due EXCEPT ![e] = now]
    /\ landed' = [landed EXCEPT ![e] = ~SlowSend]
    /\ UNCHANGED << now, acc, stmt >>

\* With SlowSend, the record reaches the broker at some later moment.
Land(e) ==
    /\ SlowSend /\ due[e] # None /\ ~landed[e]
    /\ landed' = [landed EXCEPT ![e] = TRUE]
    /\ UNCHANGED << now, due, acc, stmt >>

\* The pipeline anchors e and the anchor is under the heads read for this period's statement.
Account(e) ==
    /\ now < NP /\ due[e] # None /\ acc[e] = None /\ landed[e]
    /\ acc' = [acc EXCEPT ![e] = now]
    /\ UNCHANGED << now, due, stmt, landed >>

\* The period ends: its statement is posted (or not) and its deadline passes.
Tick ==
    /\ now < NP
    /\ \E s \in (IF Honest THEN {HonestStmt} ELSE AnyStmt) : stmt' = Append(stmt, s)
    /\ now' = now + 1
    /\ UNCHANGED << due, acc, landed >>

Next == Tick \/ \E e \in Events : Submit(e) \/ Account(e) \/ Land(e)
Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* The judge                                                               *)
(***************************************************************************)
\* What the judge in force counts as stalling tenant t on partition p, and as charging it.
JudgeStall(s, p, t) ==
    \/ s.on = "timely" /\ s.st[p] = "stall" /\ s.ten[t] # "ok"
    \/ s.on = "late" /\ LateAccepted
    \/ s.on = "none" /\ SilenceExcused
JudgeCharge(s, p, t) == JudgeStall(s, p, t) /\ (s.on = "timely" /\ s.ten[t] = "held" => NoHeld)
Counted(s, t) == ~(HeldFree /\ s.on = "timely" /\ s.ten[t] = "held")

WindowOf(j) == { k \in Periods : k <= j /\ k + WE > j }
JudgeWin(p, t, j) == Cardinality({ k \in WindowOf(j) : JudgeCharge(S(k), p, t) })

\* cp is the partition the judge uses for the complaint: the tenant's partition from the
\* contract, or, with PartitionFromComplaint, whatever partition the complainant claims.
RECURSIVE JL(_, _, _, _)
JL(e, j, m, cp) ==
    IF j >= now THEN (IF j = due[e] THEN "pending" ELSE "excused")
    ELSE LET s == S(j)
             p == cp
             t == Tenant(e)
         IN IF s.on # "timely" /\ ~JudgeStall(s, p, t) THEN "violated"         \* silence
            ELSE IF s.on = "timely" /\ acc[e] # None /\ acc[e] <= j THEN "met"  \* MET proof
            ELSE IF PartialHeadAccepted /\ s.on = "timely" /\ s.st[p] = "missing"
                    /\ \A q \in Parts : s.st[q] # "stall" THEN "met"
            ELSE IF ~JudgeStall(s, p, t) THEN "violated"                        \* false head
            ELSE LET m2 == IF Counted(s, t) THEN m + 1 ELSE m IN
                 IF ~NoBudget /\ (m2 > E \/ JudgeWin(p, t, j) > E) THEN "violated" \* over budget
                 ELSE JL(e, j + 1, m2, cp)

JQ(e, q) == IF due[e] = None THEN "none" ELSE JL(e, due[e], 0, q)
J(e) == JQ(e, Part(e))
\* The partitions a complaint about e can make the judge use.
Claims(e) == IF PartitionFromComplaint THEN Parts ELSE {Part(e)}

(***************************************************************************)
(* Properties                                                              *)
(***************************************************************************)
TypeOK ==
    /\ now \in 0..NP /\ Len(stmt) = now
    /\ \A e \in Events : due[e] \in Periods \cup {None} /\ acc[e] \in Periods \cup {None}
    /\ landed \in [Events -> BOOLEAN]

\* A timely statement stalls tenant t on partition p, and charges it (not held).
TimelyStall(j, p, t) == S(j).on = "timely" /\ S(j).st[p] = "stall" /\ S(j).ten[t] # "ok"
Charged(j, p, t) == TimelyStall(j, p, t) /\ S(j).ten[t] # "held"
TrueWin(p, t, j) == Cardinality({ k \in WindowOf(j) : Charged(k, p, t) })
EventStalls(e) ==
    Cardinality({ j \in 0..(now - 1) : Behind(e, j) /\ TimelyStall(j, Part(e), Tenant(e)) })

\* The environment is within budget (so far): per tenant per window, and per event.
BudgetOK ==
    /\ \A e \in Events, j \in 0..(now - 1) : TrueWin(Part(e), Tenant(e), j) <= E
    /\ \A e \in Events : due[e] # None => EventStalls(e) <= E

\* A timely statement committed to e's record, within e's first E + 1 statements.
MetFact(e) ==
    /\ acc[e] # None
    /\ \E j \in due[e]..(now - 1) : j <= due[e] + E /\ S(j).on = "timely" /\ acc[e] <= j

\* An honest promisor within budget is never blamed, whatever the complaint.
JudgeSound ==
    (Honest /\ BudgetOK) => \A e \in Events : \A q \in Claims(e) : JQ(e, q) # "violated"

\* MET only with a timely commitment; EXCUSED only under timely STALLs within
\* budget and before the hard deadline; VIOLATED from the hard deadline on otherwise.
JudgeComplete ==
    \A e \in Events : due[e] # None =>
        /\ J(e) = "met" =>
               acc[e] # None /\ \E j \in due[e]..(now - 1) : S(j).on = "timely" /\ acc[e] <= j
        /\ J(e) = "excused" =>
               /\ now <= due[e] + E
               /\ \A j \in due[e]..(now - 1) : TimelyStall(j, Part(e), Tenant(e))
                                                /\ TrueWin(Part(e), Tenant(e), j) <= E
        /\ (now >= due[e] + E + 1 /\ ~MetFact(e)) => J(e) = "violated"

\* Whatever the number of complaints, the judge charges at most E periods per
\* tenant per window, counting only statements that were posted in time, and excuses an event
\* for at most E periods, held ones included.
BudgetAccountable ==
    \A e \in Events : J(e) = "excused" =>
        \A j \in due[e]..(now - 1) : TimelyStall(j, Part(e), Tenant(e))
                                     /\ TrueWin(Part(e), Tenant(e), j) <= E
                                     /\ j - due[e] < E

=============================================================================
