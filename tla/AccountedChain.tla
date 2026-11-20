--------------------------- MODULE AccountedChain ---------------------------
(***************************************************************************)
(* The anchoring step of accounted mode for one tenant, without assuming   *)
(* that the database honours the tip lock. Accounted represents the        *)
(* anchor store as one sequence of records; this module checks that this   *)
(* is sound: the valid anchor records of a tenant form one chain from      *)
(* genesis, ordered by leaf count.                                         *)
(*                                                                         *)
(* An anchorer is a writer process that anchors the records it appended    *)
(* itself, up to its own leaf count want[c]. Two anchorers of one tenant   *)
(* exist during a rebalance. The anchoring step, as the code runs it: take *)
(* the tenant's tip lock; find the head (the highest valid record in the   *)
(* store above the authenticated tip); if want[c] is at or below it,       *)
(* nothing to write; otherwise, with the successor slot, claim             *)
(* succ/<t>/<head.n> with put_once, holding the new record; then write     *)
(* anchors/<t>/<n> with put_once; then record the tip and release the      *)
(* lock. A crash may stop it anywhere and releases the lock (a row lock of *)
(* a database transaction).                                                *)
(*                                                                         *)
(* The adversary is the database. It may grant the lock to several         *)
(* processes at once (AdvLock). With AdvWithhold, store listings may also  *)
(* omit records, so the head an anchorer finds may be any valid record or  *)
(* genesis; that also covers every effect of a forged, replayed or deleted *)
(* tip row, since the tip is authenticated and only sets where the listing *)
(* starts. Records are identified by their leaf count n; pred stands for   *)
(* the predecessor's record hash, which is well defined because            *)
(* anchors/<t>/<n> is written once.                                        *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Anchorers,        \* writer processes that anchor records of the tenant
    MaxN,             \* leaf counts 1..MaxN
    MaxFaults,        \* bound on crashes
    \* rules of the design (TRUE; a must-fail configuration switches one off)
    SuccSlot,         \* claim succ/<t>/<pred.n> with put_once before writing the record
    SlotCompletion,   \* an anchorer whose claim finds another record in the slot writes
                      \* that record to the store if it is missing, and continues from it
    \* what the adversary may do
    AdvLock,          \* the database grants the tip lock to more than one process
    AdvWithhold       \* store listings may omit records

ASSUME MaxN >= 1 /\ MaxFaults >= 0

None == [n |-> 0, pred |-> 0, by |-> "none", try |-> 0]
Ns == 1..MaxN

\* A record the anchorer c builds on its attempt a: leaf count n, predecessor p. The attempt number
\* stands for what differs between two attempts of one process (the write time, the signature).
Rec(n, p, c, a) == [n |-> n, pred |-> p, by |-> c, try |-> a]

VARIABLES
    store,     \* [Ns -> record or None]: anchors/<t>/<n>
    slot,      \* [0..MaxN -> record or None]: succ/<t>/<n>, the successor of the record at n
    want,      \* [Anchorers -> Ns]: the leaf count up to which c has appended its own records
    pending,   \* [Anchorers -> BOOLEAN]: c's anchor is not yet written or covered
    pc,        \* [Anchorers -> {"idle", "locked", "chosen", "claimed", "written"}]
    head,      \* [Anchorers -> 0..MaxN]: the predecessor c chose (0 = genesis)
    mine,      \* [Anchorers -> record]: the record c is writing
    locked,    \* the processes inside the tip lock
    att,       \* [Anchorers -> Nat]: c's attempt number (a crash starts a new one)
    faults

vars == << store, slot, want, pending, pc, head, mine, locked, att, faults >>

Valid == { n \in Ns : store[n] # None }
Max(S) == CHOOSE x \in S : \A y \in S : x >= y
HeadN == Max(Valid \cup {0})

(***************************************************************************)
(* Initial state: each anchorer has appended up to some leaf count.        *)
(***************************************************************************)
Init ==
    /\ store = [n \in Ns |-> None]
    /\ slot = [n \in 0..MaxN |-> None]
    /\ want \in [Anchorers -> Ns]
    /\ pending = [c \in Anchorers |-> TRUE]
    /\ pc = [c \in Anchorers |-> "idle"]
    /\ head = [c \in Anchorers |-> 0]
    /\ mine = [c \in Anchorers |-> None]
    /\ locked = {}
    /\ att = [c \in Anchorers |-> 0]
    /\ faults = 0

(***************************************************************************)
(* The anchoring step                                                      *)
(***************************************************************************)
\* Take the tenant's tip lock. The honest database grants it to one process at a time.
Lock(c) ==
    /\ pc[c] = "idle" /\ pending[c]
    /\ AdvLock \/ locked = {}
    /\ locked' = locked \cup {c}
    /\ pc' = [pc EXCEPT ![c] = "locked"]
    /\ UNCHANGED << store, slot, want, pending, head, mine, att, faults >>

Done(c) ==
    /\ pending' = [pending EXCEPT ![c] = FALSE]
    /\ pc' = [pc EXCEPT ![c] = "idle"]
    /\ locked' = locked \ {c}

\* Continue from the record at m: nothing to write if it already covers want[c]; otherwise build the
\* record that names it.
From(c, m) ==
    IF want[c] <= m
      THEN /\ Done(c) /\ UNCHANGED << head, mine >>
      ELSE /\ head' = [head EXCEPT ![c] = m]
           /\ mine' = [mine EXCEPT ![c] = Rec(want[c], m, c, att[c])]
           /\ pc' = [pc EXCEPT ![c] = "chosen"]
           /\ UNCHANGED << pending, locked >>

\* Read the tip, authenticate it, and ask the store for the highest valid record above it.
Choose(c) ==
    /\ pc[c] = "locked"
    /\ \E m \in (IF AdvWithhold THEN Valid \cup {0} ELSE {HeadN}) : From(c, m)
    /\ UNCHANGED << store, slot, want, att, faults >>

\* Claim the successor slot of the chosen predecessor. put_once: it succeeds if the slot is
\* empty or already holds exactly this record. Otherwise another record succeeds the predecessor;
\* its writer may have died before writing it, so the claimant writes it from the slot (the slot
\* holds the whole signed record), and continues from it.
Claim(c) ==
    /\ pc[c] = "chosen"
    /\ IF ~SuccSlot
         THEN /\ pc' = [pc EXCEPT ![c] = "claimed"]
              /\ UNCHANGED << store, slot, pending, head, mine, locked >>
       ELSE LET s == slot[head[c]] IN
         IF s = None \/ s = mine[c]
           THEN /\ slot' = [slot EXCEPT ![head[c]] = mine[c]]
                /\ pc' = [pc EXCEPT ![c] = "claimed"]
                /\ UNCHANGED << store, pending, head, mine, locked >>
         ELSE IF store[s.n] = s
           THEN /\ From(c, s.n) /\ UNCHANGED << store, slot >>
         ELSE IF SlotCompletion /\ store[s.n] = None
           THEN /\ store' = [store EXCEPT ![s.n] = s]
                /\ From(c, s.n) /\ UNCHANGED slot
         ELSE \* read the store again
              /\ pc' = [pc EXCEPT ![c] = "locked"]
              /\ UNCHANGED << store, slot, pending, head, mine, locked >>
    /\ UNCHANGED << want, att, faults >>

\* Write the record, put_once under its leaf count. If another record is there, the write
\* fails: the anchor stays pending and is retried.
Write(c) ==
    /\ pc[c] = "claimed"
    /\ LET r == mine[c] IN
       IF store[r.n] = None \/ store[r.n] = r
         THEN /\ store' = [store EXCEPT ![r.n] = r]
              /\ pc' = [pc EXCEPT ![c] = "written"]
              /\ UNCHANGED locked
         ELSE /\ pc' = [pc EXCEPT ![c] = "idle"]
              /\ locked' = locked \ {c}
              /\ UNCHANGED store
    /\ UNCHANGED << slot, want, pending, head, mine, att, faults >>

\* Record the tip and release the lock.
Finish(c) ==
    /\ pc[c] = "written"
    /\ Done(c)
    /\ UNCHANGED << store, slot, want, head, mine, att, faults >>

\* A crash anywhere in the step: the transaction aborts, which releases the lock; the anchor
\* stays pending (it is a flag in the append transaction) and a new attempt begins.
Crash(c) ==
    /\ faults < MaxFaults /\ pc[c] # "idle"
    /\ pc' = [pc EXCEPT ![c] = "idle"]
    /\ locked' = locked \ {c}
    /\ att' = [att EXCEPT ![c] = @ + 1]
    /\ faults' = faults + 1
    /\ UNCHANGED << store, slot, want, pending, head, mine >>

Next ==
    \E c \in Anchorers :
        Lock(c) \/ Choose(c) \/ Claim(c) \/ Write(c) \/ Finish(c) \/ Crash(c)

Spec == Init /\ [][Next]_vars

\* The lock is taken again and again by others, so its fairness must be strong.
Fairness ==
    \A c \in Anchorers :
        /\ SF_vars(Lock(c)) /\ WF_vars(Choose(c)) /\ WF_vars(Claim(c))
        /\ WF_vars(Write(c)) /\ WF_vars(Finish(c))

LiveSpec == Spec /\ Fairness

(***************************************************************************)
(* Properties                                                              *)
(***************************************************************************)
TypeOK ==
    /\ \A n \in Ns : store[n] = None \/ (store[n].n = n /\ store[n].pred < n)
    /\ locked \subseteq Anchorers
    /\ faults \in 0..MaxFaults

\* No two valid records name the same predecessor: no fork.
NoFork ==
    \A m, n \in Valid : m # n => store[m].pred # store[n].pred

\* Ordered by leaf count, the first valid record names genesis and each
\* later one names the one before it.
SingleChain ==
    \A n \in Valid : store[n].pred = Max({ m \in Valid : m < n } \cup {0})

\* Every anchorer's records end up under an anchor (its own, or a later one that covers them).
AnchoringDone == \A c \in Anchorers : <>(~pending[c])

=============================================================================
