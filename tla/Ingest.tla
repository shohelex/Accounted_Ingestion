------------------------------- MODULE Ingest -------------------------------
(***************************************************************************)
(* The acknowledgement contract of the ingestion pipeline for one tenant:  *)
(* an event the API acknowledges ends up in the provenance graph and in    *)
(* the tenant's log, the log has one writer, the anchors form one chain,   *)
(* and consecutive anchors are at most K + B - 1 leaves apart.             *)
(*                                                                         *)
(* Two consumers may crash, and the partition may move between them while  *)
(* the old owner is still working on a batch (a rebalance). The database   *)
(* and the anchor store may be unavailable, and the broker may lose        *)
(* acknowledged records it has not flushed.                                *)
(*                                                                         *)
(* With MaxTampers > 0 an adversary writes the database, not the           *)
(* write-once anchor store: ForgeTip sets the tip row without a valid      *)
(* signature, ReplayTip restores an older signed tip or deletes the row,   *)
(* and with AdvClearsPending it clears a snapshot's pending flag. No       *)
(* writer rule prevents the last one: the ClearPending configuration       *)
(* violates GapBound, and the gap it leaves in the write-once chain is     *)
(* what the verifier reports.                                              *)
(*                                                                         *)
(* AppendLock, AnchorViaTip, Fsync, AuthTip, AdoptStore and Heartbeat are  *)
(* rules of the design, and CountOutageFail is the negation of one; each   *)
(* must-fail configuration switches one rule off.                          *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Events,           \* event identifiers of one tenant
    Poison,           \* events that fail every time (a malformed-but-parsable record)
    Consumers,        \* processes that may own the tenant's partition
    K,                \* anchoring interval, in leaves
    B,                \* append batch: leaves per log transaction, and fetch size
    MaxRedeliveries,  \* poison guard ceiling
    MaxFaults,        \* bound on injected faults, to keep the state space finite
    AppendLock,       \* the database serialises appends per tenant
    AnchorViaTip,     \* anchors chain to the tip recorded in the database
    CountOutageFail,  \* the poison guard also counts failures that happened during an outage
    Fsync,            \* the broker flushes every acknowledged record
    AuthTip,          \* a tip row whose signature does not verify is discarded
    AdoptStore,       \* before chaining, the writer asks the store for a record newer than the tip
    Heartbeat,        \* a non-empty tail is anchored after a while even if no multiple of K is crossed
    MaxTampers,       \* bound on adversary actions (0 = crash faults only)
    AdvClearsPending  \* the adversary may also clear a snapshot's pending flag

ASSUME Poison \subseteq Events
ASSUME K >= 1 /\ B >= 1

None == "none"

VARIABLES
    queue,       \* the partition: a sequence of events, in acknowledgement order
    flushed,     \* how many entries of queue are on the broker's disk
    acked,       \* events the API acknowledged with 200
    committed,   \* the committed offset: entries 1..committed are done
    owner,       \* the consumer the group currently assigns the partition to
    batch,       \* [c -> sequence of queue positions the consumer is working on]
    gdone,       \* [c -> batch positions whose graph write is done, leaf not yet appended]
    done,        \* [c -> batch positions fully processed in this delivery]
    failed,      \* [c -> batch positions that failed in this delivery]
    outage,      \* [c -> failed positions whose failure happened while the database was down]
    phase,       \* [c -> "idle" | "read"]: inside an append's read-modify-write
    rd,          \* [c -> the leaf count the append read]
    lockHolder,  \* the consumer holding the tenant's append lock, or None
    seen,        \* [c -> events this process finished, for duplicate suppression]
    graph,       \* events with an Activity node
    leaves,      \* set of <<leaf index, event>>
    treeCount,   \* the leaf count stored on the tree row
    anchors,     \* set of [n |-> leaf count, prev |-> leaf count of the previous anchor]
    tip,         \* the chain tip recorded in the database (0 = genesis)
    tipSigned,   \* the tip row carries a signature that verifies for its value
    cache,       \* [c -> the last anchor this process wrote], used when ~AnchorViaTip
    due,         \* [c -> the consumer's trigger to anchor up to this leaf count, 0 = none]
    pending,     \* leaf counts whose snapshot is flagged pending in the database
    deliveries,  \* [event -> deliveries counted by the poison guard]
    dbUp,        \* the graph database is reachable
    storeUp,     \* the anchor store is reachable
    faults,      \* injected faults so far
    tampers      \* adversary actions so far

vars == << queue, flushed, acked, committed, owner, batch, gdone, done, failed, outage,
           phase, rd, lockHolder, seen, graph, leaves, treeCount, anchors, tip, tipSigned,
           cache, due, pending, deliveries, dbUp, storeUp, faults, tampers >>

advVars == << tipSigned, tampers >>

consumerVars == << batch, gdone, done, failed, outage, phase, rd, seen, cache, due >>

(***************************************************************************)
(* Derived values                                                          *)
(***************************************************************************)
QueueEvents == { queue[j] : j \in 1..Len(queue) }
LeafEvents  == { l[2] : l \in leaves }
Positions(c) == 1..Len(batch[c])
Unstarted(c) == Positions(c) \ (gdone[c] \cup done[c] \cup failed[c])
EventAt(c, i) == queue[batch[c][i]]
Min(S) == CHOOSE x \in S : \A y \in S : x <= y
Max(S) == CHOOSE x \in S : \A y \in S : x >= y
AnchorNs == { a.n : a \in anchors }
LastAnchor == IF anchors = {} THEN 0 ELSE Max(AnchorNs)
Window == K + B - 1

\* The head of the chain as the writer takes it (crypto/merkle_tree_storage.py,
\* _anchor_serialized): a tip that fails authentication is discarded, then the newest record
\* in the store above what is left is adopted.
TipTrusted == tipSigned \/ ~AuthTip
Base == IF TipTrusted THEN tip ELSE 0
ChainHead == IF AdoptStore /\ LastAnchor > Base THEN LastAnchor ELSE Base
TipRange == 0..(Cardinality(Events) + 1)

(***************************************************************************)
(* Initial state                                                           *)
(***************************************************************************)
Init ==
    /\ queue = << >> /\ flushed = 0 /\ acked = {} /\ committed = 0
    /\ owner = CHOOSE c \in Consumers : TRUE
    /\ batch = [c \in Consumers |-> << >>]
    /\ gdone = [c \in Consumers |-> {}]
    /\ done = [c \in Consumers |-> {}]
    /\ failed = [c \in Consumers |-> {}]
    /\ outage = [c \in Consumers |-> {}]
    /\ phase = [c \in Consumers |-> "idle"]
    /\ rd = [c \in Consumers |-> 0]
    /\ lockHolder = None
    /\ seen = [c \in Consumers |-> {}]
    /\ graph = {} /\ leaves = {} /\ treeCount = 0
    /\ anchors = {} /\ tip = 0 /\ tipSigned = TRUE /\ tampers = 0
    /\ cache = [c \in Consumers |-> 0]
    /\ due = [c \in Consumers |-> 0]
    /\ pending = {}
    /\ deliveries = [e \in Events |-> 0]
    /\ dbUp = TRUE /\ storeUp = TRUE /\ faults = 0

(***************************************************************************)
(* The API and the broker                                                  *)
(***************************************************************************)
\* The API acknowledges an event once the broker has it. With Fsync the record is on disk
\* before the acknowledgement; without, it is in the page cache.
Accept(e) ==
    /\ e \notin QueueEvents /\ e \notin acked
    /\ queue' = Append(queue, e)
    /\ acked' = acked \cup {e}
    /\ flushed' = IF Fsync THEN Len(queue) + 1 ELSE flushed
    /\ UNCHANGED << committed, owner, consumerVars, lockHolder, graph, leaves, treeCount,
                    anchors, tip, pending, deliveries, dbUp, storeUp, faults, advVars >>

Flush ==
    /\ flushed < Len(queue)
    /\ flushed' = Len(queue)
    /\ UNCHANGED << queue, acked, committed, owner, consumerVars, lockHolder, graph, leaves,
                    treeCount, anchors, tip, pending, deliveries, dbUp, storeUp, faults, advVars >>

\* The broker's host loses power: whatever was not flushed is gone. Consumers holding
\* batches lose their connection and start over from the committed offset.
BrokerCrash ==
    /\ faults < MaxFaults
    /\ flushed < Len(queue)
    /\ queue' = SubSeq(queue, 1, flushed)
    /\ committed' = IF committed > flushed THEN flushed ELSE committed
    /\ batch' = [c \in Consumers |-> << >>]
    /\ gdone' = [c \in Consumers |-> {}]
    /\ done' = [c \in Consumers |-> {}]
    /\ failed' = [c \in Consumers |-> {}]
    /\ outage' = [c \in Consumers |-> {}]
    /\ phase' = [c \in Consumers |-> "idle"]
    /\ lockHolder' = None
    /\ faults' = faults + 1
    /\ UNCHANGED << flushed, acked, owner, rd, seen, graph, leaves, treeCount, anchors, tip,
                    cache, due, pending, deliveries, dbUp, storeUp, advVars >>

(***************************************************************************)
(* Consumers                                                               *)
(***************************************************************************)
\* The partition's owner fetches the next batch from the committed offset.
Fetch(c) ==
    /\ c = owner /\ batch[c] = << >> /\ committed < Len(queue)
    /\ LET hi == IF committed + B <= Len(queue) THEN committed + B ELSE Len(queue)
       IN batch' = [batch EXCEPT ![c] = [i \in 1..(hi - committed) |-> committed + i]]
    /\ gdone' = [gdone EXCEPT ![c] = {}]
    /\ done' = [done EXCEPT ![c] = {}]
    /\ failed' = [failed EXCEPT ![c] = {}]
    /\ outage' = [outage EXCEPT ![c] = {}]
    /\ UNCHANGED << queue, flushed, acked, committed, owner, phase, rd, lockHolder, seen,
                    graph, leaves, treeCount, anchors, tip, cache, due, pending, deliveries,
                    dbUp, storeUp, faults, advVars >>

\* Graph write for one event of the batch. Idempotent: an existing Activity is skipped.
\* An event this process already finished is a redelivery and is done outright.
WriteGraph(c, i) ==
    /\ i \in Unstarted(c) /\ phase[c] = "idle"
    /\ dbUp
    /\ LET e == EventAt(c, i) IN
       /\ e \notin Poison
       /\ IF e \in seen[c]
            THEN /\ done' = [done EXCEPT ![c] = @ \cup {i}]
                 /\ UNCHANGED << graph, gdone >>
            ELSE /\ graph' = graph \cup {e}
                 /\ gdone' = [gdone EXCEPT ![c] = @ \cup {i}]
                 /\ UNCHANGED done
    /\ UNCHANGED << queue, flushed, acked, committed, owner, batch, failed, outage, phase, rd,
                    lockHolder, seen, leaves, treeCount, anchors, tip, cache, due, pending,
                    deliveries, dbUp, storeUp, faults, advVars >>

\* An event fails: the database is down (an outage failure, remembered as such), or the
\* record is poison.
Fail(c, i) ==
    /\ i \in Unstarted(c) /\ phase[c] = "idle"
    /\ ~dbUp \/ EventAt(c, i) \in Poison
    /\ failed' = [failed EXCEPT ![c] = @ \cup {i}]
    /\ outage' = [outage EXCEPT ![c] = IF dbUp THEN @ ELSE @ \cup {i}]
    /\ UNCHANGED << queue, flushed, acked, committed, owner, batch, gdone, done, phase, rd,
                    lockHolder, seen, graph, leaves, treeCount, anchors, tip, cache, due,
                    pending, deliveries, dbUp, storeUp, faults, advVars >>

\* The append is read-modify-write. With AppendLock the read takes the tenant's write lock,
\* held until the write commits; without it, another writer may read the same state.
AppendRead(c) ==
    /\ phase[c] = "idle" /\ gdone[c] # {}
    /\ Unstarted(c) = {}            \* the batch's graph writes are all attempted
    /\ dbUp
    /\ AppendLock => lockHolder = None
    /\ lockHolder' = IF AppendLock THEN c ELSE lockHolder
    /\ rd' = [rd EXCEPT ![c] = treeCount]
    /\ phase' = [phase EXCEPT ![c] = "read"]
    /\ UNCHANGED << queue, flushed, acked, committed, owner, batch, gdone, done, failed,
                    outage, seen, graph, leaves, treeCount, anchors, tip, cache, due, pending,
                    deliveries, dbUp, storeUp, faults, advVars >>

\* Leaves whose content is already in the log are not appended twice (redelivery after a
\* crash between the log commit and the offset commit). The batch's new leaves take
\* consecutive indexes from the count that was read; the stored count is set to the last.
\* If the append crosses a multiple of K, its snapshot is created flagged pending in the
\* same transaction: the anchor point survives a crash, and any process can anchor it.
AppendWrite(c) ==
    /\ phase[c] = "read"
    /\ dbUp
    /\ LET pos == gdone[c]
           new == { i \in pos : EventAt(c, i) \notin LeafEvents }
           m == Cardinality(new)
           order == CHOOSE f \in [new -> rd[c]..(rd[c] + m - 1)] :
                        \A i, j \in new : i # j => f[i] # f[j]
           newLeaves == { << order[i], EventAt(c, i) >> : i \in new }
           n1 == rd[c] + m
           crossing == (n1 \div K) > (rd[c] \div K)
       IN /\ leaves' = leaves \cup newLeaves
          /\ treeCount' = n1
          /\ pending' = IF crossing THEN pending \cup {n1} ELSE pending
          /\ due' = [due EXCEPT ![c] = IF crossing THEN n1 ELSE @]
    /\ done' = [done EXCEPT ![c] = @ \cup gdone[c]]
    /\ gdone' = [gdone EXCEPT ![c] = {}]
    /\ phase' = [phase EXCEPT ![c] = "idle"]
    /\ lockHolder' = IF lockHolder = c THEN None ELSE lockHolder
    /\ UNCHANGED << queue, flushed, acked, committed, owner, batch, failed, outage, rd, seen,
                    graph, anchors, tip, cache, deliveries, dbUp, storeUp, faults, advVars >>

\* Write the lowest pending anchor. With AnchorViaTip the record chains to the tip in the
\* database and an anchor at or below the tip is skipped as already covered; without it,
\* the record chains to whatever this process last wrote.
WritePending(c) ==
    LET n == Min(pending) IN
    /\ IF AnchorViaTip
         THEN /\ IF n > ChainHead
                    THEN /\ anchors' = anchors \cup {[n |-> n, prev |-> ChainHead]}
                         /\ tip' = n /\ tipSigned' = TRUE
                    ELSE /\ UNCHANGED anchors
                         \* already covered; a tip that was adopted or repaired is written back
                         /\ IF ChainHead # tip \/ ~TipTrusted
                              THEN tip' = ChainHead /\ tipSigned' = TRUE
                              ELSE UNCHANGED << tip, tipSigned >>
              /\ UNCHANGED cache
         ELSE /\ anchors' = anchors \cup {[n |-> n, prev |-> cache[c]]}
              /\ cache' = [cache EXCEPT ![c] = n]
              /\ UNCHANGED << tip, tipSigned >>
    /\ pending' = pending \ {n}
    /\ UNCHANGED tampers

\* A consumer whose append crossed a multiple of K anchors: it writes pending snapshots in
\* leaf order until its own is written. This is the ordered flush under the tip lock.
Anchor(c) ==
    /\ due[c] > 0 /\ storeUp /\ pending # {}
    /\ WritePending(c)
    /\ due' = [due EXCEPT ![c] = IF Min(pending) >= due[c] THEN 0 ELSE @]
    /\ UNCHANGED << queue, flushed, acked, committed, owner, batch, gdone, done, failed,
                    outage, phase, rd, lockHolder, seen, graph, leaves, treeCount, deliveries,
                    dbUp, storeUp, faults >>

\* The store is down, or someone else already wrote everything: the trigger is dropped.
\* The snapshot stays pending in the database.
AnchorGiveUp(c) ==
    /\ due[c] > 0 /\ (~storeUp \/ pending = {})
    /\ due' = [due EXCEPT ![c] = 0]
    /\ UNCHANGED << queue, flushed, acked, committed, owner, batch, gdone, done, failed,
                    outage, phase, rd, lockHolder, seen, graph, leaves, treeCount, anchors,
                    tip, cache, pending, deliveries, dbUp, storeUp, faults, advVars >>

\* Any consumer may write pending anchors once the store is back. In the code, any process that
\* looks at the tenant's pending flags does it (MerkleTreeStorage._anchor_after_append,
\* anchor_heartbeat_once); weak fairness stands for the bounded intervals at which that happens.
Backfill(c) ==
    /\ storeUp /\ pending # {} /\ due[c] = 0
    /\ WritePending(c)
    /\ UNCHANGED << queue, flushed, acked, committed, owner, batch, gdone, done, failed,
                    outage, phase, rd, lockHolder, seen, graph, leaves, treeCount, due,
                    deliveries, dbUp, storeUp, faults >>

\* The batch is finished: count redeliveries of the failed positions (never an outage
\* failure, unless CountOutageFail), drop those over the ceiling, commit up to the first
\* position still failed, and mark finished events as seen. Only the partition's current
\* owner can commit; a former owner's commit is rejected by the broker and its batch is
\* dropped (its database writes were idempotent).
Commit(c) ==
    /\ batch[c] # << >> /\ phase[c] = "idle" /\ gdone[c] = {}
    /\ Unstarted(c) = {} /\ due[c] = 0
    /\ LET counted == IF CountOutageFail THEN failed[c] ELSE failed[c] \ outage[c]
           newDel == [e \in Events |-> IF \E i \in counted : EventAt(c, i) = e
                                         THEN deliveries[e] + 1 ELSE deliveries[e]]
           dropped == { i \in failed[c] : newDel[EventAt(c, i)] > MaxRedeliveries }
           stillFailed == failed[c] \ dropped
           firstFailed == IF stillFailed = {} THEN Len(batch[c]) + 1 ELSE Min(stillFailed)
           newCommitted == batch[c][1] - 1 + (firstFailed - 1)
       IN /\ deliveries' = newDel
          /\ committed' = IF c = owner /\ newCommitted > committed THEN newCommitted ELSE committed
    /\ seen' = [seen EXCEPT ![c] = @ \cup { EventAt(c, i) : i \in done[c] }]
    /\ batch' = [batch EXCEPT ![c] = << >>]
    /\ done' = [done EXCEPT ![c] = {}]
    /\ failed' = [failed EXCEPT ![c] = {}]
    /\ outage' = [outage EXCEPT ![c] = {}]
    /\ UNCHANGED << queue, flushed, acked, owner, gdone, phase, rd, lockHolder, graph, leaves,
                    treeCount, anchors, tip, cache, due, pending, dbUp, storeUp, faults, advVars >>

(***************************************************************************)
(* Faults                                                                  *)
(***************************************************************************)
\* The group reassigns the partition. The former owner keeps working on its batch until it
\* tries to commit: that is the window in which two writers exist.
Rebalance(c) ==
    /\ faults < MaxFaults
    /\ c # owner
    /\ owner' = c
    /\ faults' = faults + 1
    /\ UNCHANGED << queue, flushed, acked, committed, consumerVars, lockHolder, graph, leaves,
                    treeCount, anchors, tip, pending, deliveries, dbUp, storeUp, advVars >>

\* A consumer dies: its in-flight batch, its half-done append (rolled back by the database,
\* lock released), its duplicate-suppression cache, its anchor cache and its anchor trigger
\* are gone. The pending flag in the database is not.
Dies(c) ==
    /\ batch' = [batch EXCEPT ![c] = << >>]
    /\ gdone' = [gdone EXCEPT ![c] = {}]
    /\ done' = [done EXCEPT ![c] = {}]
    /\ failed' = [failed EXCEPT ![c] = {}]
    /\ outage' = [outage EXCEPT ![c] = {}]
    /\ phase' = [phase EXCEPT ![c] = "idle"]
    /\ lockHolder' = IF lockHolder = c THEN None ELSE lockHolder
    /\ seen' = [seen EXCEPT ![c] = {}]
    /\ cache' = [cache EXCEPT ![c] = 0]
    /\ due' = [due EXCEPT ![c] = 0]
    /\ faults' = faults + 1

CrashConsumer(c) ==
    /\ faults < MaxFaults
    /\ batch[c] # << >> \/ due[c] > 0
    /\ Dies(c)
    /\ UNCHANGED << queue, flushed, acked, committed, owner, rd, graph, leaves, treeCount,
                    anchors, tip, pending, deliveries, dbUp, storeUp, advVars >>

\* A writer dies after its anchor reached the store and before the tip was recorded (the two
\* are not one transaction: the store is a different system). The record is in the store, the
\* tip is behind it, and the snapshot is still flagged pending.
AnchorDie(c) ==
    /\ faults < MaxFaults /\ AnchorViaTip
    /\ storeUp /\ pending # {} /\ Min(pending) > ChainHead
    /\ anchors' = anchors \cup {[n |-> Min(pending), prev |-> ChainHead]}
    /\ Dies(c)
    /\ UNCHANGED << queue, flushed, acked, committed, owner, rd, graph, leaves, treeCount,
                    tip, pending, deliveries, dbUp, storeUp, advVars >>

\* Time-based anchoring: a process notices a tail that has waited too long and flags the newest
\* snapshot pending; time is abstract, so this may happen whenever there is a tail. It reads the
\* tip as the writer does, so a tampered tip makes the tail look longer, never shorter.
\* WF_vars(HeartbeatFlag) stands for the leased sweep in crypto/merkle_tree_storage.py.
HeartbeatFlag ==
    /\ Heartbeat /\ dbUp
    /\ treeCount > Base /\ treeCount \notin pending
    /\ pending' = pending \cup {treeCount}
    /\ UNCHANGED << queue, flushed, acked, committed, owner, consumerVars, lockHolder, graph,
                    leaves, treeCount, anchors, tip, deliveries, dbUp, storeUp, faults, advVars >>

(***************************************************************************)
(* The adversary: writes the database, holds no signing key, cannot alter  *)
(* the write-once anchor store.                                            *)
(***************************************************************************)
ForgeTip(n) ==
    /\ tampers < MaxTampers
    /\ n # tip \/ tipSigned
    /\ tip' = n /\ tipSigned' = FALSE /\ tampers' = tampers + 1
    /\ UNCHANGED << queue, flushed, acked, committed, owner, consumerVars, lockHolder, graph,
                    leaves, treeCount, anchors, pending, deliveries, dbUp, storeUp, faults >>

\* An older head that was genuinely signed; n = 0 is deleting the row.
ReplayTip(n) ==
    /\ tampers < MaxTampers
    /\ n \in AnchorNs \cup {0} /\ (n # tip \/ ~tipSigned)
    /\ tip' = n /\ tipSigned' = TRUE /\ tampers' = tampers + 1
    /\ UNCHANGED << queue, flushed, acked, committed, owner, consumerVars, lockHolder, graph,
                    leaves, treeCount, anchors, pending, deliveries, dbUp, storeUp, faults >>

ClearPending(n) ==
    /\ AdvClearsPending /\ tampers < MaxTampers
    /\ n \in pending
    /\ pending' = pending \ {n} /\ tampers' = tampers + 1
    /\ UNCHANGED << queue, flushed, acked, committed, owner, consumerVars, lockHolder, graph,
                    leaves, treeCount, anchors, tip, tipSigned, deliveries, dbUp, storeUp, faults >>

DbDown ==
    /\ faults < MaxFaults /\ dbUp
    /\ dbUp' = FALSE /\ faults' = faults + 1
    /\ UNCHANGED << queue, flushed, acked, committed, owner, consumerVars, lockHolder, graph,
                    leaves, treeCount, anchors, tip, pending, deliveries, storeUp, advVars >>

DbRecover ==
    /\ ~dbUp
    /\ dbUp' = TRUE
    /\ UNCHANGED << queue, flushed, acked, committed, owner, consumerVars, lockHolder, graph,
                    leaves, treeCount, anchors, tip, pending, deliveries, storeUp, faults, advVars >>

StoreDown ==
    /\ faults < MaxFaults /\ storeUp
    /\ storeUp' = FALSE /\ faults' = faults + 1
    /\ UNCHANGED << queue, flushed, acked, committed, owner, consumerVars, lockHolder, graph,
                    leaves, treeCount, anchors, tip, pending, deliveries, dbUp, advVars >>

StoreRecover ==
    /\ ~storeUp
    /\ storeUp' = TRUE
    /\ UNCHANGED << queue, flushed, acked, committed, owner, consumerVars, lockHolder, graph,
                    leaves, treeCount, anchors, tip, pending, deliveries, dbUp, faults, advVars >>

(***************************************************************************)
(* Specification                                                           *)
(***************************************************************************)
\* AcceptAny and NextOther are named apart so that trace validation (traces/) can feed events
\* in one fixed order and reuse the rest.
AcceptAny == \E e \in Events : Accept(e)

NextOther ==
    \/ Flush
    \/ BrokerCrash
    \/ \E c \in Consumers :
         \/ Fetch(c) \/ AppendRead(c) \/ AppendWrite(c) \/ Anchor(c) \/ AnchorGiveUp(c)
         \/ Backfill(c) \/ Commit(c) \/ Rebalance(c) \/ CrashConsumer(c) \/ AnchorDie(c)
         \/ \E i \in 1..B : WriteGraph(c, i) \/ Fail(c, i)
    \/ DbDown \/ DbRecover \/ StoreDown \/ StoreRecover
    \/ HeartbeatFlag
    \/ \E n \in TipRange : ForgeTip(n) \/ ReplayTip(n) \/ ClearPending(n)

Next == AcceptAny \/ NextOther

Spec == Init /\ [][Next]_vars

\* Liveness needs the system to keep taking the steps it can take: consumers keep working,
\* outages end, the heartbeat keeps running. Faults and tampering are bounded (MaxFaults,
\* MaxTampers), so they stop; nothing is assumed about when.
Fairness ==
    /\ \A c \in Consumers :
         /\ WF_vars(Fetch(c)) /\ WF_vars(AppendRead(c)) /\ WF_vars(AppendWrite(c))
         /\ WF_vars(Anchor(c)) /\ WF_vars(AnchorGiveUp(c)) /\ WF_vars(Backfill(c))
         /\ WF_vars(Commit(c))
         /\ \A i \in 1..B : WF_vars(WriteGraph(c, i)) /\ WF_vars(Fail(c, i))
    /\ WF_vars(DbRecover) /\ WF_vars(StoreRecover) /\ WF_vars(HeartbeatFlag)

LiveSpec == Spec /\ Fairness

(***************************************************************************)
(* Invariants                                                              *)
(***************************************************************************)
TypeOK ==
    /\ committed <= Len(queue) /\ flushed <= Len(queue)
    /\ treeCount \in Nat /\ tip \in Nat /\ tipSigned \in BOOLEAN /\ tampers \in 0..MaxTampers
    /\ \A c \in Consumers : phase[c] \in {"idle", "read"} /\ outage[c] \subseteq failed[c]

\* One writer: leaf indexes are distinct, no event has two leaves, and the stored count is
\* the number of leaves. Fails without AppendLock.
SingleWriter ==
    /\ \A l1, l2 \in leaves : l1[1] = l2[1] => l1 = l2
    /\ \A l1, l2 \in leaves : l1[2] = l2[2] => l1 = l2
    /\ treeCount = Cardinality(leaves)

\* The committed offset never passes an event that is not in both the graph and the log,
\* unless the event is poison (the only thing the guard may drop).
OnlyPoisonSkipped ==
    \A j \in 1..committed :
        queue[j] \in Poison \/ (queue[j] \in graph /\ queue[j] \in LeafEvents)

\* An acknowledged event is still in the partition, or already in the graph and the log.
\* Fails without Fsync: a broker crash forgets acknowledged records.
NoLostAcked ==
    \A e \in acked : e \in QueueEvents \/ (e \in graph /\ e \in LeafEvents)

\* The anchors form one chain: every prev is an earlier anchor (or genesis), no two anchors
\* share a leaf count, and no two chain to the same predecessor. Fails without AnchorViaTip.
ChainLinear ==
    /\ \A a \in anchors : a.prev < a.n /\ (a.prev = 0 \/ a.prev \in AnchorNs)
    /\ \A a1, a2 \in anchors : a1 # a2 => a1.n # a2.n /\ a1.prev # a2.prev

\* Consecutive anchors are at most K + B - 1 leaves apart, the first at most that far from
\* genesis.
GapBound ==
    \A a \in anchors : a.n - a.prev <= Window

\* While the store is reachable and nothing is pending, the leaves after the last anchor
\* are at most K + B - 1. During a store outage the tail grows; the recorded chain still
\* satisfies GapBound once the pending anchors are written.
TailBound ==
    (storeUp /\ pending = {} /\ \A c \in Consumers : phase[c] = "idle")
        => treeCount - LastAnchor <= Window

\* When everything has been processed, the graph and the log agree, and hold every
\* accepted event that is not poison.
EvidenceAtQuiescence ==
    (committed = Len(queue) /\ \A c \in Consumers : batch[c] = << >>)
        => /\ graph = LeafEvents
           /\ (QueueEvents \ Poison) \subseteq graph

(***************************************************************************)
(* Liveness (checked under LiveSpec)                                       *)
(***************************************************************************)
\* An acknowledged event that is not poison ends up in the graph and in the log.
AckedEventuallyDurable ==
    \A e \in Events \ Poison : (e \in acked) ~> (e \in graph /\ e \in LeafEvents)

\* ... and under an anchor. Leaf indexes start at 0, so an anchor at leaf count n covers
\* indexes below n. Needs the heartbeat: without it the last leaves of a tenant that goes
\* quiet below a multiple of K are never anchored.
AckedEventuallyAnchored ==
    \A e \in Events \ Poison :
        (e \in acked) ~> (\E l \in leaves : l[2] = e /\ l[1] < LastAnchor)

=============================================================================
