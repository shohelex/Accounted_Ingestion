----------------------------- MODULE Accounted ------------------------------
(***************************************************************************)
(* Accounted ingestion for one partition that carries one tenant's log.    *)
(*                                                                         *)
(* Every submission the API acknowledged is, at every moment, either       *)
(*   - accounted: the write-once store holds, at the submission's broker   *)
(*     position, its event record or a verdict that a third party can      *)
(*     check;                                                              *)
(*   - still in the broker, where the replay audit can capture its tag;    *)
(*   - named by a receipt the sender still holds; or                       *)
(*   - named by an anchored verdict that fails its check, a self-contained *)
(*     proof of breach in the store.                                       *)
(* That holds with the sender (it discards receipts) and the database (it  *)
(* truncates, rewrites and plants) both corrupted. Switching off one rule  *)
(* of the design produces the loss the rule prevents.                      *)
(*                                                                         *)
(* Positions are broker offsets 1..NSubs. Submission s is the record at    *)
(* offset s: the API sends in that order, and each submission is sent once *)
(* (a retry is a new submission with the same event id). Offsets are       *)
(* opaque identifiers: a hole in the anchored offsets is not counted as    *)
(* evidence.                                                               *)
(*                                                                         *)
(* Abstractions: one record per append transaction (a finer interleaving   *)
(* than the code's batch transaction); the anchorer may anchor the whole   *)
(* tail at any moment; poison is modelled at the point its redeliveries    *)
(* are exhausted; the graph is not modelled (planted graph or index state  *)
(* enters only through what the writer's decision reads), nor is the       *)
(* system log (UNAUTH), since routing to it is a function of the record.   *)
(* The store is one sequence of records; AccountedChain checks that        *)
(* the valid anchor records form one chain.                                *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    NSubs,            \* submissions; submission s is at broker offset s
    SameEid,          \* submissions 1 and 2 carry the same event id ...
    SameContent,      \* ... and the same content (a retry), or different content (a collision)
    Malformed,        \* submissions whose bytes fail the published validator
    Consumers,        \* writer processes that may own the partition
    B,                \* records a writer may decide ahead of appending them
    MaxFaults,        \* bound on crashes, rebalances and outages
    MaxTampers,       \* bound on database-adversary actions (0 = none)
    Beta,             \* UNCHECKABLE verdicts allowed per window
    \* rules of the design (TRUE; a must-fail configuration switches one off)
    AckAfterBroker,   \* the API acknowledges only after the broker did (off: the direct
                      \* fallback acknowledges an event it wrote only to the database)
    EarlierReferent,  \* a DUP/COLLIDE referent lies at an earlier broker position
    CAA,              \* commit only positions whose record the store holds
    CoverageCheck,    \* ... and holds equal to the writer's own record
    Verdicts,         \* every skip becomes a verdict record
    ContentInVerdict, \* verdicts embed the content
    PositionDedup,    \* dedup by broker position; else by content-derived leaf id
    TailReset,        \* reset the tail from the store on acquisition and on any mismatch
    TailCheck,        \* an append to a tail shorter than the writer wrote since its reset
                      \* is a PositionConflict (the batch is dropped and the owner resets)
    TailCheckPoll,    \* the coverage poll refuses to report coverage for such a tail, and
                      \* resets it, also when the writer has nothing left to append
    Fencing,          \* writer epoch checked by every append
    AnchorerCheck,    \* the anchorer refuses non-increasing positions
    CountUnchk,       \* UNCHECKABLE verdicts beyond Beta count as violations
    AdoptUnchk,       \* a redelivering writer adopts an anchored UNCHECKABLE verdict equal to
                      \* the one an honest writer builds from the record
    FreshRedelivery,  \* a redelivered, already anchored position is decided without the
                      \* redelivery counter (never as UNCHECKABLE)
    \* what the adversary may do
    AdvTruncate,      \* delete the unanchored tail
    AdvReplace,       \* rewrite an unanchored record with another submission's record
    AdvMisplace,      \* rewrite the position of an unanchored record
    AdvPlant,         \* plant graph or index state for an event id
    AdvPoison,        \* make the writes of a position fail with a non-outage error
    AdvDropReceipts,  \* the sender discards every receipt
    Outages           \* the database and the store may be unavailable

ASSUME NSubs >= 1 /\ B >= 1 /\ Beta >= 0 /\ Malformed \subseteq 1..NSubs

Subs == 1..NSubs
Positions == 1..NSubs
None == "none"

EventOf(s) == IF SameEid /\ s = 2 THEN 1 ELSE s
ContentOf(s) == IF SameEid /\ ~SameContent /\ s = 2 THEN "c2" ELSE "c1"
Hash(s) == << EventOf(s), ContentOf(s) >>        \* the content hash h in the SUB tag
EventIds == { EventOf(s) : s \in Subs }

\* An accounting record. kind is "EVENT" or a verdict type; sub is the submission whose SUB tag
\* the record carries (and hence its content hash); content says whether the content itself is
\* embedded; ref is a referent's sequence number (DUP, COLLIDE). A record's seq is its index.
\* "SKIP" is not a record: it is a decision to append nothing (the ablated rules only).
Rec(p, k, s, r, c) == [pos |-> p, kind |-> k, sub |-> s, ref |-> r, content |-> c]
Skip(p) == Rec(p, "SKIP", p, 0, FALSE)

VARIABLES
    sent,        \* submissions acknowledged so far: 1..sent (after the broker's ack)
    direct,      \* submissions acknowledged by the direct fallback: in the database only, never
                 \*   in the broker (empty while AckAfterBroker holds)
    dropped,     \* the sender has discarded its receipts
    committed,   \* offsets 1..committed are released by the broker's consumer group
    logStart,    \* offsets 1..logStart are deleted by retention (only released ones)
    owner,       \* the writer the group assigns the partition to, or None after a crash
    next,        \* [c -> next offset the writer decides]
    batch,       \* [c -> records decided and not yet appended]
    mem,         \* [c -> set of [pos, seq, rec]: what the writer appended or verified]
                 \*   seq > 0: the record's index; 0: skipped (no record); -1: the store holds
                 \*   another record at that position, or none although it is below pos_last
    myN,         \* [c -> the tail length the writer knows it produced since its reset]
    myEpoch,     \* [c -> the writer epoch the writer holds]
    epoch,       \* the writer epoch in the database
    conflict,    \* [c -> an append hit PositionConflict]
    log,         \* the tenant's log in the database: anchored prefix and unanchored tail
    anchored,    \* the tenant's log in the write-once store (segments under anchors)
    refused,     \* the anchorer refused the tail (AnchorTamper)
    planted,     \* event ids with planted graph or index state
    poisoned,    \* offsets whose writes the adversary makes fail
    dbUp, storeUp,
    faults, tampers

vars == << sent, direct, dropped, committed, logStart, owner, next, batch, mem, myN, myEpoch, epoch,
           conflict, log, anchored, refused, planted, poisoned, dbUp, storeUp, faults, tampers >>

writerVars == << next, batch, mem, myN, myEpoch, conflict >>
advVars == << planted, poisoned, tampers >>

(***************************************************************************)
(* Derived values                                                          *)
(***************************************************************************)
Min(S) == CHOOSE x \in S : \A y \in S : x <= y
AnchoredLast == IF anchored = << >> THEN 0 ELSE anchored[Len(anchored)].pos
TailIdx == (Len(anchored) + 1)..Len(log)
TailLast == IF Len(log) > Len(anchored) THEN log[Len(log)].pos ELSE 0

UnchkUpTo(i) == Cardinality({ k \in 1..i : anchored[k].kind = "UNCHK" })

\* The third-party check of anchored record i.
Justified(i) ==
    LET r == anchored[i] IN
    CASE r.kind = "EVENT" -> TRUE
      [] r.kind \in {"DUP", "COLLIDE"} ->
            /\ r.ref \in 1..(i - 1)
            /\ anchored[r.ref].kind = "EVENT"
            /\ EventOf(anchored[r.ref].sub) = EventOf(r.sub)
            /\ (Hash(anchored[r.ref].sub) = Hash(r.sub)) = (r.kind = "DUP")
      [] r.kind = "MALFORMED" -> r.sub \in Malformed
      [] r.kind = "UNCHK" -> ~CountUnchk \/ UnchkUpTo(i) <= Beta
      [] OTHER -> FALSE

\* Submission s is accounted: the store holds, at its position, a record carrying its tag that is
\* its event record or a verdict that passes its check.
AccountedOK(s) ==
    \E i \in 1..Len(anchored) : anchored[i].pos = s /\ anchored[i].sub = s /\ Justified(i)

\* The broker still holds the record: the replay audit can form a complaint from its tag.
Retained(s) == s > logStart /\ s \notin direct

\* The store holds, at s's position, a verdict carrying s's tag that fails its check: a
\* self-contained proof of breach naming s.
EvidenceFor(s) ==
    \E i \in 1..Len(anchored) : anchored[i].pos = s /\ anchored[i].sub = s /\ ~Justified(i)

(***************************************************************************)
(* The writer's decision (processing/decide.py). It reads the database     *)
(* through the event-id index over accounting records. For an event id     *)
(* with planted state the index may answer truthfully, hide the prior      *)
(* record (0) or invent one (-1).                                          *)
(***************************************************************************)
Choices(c, p) ==
    LET view == log \o batch[c]                  \* a batch's records get the next indexes
        \* a referent is at an earlier position: a redelivered record is not its own prior
        cand == { i \in 1..Len(view) : view[i].kind = "EVENT"
                                       /\ (EarlierReferent => view[i].pos < p)
                                       /\ EventOf(view[i].sub) = EventOf(p) }
        genuine == IF cand = {} THEN 0 ELSE Min(cand)
        answers == IF EventOf(p) \in planted THEN {genuine, 0, -1} ELSE {genuine}
        FromAnswer(a) ==
            IF a = 0
              THEN IF p \in poisoned
                     THEN IF Verdicts THEN Rec(p, "UNCHK", p, 0, ContentInVerdict) ELSE Skip(p)
                   \* without verdicts a planted Activity with the id is a collision: skipped
                   ELSE IF EventOf(p) \in planted /\ ~Verdicts THEN Skip(p)
                   ELSE Rec(p, "EVENT", p, 0, TRUE)
              ELSE LET k == IF a > 0 /\ Hash(view[a].sub) = Hash(p) THEN "DUP" ELSE "COLLIDE"
                   IN IF Verdicts THEN Rec(p, k, p, IF a > 0 THEN a ELSE 0, ContentInVerdict)
                      ELSE Skip(p)
    IN IF p \in Malformed
         THEN {IF Verdicts THEN Rec(p, "MALFORMED", p, 0, TRUE) ELSE Skip(p)}  \* raw bytes in a blob
         ELSE { FromAnswer(a) : a \in answers }

\* verify_redelivery: the record at position p in the store must equal the writer's own. A new
\* owner also adopts an anchored UNCHECKABLE verdict for the record: whether writes kept failing is
\* not a function of the record, so its own attempts may differ. It adopts only a verdict equal to
\* the one an honest writer builds from the record's bytes once its attempts are exhausted (the
\* record's tag and content; counted against Beta either way), never another record.
UnchkOf(p) == Rec(p, "UNCHK", p, 0, ContentInVerdict)
Verified(p, t) ==
    IF \E i \in 1..Len(anchored) : anchored[i] = t
      THEN CHOOSE i \in 1..Len(anchored) : anchored[i] = t
    ELSE IF AdoptUnchk /\ p \notin Malformed /\ \E i \in 1..Len(anchored) : anchored[i] = UnchkOf(p)
      THEN CHOOSE i \in 1..Len(anchored) : anchored[i] = UnchkOf(p)
      ELSE -1

\* A coverage certificate for one position, as the commit rule in force sees it.
Covered(m) ==
    \/ m.seq = 0                                  \* a skip counts as covered (Verdicts off)
    \/ /\ m.seq > 0
       /\ IF ~CAA THEN TRUE                       \* commit once appended to the database
          ELSE IF CoverageCheck
                 THEN m.seq <= Len(anchored) /\ anchored[m.seq] = m.rec
                 ELSE \E i \in 1..Len(anchored) : anchored[i].pos = m.pos

Ok(c, p) == \E m \in mem[c] : m.pos = p /\ Covered(m)
NewW(c) == CHOOSE x \in committed..sent :
               /\ \A p \in (committed + 1)..x : Ok(c, p)
               /\ (x = sent \/ ~Ok(c, x + 1))

\* The tail is shorter than what the writer appended since its reset: records were removed under it.
ShortTail(c) == Len(log) < myN[c]

\* What makes the owner reset the tail, besides acquiring the partition. The last disjunct is
\* the coverage poll's check: a writer that has nothing left to append never reaches the append's.
Mismatch(c) ==
    \/ conflict[c]
    \/ refused
    \/ CAA /\ CoverageCheck
          /\ \E m \in mem[c] : m.seq > 0 /\ m.seq <= Len(anchored) /\ anchored[m.seq] # m.rec
    \/ TailCheckPoll /\ ShortTail(c)

(***************************************************************************)
(* Initial state                                                           *)
(***************************************************************************)
Init ==
    /\ sent = 0 /\ direct = {} /\ dropped = FALSE /\ committed = 0 /\ logStart = 0
    /\ owner = CHOOSE c \in Consumers : TRUE
    /\ next = [c \in Consumers |-> 1]
    /\ batch = [c \in Consumers |-> << >>]
    /\ mem = [c \in Consumers |-> {}]
    /\ myN = [c \in Consumers |-> 0]
    /\ myEpoch = [c \in Consumers |-> IF c = owner THEN 1 ELSE 0]
    /\ epoch = 1
    /\ conflict = [c \in Consumers |-> FALSE]
    /\ log = << >> /\ anchored = << >> /\ refused = FALSE
    /\ planted = {} /\ poisoned = {}
    /\ dbUp = TRUE /\ storeUp = TRUE /\ faults = 0 /\ tampers = 0

(***************************************************************************)
(* The API and the broker                                                  *)
(***************************************************************************)
\* The tagged record is in the broker (acks=all) before the receipt is returned.
Submit ==
    /\ sent < NSubs
    /\ sent' = sent + 1
    /\ UNCHANGED << direct, dropped, committed, logStart, owner, writerVars, epoch, log, anchored, refused,
                    advVars, dbUp, storeUp, faults >>

\* AckAfterBroker off: the direct fallback acknowledges a submission the broker never received,
\* after writing it to the database tail only.
DirectAck ==
    /\ ~AckAfterBroker /\ dbUp /\ sent < NSubs
    /\ sent' = sent + 1 /\ direct' = direct \cup {sent + 1}
    /\ log' = Append(log, Rec(sent + 1, "EVENT", sent + 1, 0, TRUE))
    /\ UNCHANGED << dropped, committed, logStart, owner, writerVars, epoch, anchored, refused,
                    advVars, dbUp, storeUp, faults >>

\* Retention deletes released records, in the model at once (the adversary's best case).
Expire ==
    /\ logStart < committed
    /\ logStart' = logStart + 1
    /\ UNCHANGED << sent, direct, dropped, committed, owner, writerVars, epoch, log, anchored, refused,
                    advVars, dbUp, storeUp, faults >>

(***************************************************************************)
(* Writers                                                                 *)
(***************************************************************************)
\* The owner decides the next fetched record, in offset order. A record at or below the last
\* anchored position is a redelivery and is verified against the store instead of appended.
Decide(c) ==
    /\ c = owner /\ dbUp /\ next[c] <= sent /\ Len(batch[c]) < B
    /\ next[c] \notin direct                     \* the broker has no record there
    /\ LET p == next[c] IN
       /\ p <= AnchoredLast => storeUp
       /\ \E t \in Choices(c, p) :
            IF t.kind = "SKIP"
              THEN /\ mem' = [mem EXCEPT ![c] = @ \cup {[pos |-> p, seq |-> 0, rec |-> t]}]
                   /\ UNCHANGED batch
            ELSE IF p <= AnchoredLast
              \* no graph write is redone for an accounted position, so no attempt is counted:
              \* the redelivery is decided as a fresh record, never as UNCHECKABLE
              THEN LET v == Verified(p, IF FreshRedelivery /\ t.kind = "UNCHK"
                                          THEN Rec(p, "EVENT", p, 0, TRUE) ELSE t) IN
                   /\ mem' = [mem EXCEPT ![c] = @ \cup {[pos |-> p, seq |-> v,
                                                         rec |-> IF v > 0 THEN anchored[v] ELSE t]}]
                   /\ UNCHANGED batch
            ELSE /\ batch' = [batch EXCEPT ![c] = Append(@, t)]
                 /\ UNCHANGED mem
       /\ next' = [next EXCEPT ![c] = p + 1]
    /\ UNCHANGED << sent, direct, dropped, committed, logStart, owner, myN, myEpoch, epoch, conflict, log,
                    anchored, refused, advVars, dbUp, storeUp, faults >>

\* add_records, one record per transaction. Any writer holding a batch may call it, including
\* a former owner that has not yet noticed the rebalance (a zombie).
AddRecord(c) ==
    /\ batch[c] # << >> /\ dbUp
    /\ LET t == Head(batch[c])
           seq == Len(log) + 1
           addMem(q) == mem' = [mem EXCEPT ![c] = @ \cup {[pos |-> t.pos, seq |-> q, rec |-> t]}]
       IN IF Fencing /\ myEpoch[c] # epoch
            THEN \* FencedWriter: the partition has moved on; the batch is dropped
                 /\ batch' = [batch EXCEPT ![c] = << >>]
                 /\ UNCHANGED << log, mem, myN, conflict >>
          ELSE IF TailCheck /\ ShortTail(c)
            THEN \* PositionConflict: appending on top would give the removed records' seqs to
                 \* other records. The batch is dropped and the owner resets (Mismatch).
                 /\ batch' = [batch EXCEPT ![c] = << >>]
                 /\ conflict' = [conflict EXCEPT ![c] = TRUE]
                 /\ UNCHANGED << log, mem, myN >>
          ELSE IF PositionDedup
            THEN IF t.pos <= TailLast
                   THEN IF \E i \in TailIdx : log[i] = t
                          THEN /\ addMem(CHOOSE i \in TailIdx : log[i] = t)   \* redelivery
                               /\ batch' = [batch EXCEPT ![c] = Tail(@)]
                               /\ UNCHANGED << log, myN, conflict >>
                          ELSE \* PositionConflict
                               /\ batch' = [batch EXCEPT ![c] = << >>]
                               /\ conflict' = [conflict EXCEPT ![c] = TRUE]
                               /\ UNCHANGED << log, mem, myN >>
                   ELSE /\ log' = Append(log, t) /\ addMem(seq)
                        /\ myN' = [myN EXCEPT ![c] = @ + 1]
                        /\ batch' = [batch EXCEPT ![c] = Tail(@)]
                        /\ UNCHANGED conflict
          ELSE \* content dedup: a leaf whose content-derived id exists is not appended, and counts as done
               IF t.kind = "EVENT" /\ (\/ EventOf(t.sub) \in planted
                                       \/ \E i \in 1..Len(log) : log[i].kind = "EVENT"
                                                                /\ Hash(log[i].sub) = Hash(t.sub))
                 THEN /\ addMem(0)
                      /\ batch' = [batch EXCEPT ![c] = Tail(@)]
                      /\ UNCHANGED << log, myN, conflict >>
                 ELSE /\ log' = Append(log, t) /\ addMem(seq)
                      /\ myN' = [myN EXCEPT ![c] = @ + 1]
                      /\ batch' = [batch EXCEPT ![c] = Tail(@)]
                      /\ UNCHANGED conflict
    /\ UNCHANGED << sent, direct, dropped, committed, logStart, owner, next, myEpoch, epoch, anchored,
                    refused, advVars, dbUp, storeUp, faults >>

\* The anchorer writes the tail, up to a pending snapshot, as the next segment under a signed
\* anchor. It reads the segment from the database, and nothing else. Any writer process may do it.
Anchor ==
    /\ dbUp /\ storeUp /\ ~refused /\ Len(log) > Len(anchored)
    /\ \E n \in (Len(anchored) + 1)..Len(log) :
       LET seg == SubSeq(log, Len(anchored) + 1, n)
           ok == \A i \in 1..Len(seg) :
                    seg[i].pos > (IF i = 1 THEN AnchoredLast ELSE seg[i - 1].pos)
       IN IF AnchorerCheck /\ ~ok
            THEN /\ refused' = TRUE /\ UNCHANGED anchored          \* AnchorTamper
            ELSE /\ anchored' = anchored \o seg /\ UNCHANGED refused
    /\ UNCHANGED << sent, direct, dropped, committed, logStart, owner, writerVars, epoch, log, advVars,
                    dbUp, storeUp, faults >>

\* The owner commits a prefix of the offsets it holds a coverage certificate for, up to the
\* longest. The broker accepts commits from the group's current owner only.
Commit(c) ==
    /\ c = owner /\ (CAA => storeUp)
    /\ ~(TailCheckPoll /\ ShortTail(c))           \* no coverage is reported for a cut tail
    /\ \E x \in (committed + 1)..NewW(c) :
         /\ committed' = x
         /\ mem' = [mem EXCEPT ![c] = { m \in @ : m.pos > x }]
    /\ UNCHANGED << sent, direct, dropped, logStart, owner, next, batch, myN, myEpoch, epoch, conflict, log,
                    anchored, refused, advVars, dbUp, storeUp, faults >>

\* reset_tenant_tail, then seek to the committed offset. With TailReset off the tail is
\* kept as it is; the epoch is still taken.
TakeOver(c) ==
    /\ log' = IF TailReset THEN anchored ELSE log
    /\ epoch' = epoch + 1
    /\ myEpoch' = [myEpoch EXCEPT ![c] = epoch + 1]
    /\ next' = [next EXCEPT ![c] = committed + 1]
    /\ batch' = [batch EXCEPT ![c] = << >>]
    /\ mem' = [mem EXCEPT ![c] = {}]
    /\ myN' = [myN EXCEPT ![c] = IF TailReset THEN Len(anchored) ELSE Len(log)]
    /\ conflict' = [conflict EXCEPT ![c] = FALSE]
    /\ refused' = IF TailReset THEN FALSE ELSE refused

\* The owner resets on a coverage mismatch, a position conflict, an anchorer refusal, or a tail
\* shorter than what it wrote.
Reset(c) ==
    /\ TailReset /\ c = owner /\ dbUp /\ storeUp
    /\ Mismatch(c)
    /\ TakeOver(c)
    /\ UNCHANGED << sent, direct, dropped, committed, logStart, owner, anchored, advVars, dbUp, storeUp,
                    faults >>

\* After a crash, the group assigns the partition to a live writer.
Assign(c) ==
    /\ owner = None /\ dbUp /\ storeUp
    /\ owner' = c
    /\ TakeOver(c)
    /\ UNCHANGED << sent, direct, dropped, committed, logStart, anchored, advVars, dbUp, storeUp, faults >>

(***************************************************************************)
(* Faults                                                                  *)
(***************************************************************************)
\* The group moves the partition. The former owner keeps its batch and may still append it.
Rebalance(c) ==
    /\ faults < MaxFaults /\ owner # None /\ c # owner /\ dbUp /\ storeUp
    /\ owner' = c
    /\ TakeOver(c)
    /\ faults' = faults + 1
    /\ UNCHANGED << sent, direct, dropped, committed, logStart, anchored, advVars, dbUp, storeUp >>

Crash(c) ==
    /\ faults < MaxFaults
    /\ c = owner \/ batch[c] # << >>
    /\ owner' = IF owner = c THEN None ELSE owner
    /\ next' = [next EXCEPT ![c] = 1]
    /\ batch' = [batch EXCEPT ![c] = << >>]
    /\ mem' = [mem EXCEPT ![c] = {}]
    /\ myN' = [myN EXCEPT ![c] = 0]
    /\ myEpoch' = [myEpoch EXCEPT ![c] = 0]
    /\ conflict' = [conflict EXCEPT ![c] = FALSE]
    /\ faults' = faults + 1
    /\ UNCHANGED << sent, direct, dropped, committed, logStart, epoch, log, anchored, refused, advVars,
                    dbUp, storeUp >>

DbDown ==
    /\ Outages /\ faults < MaxFaults /\ dbUp
    /\ dbUp' = FALSE /\ faults' = faults + 1
    /\ UNCHANGED << sent, direct, dropped, committed, logStart, owner, writerVars, epoch, log, anchored,
                    refused, advVars, storeUp >>
DbRecover ==
    /\ ~dbUp /\ dbUp' = TRUE
    /\ UNCHANGED << sent, direct, dropped, committed, logStart, owner, writerVars, epoch, log, anchored,
                    refused, advVars, storeUp, faults >>
StoreDown ==
    /\ Outages /\ faults < MaxFaults /\ storeUp
    /\ storeUp' = FALSE /\ faults' = faults + 1
    /\ UNCHANGED << sent, direct, dropped, committed, logStart, owner, writerVars, epoch, log, anchored,
                    refused, advVars, dbUp >>
StoreRecover ==
    /\ ~storeUp /\ storeUp' = TRUE
    /\ UNCHANGED << sent, direct, dropped, committed, logStart, owner, writerVars, epoch, log, anchored,
                    refused, advVars, dbUp, faults >>

(***************************************************************************)
(* The adversary: the database (it writes any row; it holds no key and     *)
(* cannot touch the store or the broker) and the sender.                   *)
(***************************************************************************)
TruncateTail ==
    /\ AdvTruncate /\ tampers < MaxTampers /\ Len(log) > Len(anchored)
    /\ log' = anchored /\ tampers' = tampers + 1
    /\ UNCHANGED << sent, direct, dropped, committed, logStart, owner, writerVars, epoch, anchored, refused,
                    planted, poisoned, dbUp, storeUp, faults >>

\* Replace an unanchored record by a copy of another submission's event record (the adversary
\* cannot sign a tag, so the only records it can make carry tags it has seen).
ReplaceTail(i, s) ==
    /\ AdvReplace /\ tampers < MaxTampers /\ i \in TailIdx /\ s \in 1..sent /\ s # log[i].sub
    /\ log' = [log EXCEPT ![i] = Rec(log[i].pos, "EVENT", s, 0, TRUE)]
    /\ tampers' = tampers + 1
    /\ UNCHANGED << sent, direct, dropped, committed, logStart, owner, writerVars, epoch, anchored, refused,
                    planted, poisoned, dbUp, storeUp, faults >>

MisplaceTail(i, p) ==
    /\ AdvMisplace /\ tampers < MaxTampers /\ i \in TailIdx /\ p # log[i].pos
    /\ log' = [log EXCEPT ![i].pos = p]
    /\ tampers' = tampers + 1
    /\ UNCHANGED << sent, direct, dropped, committed, logStart, owner, writerVars, epoch, anchored, refused,
                    planted, poisoned, dbUp, storeUp, faults >>

\* An Activity, an index entry or a MerkleNode keyed by the event id (or its content id).
Plant(e) ==
    /\ AdvPlant /\ tampers < MaxTampers /\ e \notin planted
    /\ planted' = planted \cup {e} /\ tampers' = tampers + 1
    /\ UNCHANGED << sent, direct, dropped, committed, logStart, owner, writerVars, epoch, log, anchored,
                    refused, poisoned, dbUp, storeUp, faults >>

\* State that makes every write for a position fail while the database is up.
InducePoison(p) ==
    /\ AdvPoison /\ tampers < MaxTampers /\ p \notin poisoned
    /\ poisoned' = poisoned \cup {p} /\ tampers' = tampers + 1
    /\ UNCHANGED << sent, direct, dropped, committed, logStart, owner, writerVars, epoch, log, anchored,
                    refused, planted, dbUp, storeUp, faults >>

\* ... and remove that state again, so that a later writer's attempts succeed.
CurePoison(p) ==
    /\ AdvPoison /\ tampers < MaxTampers /\ p \in poisoned
    /\ poisoned' = poisoned \ {p} /\ tampers' = tampers + 1
    /\ UNCHANGED << sent, direct, dropped, committed, logStart, owner, writerVars, epoch, log, anchored,
                    refused, planted, dbUp, storeUp, faults >>

DropReceipts ==
    /\ AdvDropReceipts /\ ~dropped
    /\ dropped' = TRUE
    /\ UNCHANGED << sent, direct, committed, logStart, owner, writerVars, epoch, log, anchored, refused,
                    advVars, dbUp, storeUp, faults >>

(***************************************************************************)
(* Specification                                                           *)
(***************************************************************************)
Next ==
    \/ Submit
    \/ Expire \/ Anchor \/ DirectAck
    \/ \E c \in Consumers :
         \/ Decide(c) \/ AddRecord(c) \/ Commit(c) \/ Reset(c) \/ Assign(c)
         \/ Rebalance(c) \/ Crash(c)
    \/ DbDown \/ DbRecover \/ StoreDown \/ StoreRecover
    \/ TruncateTail \/ DropReceipts
    \/ \E i \in TailIdx, s \in Subs : ReplaceTail(i, s)
    \/ \E i \in TailIdx, p \in Positions : MisplaceTail(i, p)
    \/ \E e \in EventIds : Plant(e)
    \/ \E p \in Positions : InducePoison(p) \/ CurePoison(p)

Spec == Init /\ [][Next]_vars

\* The system keeps taking the steps it can take: writers work, the anchorer anchors, outages
\* end, a crashed owner is replaced. Faults and tampering are bounded, so they stop.
Fairness ==
    /\ \A c \in Consumers :
         /\ WF_vars(Decide(c)) /\ WF_vars(AddRecord(c)) /\ WF_vars(Commit(c))
         /\ WF_vars(Reset(c)) /\ WF_vars(Assign(c))
    /\ WF_vars(Anchor) /\ WF_vars(DbRecover) /\ WF_vars(StoreRecover)

LiveSpec == Spec /\ Fairness

(***************************************************************************)
(* Invariants                                                              *)
(***************************************************************************)
TypeOK ==
    /\ sent \in 0..NSubs /\ committed \in 0..sent /\ logStart \in 0..committed
    /\ direct \subseteq 1..sent
    /\ owner \in Consumers \cup {None} /\ dropped \in BOOLEAN /\ refused \in BOOLEAN
    /\ tampers \in 0..MaxTampers /\ faults \in 0..MaxFaults
    /\ \A c \in Consumers : Len(batch[c]) <= B

\* Per acknowledged submission: accounted, still in the broker, named by a receipt the sender
\* holds, or named by an anchored verdict that fails its check. A record still in the database
\* tail counts too, so that a counterexample shows the erasure step itself.
InTail(s) == \E i \in TailIdx : log[i].pos = s /\ log[i].sub = s
NoSilentLoss ==
    \A s \in 1..sent : AccountedOK(s) \/ Retained(s) \/ ~dropped \/ EvidenceFor(s) \/ InTail(s)

\* The content of every acknowledged submission is in the broker or in the store.
ContentPreserved ==
    \A s \in 1..sent :
        Retained(s) \/ \E i \in 1..Len(anchored) : anchored[i].sub = s /\ anchored[i].content

\* Every released offset has a record in the store.
CommitCovered ==
    \A x \in 1..committed : \E i \in 1..Len(anchored) : anchored[i].pos = x

\* With no adversary, no position appears twice in the database or the store, and
\* every released offset appears exactly once in the store.
ExactlyOnceHonest ==
    tampers = 0 =>
        /\ \A i, j \in 1..Len(log) : i # j => log[i].pos # log[j].pos
        /\ \A i, j \in 1..Len(anchored) : i # j => anchored[i].pos # anchored[j].pos
        /\ \A x \in 1..committed : \E i \in 1..Len(anchored) : anchored[i].pos = x

\* Positions strictly increase in the store.
MonotoneAnchored ==
    \A i, j \in 1..Len(anchored) : i < j => anchored[i].pos < anchored[j].pos

\* No non-membership proof exists for an accounted submission: no adjacent anchored pair
\* straddles its position, and its position is not above the last anchored one.
JudgeNonFrameable ==
    \A s \in 1..sent :
        AccountedOK(s) =>
            /\ s <= AnchoredLast
            /\ ~\E i \in 1..(Len(anchored) - 1) : anchored[i].pos < s /\ s < anchored[i + 1].pos

\* At most Beta acknowledged submissions are written off as UNCHECKABLE without a violation.
UnchkBounded ==
    Cardinality({ s \in 1..sent :
                    \E i \in 1..Len(anchored) : /\ anchored[i].pos = s /\ anchored[i].sub = s
                                                /\ anchored[i].kind = "UNCHK" /\ Justified(i) })
        <= Beta

(***************************************************************************)
(* Liveness (checked under LiveSpec, with no database adversary or a       *)
(* bounded one)                                                            *)
(***************************************************************************)
AckedEventuallyAccounted == \A s \in Subs : (s <= sent) ~> AccountedOK(s)

\* ... and the committed offset passes it. The committed offset is the watermark the period
\* statement reports: an offset that is never released turns every later statement into a
\* STALL for the partition, and the stall budget into a violation, for every later event.
EventuallyReleased == \A s \in Subs : (s <= sent) ~> (committed >= s)

=============================================================================
