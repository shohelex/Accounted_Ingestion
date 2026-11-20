--------------------------- MODULE AccountedLogs ----------------------------
(***************************************************************************)
(* Exactly once across the logs of one partition, each a tenant's log or   *)
(* the partition's system log. Accounted checks one log; this module       *)
(* checks what only several logs on one partition can show:                *)
(*   - writer epochs are per log and taken lazily: a new owner takes a     *)
(*     log's epoch (and resets that log's tail from the store) only before *)
(*     its first append to that log (processing/event_processor.py,        *)
(*     ensure_epoch), so a former owner keeps a valid epoch for every log  *)
(*     the new owner has not appended to yet;                              *)
(*   - a tail reset of one log keeps the other logs' coverage, and the     *)
(*     partition is fetched again from the committed offset;               *)
(*   - the commit is per partition, over records of every log;             *)
(*   - the anchorer of a log anchors only records it appended itself under *)
(*     its current epoch, so a record the database copies into another     *)
(*     log's tail is never anchored.                                       *)
(*                                                                         *)
(* A record is identified by its position: every writer builds the same    *)
(* record for a position, and the position's log is a function of the      *)
(* record's bytes (the tenant of a valid tag, else the system log).        *)
(* Position s belongs to log ((s - 1) % NLogs) + 1.                        *)
(*                                                                         *)
(* Deduplication is the code's rule (add_records): a template at a         *)
(* position at or below the last one appended to its log must find the     *)
(* identical record there, anchored or not; otherwise PositionConflict.    *)
(* Accounted dedups against the unanchored tail only, which is why         *)
(* fencing is needed there. Here that weaker rule fails even with fencing  *)
(* (LogsTailDedup), and with the code's rule fencing is not needed for     *)
(* exactly once (LogsNoFencing).                                           *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    NSubs,          \* submissions; submission s is the broker record at offset s
    NLogs,          \* logs on the partition
    Consumers,      \* writer processes that may own the partition
    B,              \* records a writer may decide ahead of appending them
    MaxFaults,      \* bound on crashes and rebalances
    MaxTampers,     \* bound on database-adversary actions (0 = none)
    \* rules of the design (TRUE; a must-fail configuration switches one off)
    Fencing,        \* the append checks the writer's epoch for the log
    FullDedup,      \* dedup against every position appended to the log (acct_last_json);
                    \* FALSE: only against the unanchored tail
    OwnAnchor,      \* anchor only records this process appended under its epoch
    RewindOnReset,  \* after a tail reset, fetch the partition again from the committed offset
    StaleEpochReset,\* an owner whose unanchored records of a log were appended under an epoch
                    \* another process has since taken resets that log, instead of only
                    \* forgetting the records (crypto/merkle_tree_storage.py, _own_current)
    \* what the adversary (the database) may do
    AdvTruncate,    \* delete a log's unanchored tail
    AdvPlant,       \* append to any log's tail a copy of a record it has seen
    AdvEpoch        \* answer the fencing check in favour of a stale epoch

ASSUME NSubs >= 1 /\ NLogs >= 1 /\ B >= 1

Subs == 1..NSubs
Logs == 1..NLogs
None == "none"
LogOf(s) == ((s - 1) % NLogs) + 1
Rec(p) == [pos |-> p, lg |-> LogOf(p)]

VARIABLES
    sent,       \* submissions acknowledged so far (after the broker's ack)
    committed,  \* offsets 1..committed are released
    owner,      \* the writer the group assigns the partition to, or None after a crash
    next,       \* [c -> next offset the writer fetches]
    batch,      \* [c -> offsets decided and not yet appended]
    mem,        \* [c -> set of [pos, seq]: seq > 0 the record's index in its log, -1 no match]
    own,        \* [c -> set of [lg, seq, pos]: records c appended since its last reset]
    myN,        \* [c -> [l -> the length of log l c knows it produced since its reset]]
    myEpoch,    \* [c -> [l -> c's epoch for log l, 0 if not taken since (re)acquisition]]
    epoch,      \* [l -> the writer epoch of log l in the database]
    conflict,   \* [c -> logs for which an append hit PositionConflict]
    log,        \* [l -> log l in the database: anchored prefix and unanchored tail]
    anchored,   \* [l -> log l in the write-once store]
    refused,    \* [l -> the anchorer refused log l's tail (AnchorTamper)]
    faults, tampers

vars == << sent, committed, owner, next, batch, mem, own, myN, myEpoch, epoch, conflict, log,
           anchored, refused, faults, tampers >>

(***************************************************************************)
(* Derived values                                                          *)
(***************************************************************************)
AnchoredLast(l) == IF anchored[l] = << >> THEN 0 ELSE anchored[l][Len(anchored[l])].pos
LastPos(l) == IF log[l] = << >> THEN 0 ELSE log[l][Len(log[l])].pos
TailIdx(l) == (Len(anchored[l]) + 1)..Len(log[l])
TailLast(l) == IF Len(log[l]) > Len(anchored[l]) THEN LastPos(l) ELSE 0
\* The dedup range: the last position appended to the log, or only the unanchored tail's.
DedupLast(l) == IF FullDedup THEN LastPos(l) ELSE TailLast(l)
DedupIdx(l) == IF FullDedup THEN 1..Len(log[l]) ELSE TailIdx(l)

\* Where position p is anchored: pairs <<log, index>>.
AnchoredAt(p) == { li \in UNION { {l} \X (1..Len(anchored[l])) : l \in Logs } :
                       anchored[li[1]][li[2]].pos = p }

ShortTail(c, l) == myEpoch[c][l] # 0 /\ Len(log[l]) < myN[c][l]

\* A coverage certificate: the store holds, at the record's seq, exactly the record c built.
Ok(c, p) ==
    LET l == LogOf(p) IN
    /\ ~ShortTail(c, l)
    /\ \E m \in mem[c] : m.pos = p /\ m.seq > 0 /\ m.seq <= Len(anchored[l])
                         /\ anchored[l][m.seq] = Rec(p)
NewW(c) == CHOOSE x \in committed..sent :
               /\ \A p \in (committed + 1)..x : Ok(c, p)
               /\ (x = sent \/ ~Ok(c, x + 1))

\* c's own unanchored records of l were appended under an epoch another process has since taken.
StaleOwn(c, l) ==
    /\ myEpoch[c][l] # 0 /\ myEpoch[c][l] # epoch[l]
    /\ \E o \in own[c] : o.lg = l /\ o.seq > Len(anchored[l])

Mismatch(c, l) ==
    \/ StaleEpochReset /\ StaleOwn(c, l)
    \/ l \in conflict[c]
    \/ refused[l]
    \/ \E m \in mem[c] : LogOf(m.pos) = l /\ m.seq > 0 /\ m.seq <= Len(anchored[l])
                         /\ anchored[l][m.seq] # Rec(m.pos)
    \/ ShortTail(c, l)

(***************************************************************************)
(* Initial state                                                           *)
(***************************************************************************)
NoLogs == [l \in Logs |-> 0]
Init ==
    /\ sent = 0 /\ committed = 0
    /\ owner = CHOOSE c \in Consumers : TRUE
    /\ next = [c \in Consumers |-> 1]
    /\ batch = [c \in Consumers |-> << >>]
    /\ mem = [c \in Consumers |-> {}]
    /\ own = [c \in Consumers |-> {}]
    /\ myN = [c \in Consumers |-> NoLogs]
    /\ myEpoch = [c \in Consumers |-> NoLogs]
    /\ epoch = [l \in Logs |-> 1]
    /\ conflict = [c \in Consumers |-> {}]
    /\ log = [l \in Logs |-> << >>] /\ anchored = [l \in Logs |-> << >>]
    /\ refused = [l \in Logs |-> FALSE]
    /\ faults = 0 /\ tampers = 0

(***************************************************************************)
(* The API                                                                 *)
(***************************************************************************)
Submit ==
    /\ sent < NSubs /\ sent' = sent + 1
    /\ UNCHANGED << committed, owner, next, batch, mem, own, myN, myEpoch, epoch, conflict, log,
                    anchored, refused, faults, tampers >>

(***************************************************************************)
(* Writers                                                                 *)
(***************************************************************************)
\* The owner fetches the next offset. A position its log has already anchored is verified
\* against the store instead of appended (verify_redelivery).
Decide(c) ==
    /\ c = owner /\ next[c] <= sent /\ Len(batch[c]) < B
    /\ LET p == next[c]
           l == LogOf(p)
       IN IF p <= AnchoredLast(l)
            THEN LET v == IF \E i \in 1..Len(anchored[l]) : anchored[l][i] = Rec(p)
                            THEN CHOOSE i \in 1..Len(anchored[l]) : anchored[l][i] = Rec(p)
                            ELSE -1
                 IN /\ mem' = [mem EXCEPT ![c] = @ \cup {[pos |-> p, seq |-> v]}]
                    /\ UNCHANGED batch
            ELSE /\ batch' = [batch EXCEPT ![c] = Append(@, p)]
                 /\ UNCHANGED mem
    /\ next' = [next EXCEPT ![c] = @ + 1]
    /\ UNCHANGED << sent, committed, owner, own, myN, myEpoch, epoch, conflict, log, anchored,
                    refused, faults, tampers >>

\* reset_tenant_tail on one log: the tail goes back to the store's anchored log, a new epoch is
\* taken, and c's memory of what it appended there is dropped. The other logs are untouched, and
\* so is c's coverage of their records.
ResetLog(c, l) ==
    /\ log' = [log EXCEPT ![l] = anchored[l]]
    /\ epoch' = [epoch EXCEPT ![l] = @ + 1]
    /\ myEpoch' = [myEpoch EXCEPT ![c][l] = epoch[l] + 1]
    /\ myN' = [myN EXCEPT ![c][l] = Len(anchored[l])]
    /\ own' = [own EXCEPT ![c] = { o \in @ : o.lg # l }]
    /\ conflict' = [conflict EXCEPT ![c] = @ \ {l}]
    /\ refused' = [refused EXCEPT ![l] = FALSE]
    /\ mem' = [mem EXCEPT ![c] = { m \in @ : \/ LogOf(m.pos) # l
                                           \/ /\ m.seq > 0 /\ m.seq <= Len(anchored[l])
                                              /\ anchored[l][m.seq] = Rec(m.pos) }]

\* ensure_epoch: before its first append to a log since it (re)acquired the partition (or since
\* it was fenced there), a process resets that log's tail and takes a new epoch. Any process
\* holding a batch may do it, including a former owner that has not noticed the rebalance.
TakeEpoch(c, l) ==
    /\ batch[c] # << >> /\ LogOf(Head(batch[c])) = l /\ myEpoch[c][l] = 0
    /\ ResetLog(c, l)
    /\ UNCHANGED << sent, committed, owner, next, batch, anchored, faults, tampers >>

\* add_records for the head of c's batch, in its log.
AddRecord(c) ==
    /\ batch[c] # << >>
    /\ LET p == Head(batch[c])
           l == LogOf(p)
           seq == Len(log[l]) + 1
       IN /\ myEpoch[c][l] # 0
          /\ IF Fencing /\ myEpoch[c][l] # epoch[l]
               THEN \* FencedWriter: drop the batch, read the partition again from the committed
                    \* offset, and take the log's epoch again before the next append to it
                    /\ batch' = [batch EXCEPT ![c] = << >>]
                    /\ next' = [next EXCEPT ![c] = committed + 1]
                    /\ myEpoch' = [myEpoch EXCEPT ![c][l] = 0]
                    /\ UNCHANGED << log, mem, own, myN, conflict >>
             ELSE IF ShortTail(c, l)
               THEN \* PositionConflict: records were removed under the writer
                    /\ batch' = [batch EXCEPT ![c] = << >>]
                    /\ conflict' = [conflict EXCEPT ![c] = @ \cup {l}]
                    /\ UNCHANGED << log, mem, own, myN, myEpoch, next >>
             ELSE IF p <= DedupLast(l)
               THEN IF \E i \in DedupIdx(l) : log[l][i] = Rec(p)
                      THEN \* the identical record is there: a redelivery or a zombie's retry
                           /\ mem' = [mem EXCEPT ![c] = @ \cup
                                        {[pos |-> p, seq |-> CHOOSE i \in DedupIdx(l) : log[l][i] = Rec(p)]}]
                           /\ batch' = [batch EXCEPT ![c] = Tail(@)]
                           /\ UNCHANGED << log, own, myN, myEpoch, conflict, next >>
                      ELSE \* PositionConflict
                           /\ batch' = [batch EXCEPT ![c] = << >>]
                           /\ conflict' = [conflict EXCEPT ![c] = @ \cup {l}]
                           /\ UNCHANGED << log, mem, own, myN, myEpoch, next >>
             ELSE /\ log' = [log EXCEPT ![l] = Append(@, Rec(p))]
                  /\ mem' = [mem EXCEPT ![c] = @ \cup {[pos |-> p, seq |-> seq]}]
                  /\ own' = [own EXCEPT ![c] = @ \cup {[lg |-> l, seq |-> seq, pos |-> p]}]
                  /\ myN' = [myN EXCEPT ![c][l] = @ + 1]
                  /\ batch' = [batch EXCEPT ![c] = Tail(@)]
                  /\ UNCHANGED << myEpoch, conflict, next >>
    /\ UNCHANGED << sent, committed, owner, epoch, anchored, refused, faults, tampers >>

\* Process c anchors a prefix of log l's tail. Positions must increase above the last
\* anchored one. With OwnAnchor, every record must be one c appended under its current epoch
\* for l; a segment that holds some of c's records and something else, or one of c's records
\* changed, is refused (AnchorTamper); one with none of c's records is left to its writer
\* (AnchorDeferred: not a step). Without OwnAnchor any process anchors any tail.
Anchor(c, l) ==
    /\ Len(log[l]) > Len(anchored[l]) /\ ~refused[l]
    /\ \E n \in (Len(anchored[l]) + 1)..Len(log[l]) :
       LET idx == (Len(anchored[l]) + 1)..n
           seg == SubSeq(log[l], Len(anchored[l]) + 1, n)
           inc == \A i \in 1..Len(seg) :
                     seg[i].pos > (IF i = 1 THEN AnchoredLast(l) ELSE seg[i - 1].pos)
           current == myEpoch[c][l] # 0 /\ myEpoch[c][l] = epoch[l]
           mine(i) == [lg |-> l, seq |-> i, pos |-> log[l][i].pos] \in own[c]
           ownSeq(i) == \E o \in own[c] : o.lg = l /\ o.seq = i
       IN /\ OwnAnchor => current /\ \E i \in idx : ownSeq(i)
          /\ IF inc /\ (OwnAnchor => \A i \in idx : mine(i))
               THEN /\ anchored' = [anchored EXCEPT ![l] = @ \o seg] /\ UNCHANGED refused
               ELSE /\ refused' = [refused EXCEPT ![l] = TRUE] /\ UNCHANGED anchored
    /\ UNCHANGED << sent, committed, owner, next, batch, mem, own, myN, myEpoch, epoch, conflict,
                    log, faults, tampers >>

\* The owner commits the partition over offsets it holds a certificate for.
Commit(c) ==
    /\ c = owner
    /\ \E x \in (committed + 1)..NewW(c) :
         /\ committed' = x
         /\ mem' = [mem EXCEPT ![c] = { m \in @ : m.pos > x }]
    /\ UNCHANGED << sent, owner, next, batch, own, myN, myEpoch, epoch, conflict, log, anchored,
                    refused, faults, tampers >>

\* The owner resets a log on a coverage mismatch, a position conflict, an anchorer refusal or a
\* short tail, and fetches the partition again from the committed offset.
Reset(c, l) ==
    /\ c = owner /\ Mismatch(c, l)
    /\ ResetLog(c, l)
    /\ IF RewindOnReset
         THEN /\ next' = [next EXCEPT ![c] = committed + 1]
              /\ batch' = [batch EXCEPT ![c] = << >>]
         ELSE UNCHANGED << next, batch >>
    /\ UNCHANGED << sent, committed, owner, anchored, faults, tampers >>

\* A new owner starts from the committed offset with no epoch for any log (they are taken lazily).
Acquire(c) ==
    /\ next' = [next EXCEPT ![c] = committed + 1]
    /\ batch' = [batch EXCEPT ![c] = << >>]
    /\ mem' = [mem EXCEPT ![c] = {}]
    /\ own' = [own EXCEPT ![c] = {}]
    /\ myN' = [myN EXCEPT ![c] = NoLogs]
    /\ myEpoch' = [myEpoch EXCEPT ![c] = NoLogs]
    /\ conflict' = [conflict EXCEPT ![c] = {}]

Assign(c) ==
    /\ owner = None /\ owner' = c /\ Acquire(c)
    /\ UNCHANGED << sent, committed, epoch, log, anchored, refused, faults, tampers >>

(***************************************************************************)
(* Faults                                                                  *)
(***************************************************************************)
\* The group moves the partition; the former owner keeps its batch and its epochs (a zombie).
Rebalance(c) ==
    /\ faults < MaxFaults /\ owner # None /\ c # owner
    /\ owner' = c /\ Acquire(c) /\ faults' = faults + 1
    /\ UNCHANGED << sent, committed, epoch, log, anchored, refused, tampers >>

Crash(c) ==
    /\ faults < MaxFaults /\ (c = owner \/ batch[c] # << >>)
    /\ owner' = IF owner = c THEN None ELSE owner
    /\ next' = [next EXCEPT ![c] = 1]
    /\ batch' = [batch EXCEPT ![c] = << >>]
    /\ mem' = [mem EXCEPT ![c] = {}]
    /\ own' = [own EXCEPT ![c] = {}]
    /\ myN' = [myN EXCEPT ![c] = NoLogs]
    /\ myEpoch' = [myEpoch EXCEPT ![c] = NoLogs]
    /\ conflict' = [conflict EXCEPT ![c] = {}]
    /\ faults' = faults + 1
    /\ UNCHANGED << sent, committed, epoch, log, anchored, refused, tampers >>

(***************************************************************************)
(* The adversary: the database. It holds no key and cannot touch the store *)
(* or the broker.                                                          *)
(***************************************************************************)
TruncateTail(l) ==
    /\ AdvTruncate /\ tampers < MaxTampers /\ Len(log[l]) > Len(anchored[l])
    /\ log' = [log EXCEPT ![l] = anchored[l]] /\ tampers' = tampers + 1
    /\ UNCHANGED << sent, committed, owner, next, batch, mem, own, myN, myEpoch, epoch, conflict,
                    anchored, refused, faults >>

\* A copy of the record of an acknowledged submission, in any log's tail (its own log's, where
\* dedup would have refused it, or another log's).
Plant(l, p) ==
    /\ AdvPlant /\ tampers < MaxTampers /\ p \in 1..sent
    /\ log' = [log EXCEPT ![l] = Append(@, Rec(p))] /\ tampers' = tampers + 1
    /\ UNCHANGED << sent, committed, owner, next, batch, mem, own, myN, myEpoch, epoch, conflict,
                    anchored, refused, faults >>

\* The epoch row of log l takes the (stale) epoch a process holds, so that its fencing check
\* passes.
ForgeEpoch(l, c) ==
    /\ AdvEpoch /\ tampers < MaxTampers /\ myEpoch[c][l] # 0 /\ myEpoch[c][l] # epoch[l]
    /\ epoch' = [epoch EXCEPT ![l] = myEpoch[c][l]] /\ tampers' = tampers + 1
    /\ UNCHANGED << sent, committed, owner, next, batch, mem, own, myN, myEpoch, conflict, log,
                    anchored, refused, faults >>

(***************************************************************************)
(* Specification                                                           *)
(***************************************************************************)
Next ==
    \/ Submit
    \/ \E c \in Consumers :
         \/ Decide(c) \/ AddRecord(c) \/ Commit(c) \/ Assign(c) \/ Rebalance(c) \/ Crash(c)
         \/ \E l \in Logs : TakeEpoch(c, l) \/ Anchor(c, l) \/ Reset(c, l)
    \/ \E l \in Logs : \/ TruncateTail(l)
                       \/ \E p \in Subs : Plant(l, p)
                       \/ \E c \in Consumers : ForgeEpoch(l, c)

Spec == Init /\ [][Next]_vars

Fairness ==
    \A c \in Consumers :
        /\ WF_vars(Decide(c)) /\ WF_vars(AddRecord(c)) /\ WF_vars(Commit(c)) /\ WF_vars(Assign(c))
        /\ \A l \in Logs : WF_vars(TakeEpoch(c, l)) /\ WF_vars(Anchor(c, l)) /\ WF_vars(Reset(c, l))

LiveSpec == Spec /\ Fairness

(***************************************************************************)
(* Properties                                                              *)
(***************************************************************************)
TypeOK ==
    /\ sent \in 0..NSubs /\ committed \in 0..sent
    /\ owner \in Consumers \cup {None}
    /\ faults \in 0..MaxFaults /\ tampers \in 0..MaxTampers
    /\ \A c \in Consumers : Len(batch[c]) <= B

\* With an honest database: no position twice in any log, no record in a log
\* other than its own, and every released offset anchored exactly once across all logs.
ExactlyOnceHonest ==
    tampers = 0 =>
        /\ \A l \in Logs : \A i, j \in 1..Len(log[l]) : i # j => log[l][i].pos # log[l][j].pos
        /\ \A l \in Logs : \A i \in 1..Len(log[l]) : log[l][i].lg = l
        /\ \A x \in 1..committed : Cardinality(AnchoredAt(x)) = 1

\* With the database corrupted too: no position is anchored twice, and none outside its own
\* log.
AtMostOnceAnchored ==
    \A p \in Subs : /\ Cardinality(AnchoredAt(p)) <= 1
                    /\ \A li \in AnchoredAt(p) : li[1] = LogOf(p)

\* Every released offset is anchored in its own log.
CommitCovered ==
    \A x \in 1..committed : \E i \in 1..Len(anchored[LogOf(x)]) : anchored[LogOf(x)][i] = Rec(x)

\* Per log, positions strictly increase in the store.
MonotoneAnchored ==
    \A l \in Logs : \A i, j \in 1..Len(anchored[l]) : i < j => anchored[l][i].pos < anchored[l][j].pos

\* Every acknowledged submission is eventually released (and so anchored in its log).
EventuallyReleased == \A s \in Subs : (s <= sent) ~> (committed >= s)

=============================================================================
