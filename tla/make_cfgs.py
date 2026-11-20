import os
os.chdir(os.path.dirname(os.path.abspath(__file__)))

INGEST_BASE = dict(Events="{e1, e2, e3, e4}", Poison="{}", Consumers="{c1, c2}", K=2, B=2,
                   MaxRedeliveries=1, MaxFaults=2, AppendLock="TRUE", AnchorViaTip="TRUE",
                   CountOutageFail="FALSE", Fsync="TRUE", AuthTip="TRUE", AdoptStore="TRUE",
                   Heartbeat="TRUE", MaxTampers=0, AdvClearsPending="FALSE")
INGEST_RULES = ["AppendLock", "AnchorViaTip", "CountOutageFail", "Fsync", "AuthTip", "AdoptStore",
                "Heartbeat"]
INGEST_SAFETY = ["TypeOK", "SingleWriter", "OnlyPoisonSkipped", "NoLostAcked", "ChainLinear", "GapBound",
                 "TailBound", "EvidenceAtQuiescence"]
INGEST_LIVE = ["AckedEventuallyDurable", "AckedEventuallyAnchored"]

# name: (comment, overrides, invariants, properties, expected: None = OK, else the properties
# of which TLC must report one as violated)
INGEST_CFGS = {
    # every rule on
    "Contract": ("Every rule on, crash faults only: every invariant must hold.",
                 dict(MaxFaults=3), INGEST_SAFETY, [], None),
    "Poison": ("Every rule on, one poison record.",
               dict(Events="{e1, e2, e3}", Poison="{e2}", MaxFaults=2), INGEST_SAFETY, [], None),
    "Adversary": ("Every rule on, and an adversary who forges or replays the chain tip in the "
                  "database: every invariant must still hold.",
                  dict(Events="{e1, e2, e3, e4}", MaxFaults=1, MaxTampers=2), INGEST_SAFETY, [], None),
    "Liveness": ("Every rule on, fair scheduling, crash faults and a tip adversary: an acknowledged "
                 "event ends up durable and under an anchor.",
                 dict(Events="{e1, e2, e3}", MaxFaults=1, MaxTampers=1), ["TypeOK"], INGEST_LIVE, None),
    "LivenessPoison": ("As Liveness, with a poison record ahead of a good one.",
                       dict(Events="{e1, e2, e3}", Poison="{e1}", MaxFaults=1, MaxTampers=0),
                       ["TypeOK"], INGEST_LIVE, None),
    # one rule off: each must fail
    "NoAppendLock": ("AppendLock off: no database lock on the append, two appends read the same state.",
                     dict(AppendLock="FALSE"), ["SingleWriter"], [], ["SingleWriter"]),
    "NoAnchorTip": ("AnchorViaTip off: anchors chain to a per-process cache instead of the tip in the "
                    "database, and the chain forks.",
                    dict(AnchorViaTip="FALSE"), ["ChainLinear"], [], ["ChainLinear"]),
    "CountDuringOutage": ("CountOutageFail on: the poison guard counts failures that happened during a "
                          "database outage.",
                          dict(Events="{e1, e2, e3}", CountOutageFail="TRUE"), ["OnlyPoisonSkipped"], [],
                          ["OnlyPoisonSkipped"]),
    "NoFsync": ("Fsync off: the broker acknowledges before flushing.",
                dict(Events="{e1, e2, e3}", Fsync="FALSE"), ["NoLostAcked"], [], ["NoLostAcked"]),
    "NoAuthTip": ("AuthTip off: the writer believes whatever tip the database holds; a forged tip makes "
                  "it chain a write-once record to a head that does not exist (ChainLinear), or stop "
                  "anchoring (TailBound).",
                  dict(AuthTip="FALSE", MaxFaults=0, MaxTampers=1), ["ChainLinear", "TailBound"], [],
                  ["ChainLinear", "TailBound"]),
    "NoAdoptStore": ("AdoptStore off: the writer does not ask the store for a newer record, and a "
                     "replayed, genuinely signed tip forks the chain.",
                     dict(AdoptStore="FALSE", MaxFaults=0, MaxTampers=1), ["ChainLinear"], [],
                     ["ChainLinear"]),
    "NoHeartbeat": ("Heartbeat off: no time-based anchoring, and the last leaves of a tenant that goes "
                    "quiet below a multiple of K are never anchored.",
                    dict(Events="{e1, e2, e3}", Heartbeat="FALSE", MaxFaults=0), ["TypeOK"],
                    ["AckedEventuallyAnchored"], ["AckedEventuallyAnchored"]),
    # a limit of the design: fails with every rule on
    "ClearPending": ("Every rule on, and an adversary who clears a snapshot's pending flag. No writer "
                     "rule prevents this. The violation is the evidence: a gap wider than K + B - 1 in a "
                     "write-once chain, which the verifier reports (gaps_over_window).",
                     dict(MaxFaults=0, MaxTampers=1, AdvClearsPending="TRUE"), ["GapBound"], [],
                     ["GapBound"]),
}

ACCT_BASE = dict(NSubs=3, SameEid="TRUE", SameContent="TRUE", Malformed="{3}",
                 Consumers="{c1, c2}", B=1, MaxFaults=2, MaxTampers=0, Beta=1,
                 AckAfterBroker="TRUE", EarlierReferent="TRUE", CAA="TRUE", CoverageCheck="TRUE",
                 Verdicts="TRUE", ContentInVerdict="TRUE", PositionDedup="TRUE", TailReset="TRUE",
                 TailCheck="TRUE", TailCheckPoll="TRUE", Fencing="TRUE", AnchorerCheck="TRUE",
                 CountUnchk="TRUE", AdoptUnchk="TRUE", FreshRedelivery="TRUE",
                 AdvTruncate="FALSE", AdvReplace="FALSE", AdvMisplace="FALSE", AdvPlant="FALSE",
                 AdvPoison="FALSE", AdvDropReceipts="FALSE", Outages="TRUE")
ACCT_RULES = ["AckAfterBroker", "EarlierReferent", "CAA", "CoverageCheck", "Verdicts", "ContentInVerdict",
              "PositionDedup", "TailReset", "TailCheck", "TailCheckPoll", "Fencing", "AnchorerCheck",
              "CountUnchk", "AdoptUnchk", "FreshRedelivery"]
ACCT_SAFETY = ["TypeOK", "NoSilentLoss", "ContentPreserved", "CommitCovered", "ExactlyOnceHonest",
               "MonotoneAnchored", "JudgeNonFrameable", "UnchkBounded"]
ACCT_LIVE = ["AckedEventuallyAccounted", "EventuallyReleased"]
ALL_ADV = dict(AdvTruncate="TRUE", AdvReplace="TRUE", AdvMisplace="TRUE", AdvPlant="TRUE",
               AdvPoison="TRUE", AdvDropReceipts="TRUE")
DISTINCT = dict(SameEid="FALSE", Malformed="{}")          # three unrelated submissions

ACCT_CFGS = {
    # every rule on
    "AcctContract": ("Every rule on; a retry (submissions 1 and 2), a malformed record, crashes, "
                     "rebalances and outages; no adversary: every invariant must hold.",
                     dict(NSubs=6, B=3, MaxFaults=4), ACCT_SAFETY, [], None),
    "AcctCollide": ("Every rule on; submissions 1 and 2 share an event id with different content "
                    "(a collision or a squat): every invariant must hold.",
                    dict(SameContent="FALSE", Malformed="{}", NSubs=6, B=3, MaxFaults=4),
                    ACCT_SAFETY, [], None),
    "AcctAdversary": ("Every rule on; the sender discards its receipts and the database truncates, "
                      "rewrites, misplaces, plants and poisons (two actions): every invariant must "
                      "hold.",
                      dict(ALL_ADV, NSubs=4, MaxTampers=2, MaxFaults=2), ACCT_SAFETY, [], None),
    "AcctLiveness": ("Every rule on, fair scheduling, crashes, rebalances and outages: every "
                     "acknowledged submission ends up accounted.",
                     dict(NSubs=4, B=2, MaxFaults=3), ["TypeOK"], ACCT_LIVE, None),
    "AcctLivenessTruncate": ("As AcctLiveness, with a database that truncates the tail once and a "
                             "crash: still every acknowledged submission ends up accounted.",
                             dict(AdvTruncate="TRUE", MaxTampers=1, MaxFaults=2), ["TypeOK"],
                             ACCT_LIVE, None),
    "AcctLivenessPoison": ("As AcctLiveness, with a database that makes the writes of a record "
                           "fail until it is written off as UNCHECKABLE, and then lets them "
                           "succeed, and a crash: the record is accounted once, by the verdict "
                           "(poison within Beta).",
                           dict(DISTINCT, AdvPoison="TRUE", MaxTampers=2, Beta=2, MaxFaults=1,
                                Outages="FALSE"), ["TypeOK"], ACCT_LIVE, None),
    # one rule off: each must fail
    "NoAckAfterBroker": ("AckAfterBroker off: the direct fallback acknowledges a submission it "
                         "wrote only to the database. The database truncates the tail and the sender "
                         "discards the receipt: nothing names the event.",
                         dict(DISTINCT, AckAfterBroker="FALSE", AdvTruncate="TRUE",
                              AdvDropReceipts="TRUE", MaxTampers=1, NSubs=1, MaxFaults=0),
                         ["NoSilentLoss"], [], ["NoSilentLoss"]),
    "NoEarlierReferent": ("EarlierReferent off: the event-id index may return the record at "
                          "the position being decided. A redelivered, anchored event becomes a DUP "
                          "of itself, which never matches the store, and the offset is never "
                          "released.",
                          dict(DISTINCT, EarlierReferent="FALSE", MaxFaults=1, Outages="FALSE"),
                          ["TypeOK"], ["EventuallyReleased"], ["EventuallyReleased"]),
    "NoCAA": ("CAA off: the offset is committed once the record is in the database (the standard "
              "crash-safe rule). The database truncates the tail, retention deletes the released "
              "record, the sender discards the receipt.",
              dict(DISTINCT, CAA="FALSE", AdvTruncate="TRUE", AdvDropReceipts="TRUE", MaxTampers=1,
                   NSubs=2, MaxFaults=0), ["NoSilentLoss"], [], ["NoSilentLoss"]),
    "NoCoverageCheck": ("CoverageCheck off: a record at the position is enough to commit. The "
                        "database substitutes another submission's record before it is anchored.",
                        dict(DISTINCT, CoverageCheck="FALSE", AdvReplace="TRUE",
                             AdvDropReceipts="TRUE", MaxTampers=1, NSubs=2, MaxFaults=0),
                        ["NoSilentLoss", "ContentPreserved"], [], ["NoSilentLoss", "ContentPreserved"]),
    "NoVerdicts": ("Verdicts off: a skip leaves no record and counts as done. Planted state or "
                   "induced poison suppresses an acknowledged event.",
                   dict(DISTINCT, Verdicts="FALSE", AdvPlant="TRUE", AdvPoison="TRUE",
                        AdvDropReceipts="TRUE", MaxTampers=1, NSubs=2, MaxFaults=0),
                   ["NoSilentLoss"], [], ["NoSilentLoss"]),
    "NoContentInVerdict": ("ContentInVerdict off: verdicts carry the tag but not the content. An "
                           "index lie produces an unjustified verdict: detected, but the content "
                           "is gone once the broker releases the record.",
                           dict(DISTINCT, ContentInVerdict="FALSE", AdvPlant="TRUE", MaxTampers=1,
                                NSubs=2, MaxFaults=0), ["ContentPreserved"], [], ["ContentPreserved"]),
    "ContentDedup": ("PositionDedup off: leaves are deduplicated by their content-derived id. "
                     "A planted leaf with the victim's id makes the append a no-op.",
                     dict(DISTINCT, PositionDedup="FALSE", AdvPlant="TRUE", AdvDropReceipts="TRUE",
                          MaxTampers=1, NSubs=2, MaxFaults=0), ["NoSilentLoss"], [], ["NoSilentLoss"]),
    "NoTailReset": ("TailReset off: the owner never rebuilds the tail from the store. After the "
                    "database truncates it, the owner cannot append or commit again.",
                    dict(TailReset="FALSE", AdvTruncate="TRUE", MaxTampers=1, MaxFaults=1,
                         Outages="FALSE"), ["TypeOK"], ACCT_LIVE, ACCT_LIVE),
    "NoTailCheck": ("TailCheck off: the owner appends to a tail the database has cut. The next "
                    "anchor has a hole where the deleted records were, which no replay can fill.",
                    dict(TailCheck="FALSE", AdvTruncate="TRUE", MaxTampers=1, MaxFaults=1,
                         Outages="FALSE"), ["TypeOK"], ACCT_LIVE, ACCT_LIVE),
    "NoTailCheckPoll": ("TailCheckPoll off: only the append checks the tail's length. A writer "
                        "that has nothing left to append after the database cut its tail never "
                        "resets, and the committed offset never passes the removed records.",
                        dict(TailCheckPoll="FALSE", AdvTruncate="TRUE", MaxTampers=1, MaxFaults=1,
                             Outages="FALSE"), ["TypeOK"], ACCT_LIVE, ACCT_LIVE),
    "NoFreshRedelivery": ("FreshRedelivery off: a redelivered position the store already holds as "
                          "an event record is decided with the redelivery counter. Failures "
                          "induced after the anchor make the new owner build UNCHECKABLE, which "
                          "never matches the store.",
                          dict(DISTINCT, FreshRedelivery="FALSE", AdvPoison="TRUE", MaxTampers=1,
                               MaxFaults=1, Outages="FALSE"), ["TypeOK"], ["EventuallyReleased"],
                          ["EventuallyReleased"]),
    "NoAdoptUnchk": ("AdoptUnchk off: a new owner whose writes of a record succeed does not "
                     "accept the anchored UNCHECKABLE verdict for it. The record stays accounted, "
                     "but the committed offset never passes it again.",
                     dict(DISTINCT, AdoptUnchk="FALSE", AdvPoison="TRUE", MaxTampers=2, Beta=2,
                          MaxFaults=1, Outages="FALSE"), ["TypeOK"], ["EventuallyReleased"],
                     ["EventuallyReleased"]),
    "NoFencing": ("Fencing off: after a rebalance the former owner appends a record it decided "
                  "earlier, and the position is in the log twice.",
                  dict(DISTINCT, Fencing="FALSE", Outages="FALSE"), ["ExactlyOnceHonest"], [],
                  ["ExactlyOnceHonest"]),
    "NoAnchorerCheck": ("AnchorerCheck off: the anchorer anchors a tail whose positions do not "
                        "increase.",
                        dict(DISTINCT, AnchorerCheck="FALSE", AdvMisplace="TRUE", MaxTampers=1,
                             MaxFaults=0), ["MonotoneAnchored"], [], ["MonotoneAnchored"]),
    "NoAnchorerCheckFrame": ("AnchorerCheck off, checking only JudgeNonFrameable: the anchored "
                             "data then proves the non-membership of a submission that is "
                             "accounted.",
                             dict(DISTINCT, AnchorerCheck="FALSE", AdvMisplace="TRUE",
                                  MaxTampers=1, MaxFaults=0), ["JudgeNonFrameable"], [],
                             ["JudgeNonFrameable"]),
    "NoUnchkBudget": ("CountUnchk off: UNCHECKABLE verdicts are always accepted. Induced poison "
                      "writes off more than Beta acknowledged events.",
                      dict(DISTINCT, CountUnchk="FALSE", AdvPoison="TRUE", MaxTampers=2,
                           MaxFaults=0), ["UnchkBounded"], [], ["UnchkBounded"]),
}

PERIOD_BASE = dict(NE=3, NParts=2, NP=6, E=1, WE=3, Honest="TRUE", MakerIgnoresW="FALSE",
                   NoBudget="FALSE", LateAccepted="FALSE", PartialHeadAccepted="FALSE",
                   SilenceExcused="FALSE", CoTenants="FALSE", NoHeld="FALSE", HeldFree="FALSE",
                   SlowSend="FALSE", PartitionFromComplaint="FALSE")
PERIOD_RULES = ["MakerIgnoresW", "NoBudget", "LateAccepted", "PartialHeadAccepted",
                "SilenceExcused", "NoHeld", "HeldFree", "SlowSend", "PartitionFromComplaint"]
# Two tenants on one partition: events 1 and 2 are tenant 1's, 3 and 4 tenant 2's.
COTENANT = dict(CoTenants="TRUE", NE=4, NParts=1)
PERIOD_ALL = ["TypeOK", "JudgeSound", "JudgeComplete", "BudgetAccountable"]
# One partition keeps a dishonest promisor's choices small and still allows every kind of
# statement ("ok", "stall", "missing", late, none) and a shared window between the two events.
DISHONEST = dict(Honest="FALSE", NParts=1, NE=2, NP=5)

PERIOD_CFGS = {
    "PeriodContract": ("Honest promisor, any accounting delays: the judge is fair, complete and "
                       "budget-accountable.", dict(), PERIOD_ALL, [], None),
    "PeriodDishonest": ("A dishonest promisor posts anything, or nothing, in every period: the "
                        "judge is still complete and budget-accountable.",
                        DISHONEST, ["TypeOK", "JudgeComplete", "BudgetAccountable"], [], None),
    "NoBudget": ("The judge has no stall budget: a promisor that declares a stall in every period "
                 "is never violated.",
                 dict(DISHONEST, NoBudget="TRUE"), ["JudgeComplete", "BudgetAccountable"], [],
                 ["JudgeComplete", "BudgetAccountable"]),
    "LateDeclarations": ("The judge accepts a stall posted after the deadline: an excuse in "
                         "hindsight.",
                         dict(DISHONEST, LateAccepted="TRUE"), ["JudgeComplete"], [],
                         ["JudgeComplete"]),
    "PartialHead": ("The judge takes a HEAD that leaves the partition out as covering it: a "
                    "selective delay passes as met.",
                    dict(DISHONEST, PartialHeadAccepted="TRUE"), ["JudgeComplete"], [],
                    ["JudgeComplete"]),
    "MakerIgnoresW": ("The honest maker posts a HEAD whatever the backlog (no status rule): an "
                      "honest deployment is blamed for a delay within budget.",
                      dict(MakerIgnoresW="TRUE"), ["JudgeSound"], [], ["JudgeSound"]),
    "PeriodCoTenant": ("Honest promisor, two tenants on one partition: a tenant stalled only by "
                       "a co-tenant over its fair share is held, and is never blamed within its "
                       "own budget.", COTENANT, PERIOD_ALL, [], None),
    "NoHeld": ("The judge charges a held stall to the tenant's budget window: a co-tenant's flood "
               "spends an honest tenant's budget, and the deployment is blamed.",
               dict(COTENANT, NoHeld="TRUE"), ["JudgeSound"], [], ["JudgeSound"]),
    "HeldFree": ("The judge does not count held stalls toward the per-event bound: a promisor "
                 "that calls every stall held is never violated.",
                 dict(DISHONEST, HeldFree="TRUE"), ["JudgeComplete", "BudgetAccountable"], [],
                 ["JudgeComplete", "BudgetAccountable"]),
    "SilenceExcused": ("The judge counts a missing statement as a stall: silence becomes an "
                       "excuse.",
                       dict(DISHONEST, SilenceExcused="TRUE"), ["JudgeComplete"], [],
                       ["JudgeComplete"]),
    "SlowSend": ("Send bound broken: an acknowledged record may reach the broker after the statement "
                 "of its due period read the committed offset and the high watermark. The honest "
                 "maker posts a HEAD that does not cover it, and the deployment is blamed.",
                 dict(SlowSend="TRUE"), ["JudgeSound"], [], ["JudgeSound"]),
    "PartitionFromComplaint": ("The judge takes the partition from the complaint instead of "
                               "computing the tenant's partition from the contract: a complainant "
                               "points a stalled tenant at another partition's HEAD, and an honest "
                               "deployment is blamed.",
                               dict(PartitionFromComplaint="TRUE"), ["JudgeSound"], [],
                               ["JudgeSound"]),
}


# AccountedChain.tla. NoSuccSlotLockHeld holds with SuccSlot off: the lock is honoured and
# store reads are complete.
CHAIN_BASE = dict(Anchorers="{c1, c2, c3}", MaxN=4, MaxFaults=2, SuccSlot="TRUE",
                  SlotCompletion="TRUE", AdvLock="TRUE", AdvWithhold="TRUE")
CHAIN_RULES = ["SuccSlot", "SlotCompletion"]
CHAIN_SAFETY = ["TypeOK", "NoFork", "SingleChain"]
CHAIN_CFGS = {
    "ChainContract": ("Every rule on; three anchorers of one tenant, a database that grants the "
                      "tip lock to all of them, a store that withholds records from listings, "
                      "and crashes: the valid anchor records form one chain.",
                      dict(), CHAIN_SAFETY, [], None),
    "ChainLiveness": ("As ChainContract, with fair scheduling: every anchorer's records end up "
                      "under an anchor, including after a crash between the slot claim and the "
                      "record write.",
                      dict(Anchorers="{c1, c2}", MaxN=3), ["TypeOK"], ["AnchoringDone"], None),
    "NoSuccSlot": ("SuccSlot off: two anchorers inside a lock the database granted twice both "
                   "chain to the same predecessor, even with complete store reads.",
                   dict(Anchorers="{c1, c2}", MaxN=3, SuccSlot="FALSE", AdvWithhold="FALSE",
                        MaxFaults=0), ["NoFork", "SingleChain"], [], ["NoFork", "SingleChain"]),
    "NoSuccSlotWithhold": ("SuccSlot off, the lock honoured: a store that withholds the newest "
                           "record from a listing makes the next anchorer chain around it.",
                           dict(Anchorers="{c1, c2}", MaxN=3, SuccSlot="FALSE", AdvLock="FALSE",
                                MaxFaults=0), ["NoFork", "SingleChain"], [],
                           ["NoFork", "SingleChain"]),
    "NoSuccSlotLockHeld": ("SuccSlot off, the lock honoured and store reads complete: the "
                           "design without the slot is safe only under those two assumptions.",
                           dict(SuccSlot="FALSE", AdvLock="FALSE", AdvWithhold="FALSE"),
                           CHAIN_SAFETY, [], None),
    "NoSlotCompletion": ("SlotCompletion off: an anchorer that crashed between claiming the slot "
                         "and writing the record leaves a slot nobody can get past.",
                         dict(Anchorers="{c1, c2}", MaxN=3, SlotCompletion="FALSE", MaxFaults=1),
                         ["TypeOK"], ["AnchoringDone"], ["AnchoringDone"]),
}


# AccountedLogs.tla. LogsNoFencing holds with a rule off: with the code's deduplication,
# fencing is not what keeps a position out of a log twice.
LOGS_BASE = dict(NSubs=4, NLogs=2, Consumers="{c1, c2}", B=2, MaxFaults=2, MaxTampers=0,
                 Fencing="TRUE", FullDedup="TRUE", OwnAnchor="TRUE", RewindOnReset="TRUE",
                 StaleEpochReset="TRUE", AdvTruncate="FALSE", AdvPlant="FALSE", AdvEpoch="FALSE")
LOGS_RULES = ["Fencing", "FullDedup", "OwnAnchor", "RewindOnReset", "StaleEpochReset"]
LOGS_SAFETY = ["TypeOK", "ExactlyOnceHonest", "AtMostOnceAnchored", "CommitCovered",
               "MonotoneAnchored"]
LOGS_LIVE = ["EventuallyReleased"]
LOGS_CFGS = {
    "LogsContract": ("Every rule on; two logs on one partition, a zombie after a rebalance, "
                     "crashes: every position anchored once, in its own log.",
                     dict(), LOGS_SAFETY, [], None),
    "LogsAdversary": ("Every rule on; the database truncates tails, plants copies of records in "
                      "any log and forges epochs (two actions): still no position anchored "
                      "twice or outside its own log.",
                      dict(MaxFaults=1, MaxTampers=2, AdvTruncate="TRUE", AdvPlant="TRUE",
                           AdvEpoch="TRUE"), LOGS_SAFETY, [], None),
    "LogsLiveness": ("Every rule on, fair scheduling, crashes and rebalances: every "
                     "acknowledged submission is released.",
                     dict(NSubs=3), ["TypeOK"], LOGS_LIVE, None),
    "LogsLivenessTruncate": ("As LogsLiveness, with a database that truncates a tail once.",
                             dict(NSubs=3, MaxFaults=1, MaxTampers=1, AdvTruncate="TRUE"),
                             ["TypeOK"], LOGS_LIVE, None),
    "LogsTailDedup": ("FullDedup off: a template is deduplicated only against the unanchored "
                      "tail. A former owner that still holds a valid epoch for a log anchors the "
                      "record first; the new owner's copy follows it into the log, with fencing on.",
                      dict(FullDedup="FALSE"), ["ExactlyOnceHonest"], [], ["ExactlyOnceHonest"]),
    "LogsNoOwnAnchor": ("OwnAnchor off: any process anchors any tail. A copy the database plants "
                        "in another log's tail is anchored there.",
                        dict(OwnAnchor="FALSE", AdvPlant="TRUE", MaxTampers=1, MaxFaults=0),
                        ["AtMostOnceAnchored"], [], ["AtMostOnceAnchored"]),
    "LogsNoRewind": ("RewindOnReset off: after a tail reset the owner goes on fetching where it "
                     "was, and the records the reset removed are never fetched again.",
                     dict(NSubs=3, RewindOnReset="FALSE", MaxFaults=0, MaxTampers=1,
                          AdvTruncate="TRUE"), ["TypeOK"], LOGS_LIVE, LOGS_LIVE),
    "LogsNoStaleEpochReset": ("StaleEpochReset off: a former owner takes the epoch of a log the "
                              "new owner has appended to, appends there and crashes; the new owner "
                              "forgets its own records, nobody anchors the tail, and the partition "
                              "is never released.",
                              dict(NSubs=3, StaleEpochReset="FALSE"), ["TypeOK"], LOGS_LIVE,
                              LOGS_LIVE),
    "LogsNoFencing": ("Fencing off, with the code's deduplication: exactly once still holds. "
                      "Fencing is not what keeps a position out of a log twice here (compare "
                      "NoFencing in Accounted, which deduplicates against the unanchored "
                      "tail only, and LogsTailDedup).",
                      dict(Fencing="FALSE"), LOGS_SAFETY, [], None),
}

# MakerTiming.tla. Dpub = 16 ticks and clocks within 1 tick give an inclusion bound of
# Dpub/4 - 2 Skew = 2 ticks. MakerSlowLog breaks that assumption, not a rule, and must fail.
MAKER_BASE = dict(Makers='{"m1", "m2"}', Live='"m1"', Dpub=16, Incl=2, Skew=1, StoreBy="TRUE",
                  OutageFrom="TRUE", LogCheck="TRUE", StoreLock="TRUE")
MAKER_RULES = ["StoreBy", "OutageFrom", "LogCheck", "StoreLock"]
MAKER_SAFETY = ["TypeOK", "NoEquivocation", "NotSilent"]
MAKER_CFGS = {
    "MakerTiming": ("Every rule on; two makers with skewed clocks, a store that may refuse any "
                    "of them at any time, inclusion within Dpub/4 - 2 Skew: one body per period, "
                    "included by the deadline.", dict(), MAKER_SAFETY, [], None),
    "MakerNoStoreBy": ("StoreBy off: a regular body may be stored and submitted at any time. A "
                       "maker that reaches the store late posts it after another posted the "
                       "outage body.", dict(StoreBy="FALSE"), ["NoEquivocation"], [],
                       ["NoEquivocation"]),
    "MakerOutageEarly": ("OutageFrom off: the outage body from Dpub/2. A regular body submitted "
                         "just before Dpub/2 is not yet on the log when another maker checks.",
                         dict(OutageFrom="FALSE"), ["NoEquivocation"], [], ["NoEquivocation"]),
    "MakerNoLogCheck": ("LogCheck off: the outage body is posted without looking at the log.",
                        dict(LogCheck="FALSE"), ["NoEquivocation"], [], ["NoEquivocation"]),
    "MakerNoStoreLock": ("StoreLock off: each maker submits the body it built, without put_once.",
                         dict(StoreLock="FALSE"), ["NoEquivocation"], [], ["NoEquivocation"]),
    "MakerSlowLog": ("Every rule on, but the public log is slower than assumed (Dpub/4 - 2 Skew "
                     "+ 1 tick): an honest deployment posts two bodies for one period.",
                     dict(Incl=3), ["NoEquivocation"], [], ["NoEquivocation"]),
}

# Rows whose outcome does not follow the one-rule-off discipline, with the reason in their comment.
EXCEPTIONS = {"ClearPending", "NoSuccSlotLockHeld", "LogsNoFencing", "MakerSlowLog"}


def write(module, base, rules, table):
    order = list(base)
    for name, (why, over, invs, props, expect) in table.items():
        off = [r for r in rules if r in over and over[r] != base[r]]
        assert len(off) <= 1, f"{name} changes more than one rule: {off}"
        assert (expect is None) == (not off) or name in EXCEPTIONS, name
        c = dict(base, **over)
        out = [f"\\* {why}",
               "\\* EXPECT: " + ("OK" if expect is None else "FAIL " + " ".join(expect)),
               f"\\* MODULE: {module}",
               "SPECIFICATION " + ("LiveSpec" if props else "Spec"), "CONSTANTS"]
        out += [f"    {k} = {c[k]}" for k in order]
        out += ["INVARIANTS"] + [f"    {i}" for i in invs]
        if props:
            out += ["PROPERTIES"] + [f"    {p}" for p in props]
        out += ["CHECK_DEADLOCK FALSE", ""]
        with open(name + ".cfg", "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(out))
        print("wrote", name + ".cfg")


write("Ingest", INGEST_BASE, INGEST_RULES, INGEST_CFGS)
write("Accounted", ACCT_BASE, ACCT_RULES, ACCT_CFGS)
write("AccountedChain", CHAIN_BASE, CHAIN_RULES, CHAIN_CFGS)
write("Period", PERIOD_BASE, PERIOD_RULES, PERIOD_CFGS)
write("AccountedLogs", LOGS_BASE, LOGS_RULES, LOGS_CFGS)
write("MakerTiming", MAKER_BASE, MAKER_RULES, MAKER_CFGS)
