---------------------------- MODULE MakerTiming -----------------------------
(***************************************************************************)
(* The statement makers' timing for one period. Period assumes one         *)
(* statement per period; this module checks the rule that gives it.        *)
(*                                                                         *)
(* Time is counted in ticks from the end of the period, up to the          *)
(* deadline Dpub ticks later. Several makers race. Each has a clock        *)
(* within Skew ticks of real time. The store may refuse any maker at any   *)
(* moment (a partial partition): a maker that reaches it stores a regular  *)
(* body with put_once (the first write wins, later makers re-post the      *)
(* stored body), and each maker's own body differs from the others' (it    *)
(* read the heads at another moment). A maker that finds no leaf of the    *)
(* deployment on the public log from 3/4 Dpub posts the outage body,       *)
(* which is the same for every maker. The public log includes a submitted  *)
(* leaf within Incl ticks.                                                 *)
(*                                                                         *)
(* NoEquivocation: never two different bodies submitted for the period.    *)
(* NotSilent: by the deadline some body is included, provided one maker    *)
(* (Live) keeps running; the store may be down for everyone.               *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    Makers,      \* maker processes
    Live,        \* a maker that keeps running through the window
    Dpub,        \* ticks from the end of the period to its deadline (a multiple of 4)
    Incl,        \* the public log includes a submitted leaf within Incl ticks
    Skew,        \* makers' clocks are within Skew ticks of real time
    \* rules of the design (TRUE; a must-fail configuration switches one off)
    StoreBy,     \* a regular body is stored and submitted only before end + Dpub/2 (maker's clock)
    OutageFrom,  \* the outage body only from end + 3/4 Dpub (off: from end + Dpub/2)
    LogCheck,    \* the outage body only when the log shows no leaf of the deployment for the period
    StoreLock    \* regular bodies go through put_once in the store (off: each maker posts its own)

ASSUME Dpub % 4 = 0 /\ Incl >= 0 /\ Skew >= 0 /\ Live \in Makers

Outage == "outage"
Skews == -Skew..Skew

VARIABLES
    now,        \* real time, in ticks after the end of the period
    skew,       \* [m -> the offset of m's clock]
    stored,     \* the regular body in the store ("none" until the first put_once)
    submitted,  \* set of [b, at]: bodies submitted to the public log, and when
    included,   \* set of the same records: those the log has included
    posted,     \* makers that have posted the outage body
    regDone     \* makers that have submitted a regular body (each does so once)

vars == << now, skew, stored, submitted, included, posted, regDone >>

Clock(m) == now + skew[m]
Ours == { x.b : x \in included }   \* what a maker sees of the deployment's leaves on the log

Init ==
    /\ now = 0 /\ skew \in [Makers -> Skews]
    /\ stored = "none" /\ submitted = {} /\ included = {} /\ posted = {} /\ regDone = {}

\* A maker that reaches the store: it stores its body if the key is free and submits the stored
\* body (StoreLock); without the lock it submits its own body.
PostRegular(m) ==
    /\ m \notin regDone /\ regDone' = regDone \cup {m}
    /\ StoreBy => Clock(m) < Dpub \div 2
    /\ LET b == IF ~StoreLock THEN m ELSE IF stored = "none" THEN m ELSE stored IN
       /\ stored' = IF StoreLock /\ stored = "none" THEN m ELSE stored
       /\ submitted' = submitted \cup {[b |-> b, at |-> now]}
    /\ UNCHANGED << now, skew, included, posted >>

PostOutage(m) ==
    /\ m \notin posted
    /\ Clock(m) >= IF OutageFrom THEN (3 * Dpub) \div 4 ELSE Dpub \div 2
    /\ LogCheck => Ours = {}
    /\ submitted' = submitted \cup {[b |-> Outage, at |-> now]}
    /\ posted' = posted \cup {m}
    /\ UNCHANGED << now, skew, stored, included, regDone >>

Include(x) ==
    /\ x \in submitted \ included
    /\ included' = included \cup {x}
    /\ UNCHANGED << now, skew, stored, submitted, posted, regDone >>

\* Time passes, but not past an inclusion deadline, and not past the moment at which the live
\* maker has to post the outage body.
Tick ==
    /\ now < Dpub
    /\ \A x \in submitted \ included : x.at + Incl >= now + 1
    /\ ~(/\ Clock(Live) >= (IF OutageFrom THEN (3 * Dpub) \div 4 ELSE Dpub \div 2)
         /\ (LogCheck => Ours = {}) /\ Live \notin posted)
    /\ now' = now + 1
    /\ UNCHANGED << skew, stored, submitted, included, posted, regDone >>

Next ==
    \/ Tick
    \/ \E m \in Makers : PostRegular(m) \/ PostOutage(m)
    \/ \E x \in submitted : Include(x)

Spec == Init /\ [][Next]_vars

TypeOK == now \in 0..Dpub /\ skew \in [Makers -> Skews]

\* Never two different bodies for the period.
NoEquivocation == Cardinality({ x.b : x \in submitted }) <= 1

\* By the deadline a body is included, with one live maker.
NotSilent == now = Dpub => included # {}

=============================================================================
