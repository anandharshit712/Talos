# Design — Network Brute Force Detection

## The chain

```
NormalizedEvent
  → NetworkDomainAgent          routes within the domain, knows categories only
     → NetworkTypeClassifier    auth-bearing? → "network_brute_force", else "unclassified"
     → NetworkBruteForceSubAgent  runs its detectors concurrently
        → SshBruteForceDetector   thresholds, scopes, and words the finding
           → RateEngine           counts failures per key inside a window
              → EventWindowStore  the rolling buffer the count reads from
```

The orchestrator above this chain knows domains only; the domain agent knows categories only.
Adding RDP in P5 touches the sub-agent's detector list and nothing else.

## Contracts

| Direction | Contract |
|---|---|
| Consumes | `NormalizedEvent` with `auth.protocol == "ssh"`, plus `DetectionContext` |
| Emits | `Verdict` — `technique="brute_force"`, `category="network_brute_force"`, MITRE T1110 |

## Decisions

**The rate engine is shared, and built first.** SSH, RDP, web brute force, and credential
stuffing are the same arithmetic over different keys. Building the core in P2 is what lets P5
add three detectors in two days (HLD §5.5). The engine reports what it counted; it decides
nothing about severity, wording, or confidence — those need the technique, and it does not know
one.

**The window is keyed on `(host, account)`.** "Is someone grinding *this* account on *this* box"
is the analyst's question. Keying on source IP alone would merge a distributed attempt into one
verdict and miss a rotating-source campaign; keying on account alone would merge two unrelated
hosts. The store also indexes by account and by source IP, so P5's credential-stuffing detector
gets the breadth view without a second buffer.

**TTL is measured in event time.** Replaying last week's log has to behave exactly like reading a
live stream. A wall-clock TTL would evict every historical event on arrival, and the demo would
detect nothing.

**Keys are namespaced** (`account:root`, `ip:203.0.113.7`, `host_account:bastion-01|root`), so a
username that looks like an address cannot collide with one.

**Detector failures are contained twice** — per detector inside the sub-agent, and around the
sub-agent inside the domain agent. Fail-open for detection: one broken detector must not silence
the ones beside it (LLD §11).

## Alternatives considered

| Option | Why not |
|---|---|
| Detector owns its own buffer | Every rate detector would keep a private copy of the same events; the window is a shared service for exactly this reason. |
| Fire on the first failure, decay a score | Harder to explain in a report and harder to calibrate; a threshold over a window is what an analyst can check by eye against the raw lines. |
| Wall-clock TTL | Breaks replay, which is how the demo and the whole P8 evaluation run. |
| One global event list, filtered per query | O(n) per event and unbounded; the keyed buffer is O(1) per lookup and bounded per key (NFR-7). |
