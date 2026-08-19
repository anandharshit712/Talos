# Design — Network Brute Force Detection

## The chain

```
NormalizedEvent
  → NetworkDomainAgent          routes within the domain, knows categories only
     → NetworkTypeClassifier    auth-bearing? → "network_brute_force", else "unclassified"
     → NetworkBruteForceSubAgent  runs its detectors concurrently
        → SshBruteForceDetector   protocol filter, thresholds, evidence wording
        → RdpBruteForceDetector    the same, over Windows logon events
           → RateEngine            counts failures per key inside a window
              → EventWindowStore   the rolling buffer the count reads from
           → RateVerdictEngine     curve, narration, Scope, ModelInfo, Verdict
```

The orchestrator above this chain knows domains only; the domain agent knows categories only.
Adding RDP in P5 cost one entry in the sub-agent's detector list and nothing else — the claim
this design made in P2, now measured.

## Contracts

| Direction | Contract |
|---|---|
| Consumes | `NormalizedEvent` with `auth.protocol ∈ {"ssh", "rdp"}`, plus `DetectionContext` |
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

## RDP (P5)

**Two files, not one detector with a protocol argument.** SSH and RDP diverge on the things that
matter operationally: an exposed RDP endpoint is a named top ransomware initial-access vector, so
its threshold, its model route, and the wording of its evidence are tuned separately, and a change
to one must not silently move the other. What they share — counting, the confidence curve, the
narration call, verdict assembly — lives in `detection/rate/`, so the duplication is configuration
and wording, not logic. `RdpBruteForceDetector` is 94 lines, of which three are the algorithm.

**Telemetry is the exported Windows Security log, one JSON object per line** — the shape
`wevtutil`, Winlogbeat, and every EVTX-to-JSON exporter produce. Parsing EVTX itself would need a
third-party library and a Windows-only binary file, and the collector shipping these logs has
already done the conversion.

| Read | Meaning |
|---|---|
| `EventID` 4625 / 4624 | failed / successful logon |
| `LogonType` 10 | RemoteInteractive — an RDP session |
| `TargetUserName`, `IpAddress`, `Computer` | account, source, host |
| `SubStatus` | the failure reason, named for the six codes worth naming |

**Only logon type 10 is read as RDP.** 4625 also covers network (3) and unlock (7) logons; counting
those would put unrelated failures in the same window and inflate a burst. Events with no usable
source (`-`, `127.0.0.1`, `::1`) or no account are skipped rather than keyed on a placeholder.

The key stays `(host, account)`, unchanged from SSH: "is someone grinding this account on this
box" is the same question, and RDP hosts are not load-balanced the way a web login is.
