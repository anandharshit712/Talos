# Sub-feature — Web Brute Force

**Status:** in-progress
**Code:** `src/talos/domains/web/auth_failure/brute_force_detector.py`
**Config:** `talos.detection.brute_force` — `window_seconds: 120`, `fail_threshold: 10`
**MITRE:** T1110

Depth against one account: `fail_threshold` rejected HTTP logins for the same account inside
`window_seconds`, from any number of sources.

**Keyed on the account alone.** Not `(host, account)` as SSH is — a web login is served by
whichever app server the balancer picked, and splitting one attack across three hosts would hide
it. Not the source IP either, though LLD §7.3.1 allows it: that key belongs to credential
stuffing, and sharing it would report one attack twice under two techniques.

Confidence scales on the failure count above the threshold and is floored at `success_floor` once
a login succeeds after the burst began — at which point the evidence names the account that got
in, and the aggregator adds credential rotation to the recommended actions.

`source_diversity` in the scope is what distinguishes a single grinder from a distributed
password-spray against one account; both fire this detector, and the report says which it was.
