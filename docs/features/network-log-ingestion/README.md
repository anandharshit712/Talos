# Feature — Network Log Ingestion

**Status:** in-progress
**Owner:** Harshit Anand
**Code:** `src/talos/ingestion/parser_contract.py`, `src/talos/ingestion/parsers/network_log_parser.py`
**Config:** `config/default.yaml` → `talos.ingestion.network.formats`
**Tests:** `tests/unit/ingestion/test_parser_contract.py`, `tests/unit/ingestion/parsers/test_network_log_parser.py`
**Fixtures:** `tests/fixtures/logs/network_ssh_brute_force_sshd.log`

Turns `sshd` syslog lines into `NormalizedEvent`, the single contract the rest of the pipeline
consumes. Every field a detector reasons about — who, from where, against which account on which
host, and whether the attempt succeeded — is extracted here, once, so no detector ever parses a
string again.

Unreadable lines are skipped and counted, never raised: a log file full of other daemons'
chatter must not stop detection on the lines that do matter.

| Document | Contents |
|---|---|
| [design.md](design.md) | contracts consumed and emitted, position in the pipeline, alternatives rejected |
| [behaviour.md](behaviour.md) | supported line shapes, field mapping, edge cases, error handling |
| [testing.md](testing.md) | cases covered, fixtures, how to run |
| [changelog.md](changelog.md) | dated entries |

**Scope for the hackathon slice:** sshd syslog. RDP event logs are added in P5; netflow records
map to `target` + `meta` and are deliberately not consumed by any detector yet.
