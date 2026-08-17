# Design — Incident Aggregation and Output

## Position in the pipeline

```
NormalizedEvent → EventOrchestrator ─ add to window
                                    ├ AgentRegistry.get(domain) → DomainAgent → [Verdict]
                                    ├ VerdictAggregator.aggregate → IncidentReport | None
                                    ├ VerdictLogStore.append
                                    └ sinks: stdout, json_file
```

## Contracts

| Direction | Contract |
|---|---|
| Consumes | `NormalizedEvent` + the `Verdict` list its domain agent produced |
| Emits | `IncidentReport` (`schemas/report_schema.py`), or `None` |

## Decisions

**The orchestrator routes by domain only.** It has never heard of brute force, injection, or
IDOR. Adding a technique must not change a line of it (HLD P7/NFR-4); adding a *domain* is one
`register_domain_agent` call.

**The event enters the window before the agents run.** A windowed detector evaluating this event
must see this event — an off-by-one here means the burst is always one short.

**`None` beats an empty report.** "Nothing fired" and "we looked and found nothing" are different
claims, and an empty `IncidentReport` is unrepresentable by contract. Inconclusive verdicts ride
along inside a report another verdict created, but never create one themselves.

**Aggregate confidence is max-plus-corroboration, not an average.** Averaging lets a weak second
opinion drag down a strong finding. The highest verdict stands, and each *additional* independent
detector adds `aggregation.corroboration_boost`.

**Severity is a category floor, adjusted twice**: up one step when the attack demonstrably
succeeded, down one when confidence is below 0.5. A successful brute force is `high`; the same
burst blocked is `medium`; an unsure finding is a lead, not a page.

**The store never creates its schema.** `src/` issues no DDL (standards §4.4 rule 5). A missing
table raises `StorageError` naming `scripts/apply_migrations.py` — a clear two-step setup beats a
store that silently creates a table which then drifts from `db/migrations/`.

**An ongoing attack is one alert, not one per event.** A windowed detector re-fires on every
event past its threshold. The orchestrator keeps the signature of what it has already reported
and stays quiet until the incident escalates — it succeeded, or it doubled. Suppression lives in
the orchestrator rather than the aggregator because it is a property of the *stream*, and the
aggregator is deliberately stateless.

**stdout carries reports, stderr carries diagnostics**, so `talos scan file.log | jq` needs no
filtering.

## Alternatives considered

| Option | Why not |
|---|---|
| One report per verdict | Two detectors on one burst would page twice for one incident. |
| Summarise verdicts into the report and drop them | The trace *is* the differentiator (plan §9). |
| Average the confidences | Punishes corroboration, which is the opposite of what agreement means. |
| Auto-create tables on first write | Two sources of schema truth, and the second one is invisible in `db/`. |
| Suppress duplicates by time cooldown | A clock-based window is wrong under replay, where a whole day of log arrives in a second. Escalation-based suppression works identically live and replayed. |
| A `Sink` ABC | Two sinks with one method each. A union type is the whole abstraction that is needed; add the ABC if a third sink disagrees. |
