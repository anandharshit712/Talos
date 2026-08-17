# Design — Network Log Ingestion

## Position in the pipeline

```
raw sshd syslog  →  NetworkLogParser  →  NormalizedEvent  →  EventOrchestrator
```

Ingestion is the only layer that sees a raw string. Everything downstream sees the contract.

## Contracts

| Direction | Contract |
|---|---|
| Consumes | lines of text (`Iterable[str]`), typically a file handle |
| Emits | `NormalizedEvent` (`schemas/event_schema.py`) with `domain="network"`, `telemetry_source="sshd"` |

`BaseParser` (`ingestion/parser_contract.py`) fixes the shape: `parse_line` per line,
`parse_stream` for the iteration, and a `parse_errors` counter. `parse_stream` is a generator, so
a live tail yields events as they arrive rather than after the file ends.

## Decisions

**Unparseable lines return `None`.** A parser that raises turns one malformed line into zero
detection for the rest of the file. Skipping and counting keeps the stream alive and still makes
the loss visible — the CLI prints the count on stderr (LLD §11).

**Timestamps are normalised to UTC by the contract, not by the parser.** `NormalizedEvent` owns
that conversion, so every parser gets it right by construction.

**The year is reconstructed, not assumed.** syslog carries no year. The parser takes
`default_year` (current year by default) and steps back one year when the result would land more
than a day in the future — the only way a December log read in January parses correctly. One day
of slack absorbs clock skew between source and host.

**Port is set to 22 for sshd lines.** The line reports the *client's* ephemeral port, which is
noise; the target port is what a report should carry.

## Alternatives considered

| Option | Why not |
|---|---|
| One regex for the whole line including the message | Unreadable, and every new message shape would edit one shared pattern. Split: syslog envelope, then message. |
| Raise on malformed input, let the caller catch | Pushes the same `try` into every caller and makes a partial file an error rather than a partial result. |
| Infer the year from surrounding lines | More machinery for a case a single flag solves; a fixture with a deliberate year is also easier to test. |
| Parse RDP now | P5 owns it. The regex table is where it will go, and the contract does not change. |
