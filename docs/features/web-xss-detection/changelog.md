# Changelog — Web XSS Detection

## 2026-08-18 — reflected and stored XSS (P4)

- Added `xss_pattern_rules`: script elements, event handlers, executing URI schemes, encoded
  variants, and attribute breakouts, each written against the markup that would otherwise defeat
  it.
- Added `XssDetector`: patterns decide, a model judges the obfuscated middle, inert markup is
  cleared without either.
- **Stored versus reflected** via the event window: the same payload signature at a different
  endpoint marks the payload stored, floors confidence at 0.9, and puts every affected endpoint
  into scope. The signature is built from matched fragments, so it is path-independent by
  construction — a key including the endpoint could never match twice.
- Added `xss_detector_judge_v1.md`, written so that "no" is an expected answer.
- **Fixed during development:** a heredoc wrote a literal backspace byte into one rule's regex, so
  the rule silently never matched. A repository-wide scan for control characters found no others,
  and the rule now has its own test.
- **Fixed during development:** every XSS rule was either decisive or corroboration-only, which
  made the judge path unreachable code. Added `unlisted_handler_in_tag` — a handler-shaped
  attribute whose name is not on the known list — as the genuine borderline case.
- **Known limitations:** stored detection sees a second sighting only inside the event window, so
  a payload rendered days later reads as reflected; DOM-based XSS leaves no server-side trace.
