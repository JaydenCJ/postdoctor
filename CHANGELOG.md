# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-08

### Added

- `postdoctor check <domain>`: full deliverability health check — SPF, DKIM,
  DMARC, MTA-STS/TLS-RPT, reverse DNS (FCrDNS), and DNS blocklists — with
  colored PASS/WARN/FAIL findings, remediation hints, and `--json` output.
- SPF parser and evaluator (RFC 7208): mechanism/modifier parsing with
  syntax diagnostics, recursive include/redirect walking, 10-DNS-lookup
  counting, loop detection, `+all`/`?all`/`ptr` policy grading.
- DKIM key record checks (RFC 6376): tag list validation, revoked-key and
  testing-mode detection, RSA key size measured by decoding the DER
  SubjectPublicKeyInfo (flags keys under 1024/2048 bits), ed25519 support.
- DMARC policy parser (RFC 7489): policy/subdomain policy, pct semantics,
  rua/ruf URI validation, external report destination hints.
- `postdoctor dmarc-report <file>`: translates DMARC aggregate XML reports
  (plain or gzipped) into a per-source plain-language summary with verdicts.
- `postdoctor gen <domain>`: generates SPF, DMARC, MTA-STS, and TLS-RPT
  records in zone-file format plus the MTA-STS policy file body.
- `postdoctor diff <domain>`: snapshots all deliverability-relevant records
  to a baseline JSON and reports drift (added/removed/changed, MX changes).
- `postdoctor checklist <domain>`: maps findings onto Gmail, Outlook, and
  Yahoo sender requirement checklists.
- `postdoctor watch <domain>`: foreground monitoring loop that alerts on new
  failures and DNS drift via ntfy or Telegram; `--max-cycles` for bounded
  runs.
- `--dns-fixture` offline mode: answer all DNS/HTTP from a JSON snapshot,
  used by CI and the smoke test.
- Library entry point (`postdoctor` package exports) with typed public API.
