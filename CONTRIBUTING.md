# Contributing to postdoctor

Thanks for your interest in improving postdoctor. Bug reports, deliverability
edge cases (weird SPF records you found in the wild are gold), and pull
requests are all welcome.

## Development setup

Requirements: Node.js >= 20 and npm.

```bash
git clone https://github.com/JaydenCJ/postdoctor.git
cd postdoctor
npm install
npm run build
```

Run the CLI from your working tree:

```bash
node dist/cli.js check example.com
```

## Running tests

```bash
npm test              # unit tests (vitest) — never touch the network
bash scripts/smoke.sh # end-to-end CLI smoke test, fully offline
```

Both must pass before a PR is merged. Unit tests use recorded DNS/HTTP
fixtures via `FixtureResolver` / `FixtureFetcher` (see `src/net/fixture.ts`);
please keep it that way — a test that performs live DNS queries will be
rejected in review because it makes CI flaky and slow.

## Project layout

| Path | Contents |
|---|---|
| `src/spf/` | SPF record parser (RFC 7208) and recursive evaluator |
| `src/dkim/` | DKIM key record parser, including DER key-size measurement |
| `src/dmarc/` | DMARC policy parser and aggregate report (XML) translator |
| `src/mtasts/` | MTA-STS / TLS-RPT parsing |
| `src/engine.ts` | Runs all check areas and assembles the report |
| `src/gen/` | DNS record generation and baseline diff |
| `src/checklist.ts` | Per-receiver (Gmail/Outlook/Yahoo) requirement mapping |
| `src/watch.ts` | Foreground monitoring loop with ntfy/Telegram alerts |
| `src/net/` | `DnsResolver` / `HttpFetcher` interfaces + fixture implementations |
| `tests/` | vitest suites and recorded fixtures |

## Pull request guidelines

1. One logical change per PR; keep diffs reviewable.
2. Add or update tests for any behavior change — parser changes need a test
   case with the exact record text that motivated them.
3. New findings should carry a stable `code` (e.g. `spf.lookup-limit`), a
   one-line message, and a remediation hint when actionable.
4. All code comments and test descriptions are written in English.
5. Run `npm run build && npm test && bash scripts/smoke.sh` locally before
   pushing; CI runs the same three steps.
6. When a check's verdict is based on a receiver policy (Gmail/Outlook/Yahoo
   rules), cite the source document in the PR description.

## Reporting deliverability edge cases

If postdoctor mis-parses a record you saw in production, open an issue with
the record text (redact your domain if you like) and the behavior you
expected. These reports directly become parser test cases.
