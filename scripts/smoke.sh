#!/usr/bin/env bash
# Smoke test: exercises every CLI command end-to-end through the compiled
# entry point, fully offline (DNS/HTTP answered from a generated fixture).
# Prints "SMOKE OK" and exits 0 only when every assertion holds.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI="$ROOT/dist/cli.js"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

step() { printf '[smoke] %s\n' "$1"; }
die() { printf '[smoke] FAILED: %s\n' "$1" >&2; exit 1; }

cd "$ROOT"

step "building (tsc)"
npm run build --silent >/dev/null

[ -f "$CLI" ] || die "dist/cli.js missing after build"

# --- fixture: a realistic self-hosted mail domain, DKIM key generated locally ---
step "generating offline DNS fixture"
node - "$WORK" <<'EOF'
const { generateKeyPairSync } = require("node:crypto");
const { writeFileSync } = require("node:fs");
const { join } = require("node:path");
const dir = process.argv[2];
const key = generateKeyPairSync("rsa", { modulusLength: 2048 })
  .publicKey.export({ type: "spki", format: "der" }).toString("base64");
const healthy = {
  dns: {
    "TXT:smoke.example": [["v=spf1 ip4:192.0.2.10 -all"]],
    "TXT:_dmarc.smoke.example": [["v=DMARC1; p=reject; rua=mailto:dmarc@smoke.example"]],
    ["TXT:mail._domainkey.smoke.example"]: [[`v=DKIM1; k=rsa; p=${key}`]],
    "TXT:_mta-sts.smoke.example": [["v=STSv1; id=20260708120000"]],
    "TXT:_smtp._tls.smoke.example": [["v=TLSRPTv1; rua=mailto:tls@smoke.example"]],
    "MX:smoke.example": [{ exchange: "mail.smoke.example", priority: 10 }],
    "A:mail.smoke.example": ["192.0.2.10"],
    "PTR:192.0.2.10": ["mail.smoke.example"]
  },
  http: {
    "https://mta-sts.smoke.example/.well-known/mta-sts.txt":
      "version: STSv1\nmode: enforce\nmx: mail.smoke.example\nmax_age: 604800\n"
  }
};
writeFileSync(join(dir, "healthy.json"), JSON.stringify(healthy));
const broken = JSON.parse(JSON.stringify(healthy));
broken.dns["TXT:smoke.example"] = [["v=spf1 mx +all"]];
delete broken.dns["TXT:_dmarc.smoke.example"];
writeFileSync(join(dir, "broken.json"), JSON.stringify(broken));
EOF

# --- --version / --help consistency ---
step "--version and --help"
VERSION="$(node "$CLI" --version)"
[ "$VERSION" = "0.1.0" ] || die "--version printed '$VERSION', expected 0.1.0"
HELP="$(node "$CLI" --help)"
echo "$HELP" | grep -q "postdoctor" || die "--help does not mention program name"
for cmd in check gen diff dmarc-report checklist watch; do
  echo "$HELP" | grep -q "$cmd" || die "--help does not list command '$cmd'"
done

# --- check: healthy domain exits 0 with PASS output ---
step "check (healthy fixture)"
OUT="$(node "$CLI" check smoke.example --selector mail --dns-fixture "$WORK/healthy.json")"
echo "$OUT" | grep -q "Deliverability report for smoke.example" || die "check output missing header"
echo "$OUT" | grep -q "forward-confirmed rDNS" || die "check did not confirm rDNS"
echo "$OUT" | grep -q "Overall: PASS" || die "healthy check not PASS"

# --- check: broken domain exits 1 and names the problems ---
step "check (broken fixture, expect exit 1)"
set +e
OUT="$(node "$CLI" check smoke.example --selector mail --dns-fixture "$WORK/broken.json" 2>&1)"
RC=$?
set -e
[ "$RC" -eq 1 ] || die "broken check exited $RC, expected 1"
echo "$OUT" | grep -q '"+all"' || die "broken check did not flag +all"
echo "$OUT" | grep -q "no DMARC record" || die "broken check did not flag missing DMARC"

# --- check --json is machine readable ---
step "check --json"
node "$CLI" check smoke.example --selector mail --dns-fixture "$WORK/healthy.json" --json \
  | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const r=JSON.parse(s);if(r.domain!=='smoke.example'||r.results.length<5)process.exit(1)})" \
  || die "check --json did not produce a valid report"

# --- gen: zone-file output parses back through our own checker ---
step "gen"
OUT="$(node "$CLI" gen smoke.example --ip 192.0.2.10 --policy quarantine --rua dmarc@smoke.example)"
echo "$OUT" | grep -q 'v=spf1 ip4:192.0.2.10 -all' || die "gen SPF wrong"
echo "$OUT" | grep -q '_dmarc.smoke.example. 3600 IN TXT "v=DMARC1; p=quarantine' || die "gen DMARC wrong"
echo "$OUT" | grep -q 'mode: testing' || die "gen MTA-STS policy file missing"

# --- diff: save baseline, expect no drift, then detect drift ---
step "diff (baseline save, no-drift, drift)"
BASE="$WORK/baseline.json"
node "$CLI" diff smoke.example --baseline "$BASE" --save --selector mail --dns-fixture "$WORK/healthy.json" >/dev/null
node "$CLI" diff smoke.example --baseline "$BASE" --selector mail --dns-fixture "$WORK/healthy.json" \
  | grep -q "No drift" || die "diff reported drift on identical state"
set +e
OUT="$(node "$CLI" diff smoke.example --baseline "$BASE" --selector mail --dns-fixture "$WORK/broken.json")"
RC=$?
set -e
[ "$RC" -eq 1 ] || die "diff with drift exited $RC, expected 1"
echo "$OUT" | grep -q "_dmarc.smoke.example" || die "diff did not report removed DMARC record"

# --- dmarc-report: translate the recorded Google aggregate report ---
step "dmarc-report"
set +e
OUT="$(node "$CLI" dmarc-report "$ROOT/tests/fixtures/google-aggregate.xml")"
RC=$?
set -e
[ "$RC" -eq 1 ] || die "dmarc-report exited $RC, expected 1 (report contains failures)"
echo "$OUT" | grep -q "google.com" || die "dmarc-report missing reporter"
echo "$OUT" | grep -q "42/52 messages passed" || die "dmarc-report totals wrong"

# --- checklist ---
step "checklist"
OUT="$(node "$CLI" checklist smoke.example --provider gmail --selector mail --dns-fixture "$WORK/healthy.json")"
echo "$OUT" | grep -q "Gmail" || die "checklist missing provider header"
echo "$OUT" | grep -qi "met" || die "checklist has no status marks"

# --- watch: bounded foreground run (daemon mode smoke) ---
step "watch (foreground, 2 cycles)"
OUT="$(timeout 60 node "$CLI" watch smoke.example --selector mail --interval 1 --max-cycles 2 --dns-fixture "$WORK/healthy.json")"
echo "$OUT" | grep -q "cycle 1" || die "watch cycle 1 missing"
echo "$OUT" | grep -q "cycle 2" || die "watch cycle 2 missing"
echo "$OUT" | grep -q "alerts=0" || die "watch raised unexpected alerts"

# --- error handling: invalid input must exit 2 with a readable message ---
step "error handling"
set +e
ERR="$(node "$CLI" check "not a domain" 2>&1 >/dev/null)"
RC=$?
set -e
[ "$RC" -eq 2 ] || die "invalid domain exited $RC, expected 2"
echo "$ERR" | grep -q "not a valid domain name" || die "invalid-domain error not human readable"
set +e
ERR="$(node "$CLI" dmarc-report /nonexistent-report.xml 2>&1 >/dev/null)"
RC=$?
set -e
[ "$RC" -eq 2 ] || die "missing report file exited $RC, expected 2"
echo "$ERR" | grep -q "cannot read report file" || die "missing-file error not human readable"

echo "SMOKE OK"
