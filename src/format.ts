/**
 * Terminal rendering: sections with colored PASS/WARN/FAIL markers.
 * Plain ANSI escapes only — no dependency, honors NO_COLOR.
 */
import type { DomainReport, Finding, Severity } from "./types.js";
import { reportSeverity } from "./types.js";
import type { ProviderChecklist } from "./checklist.js";
import type { RecordChange } from "./gen/diff.js";
import type { AggregateReport, ReportSummary } from "./dmarc/report.js";

const useColor = process.stdout.isTTY === true && process.env["NO_COLOR"] === undefined;

function paint(code: string, s: string): string {
  return useColor ? `[${code}m${s}[0m` : s;
}

const green = (s: string) => paint("32", s);
const yellow = (s: string) => paint("33", s);
const red = (s: string) => paint("31", s);
const dim = (s: string) => paint("2", s);
const bold = (s: string) => paint("1", s);

export function badge(severity: Severity): string {
  switch (severity) {
    case "pass":
      return green("PASS");
    case "warn":
      return yellow("WARN");
    case "fail":
      return red("FAIL");
    case "info":
      return dim("INFO");
  }
}

function renderFinding(f: Finding): string {
  const lines = [`  ${badge(f.severity)}  ${f.message}`];
  if (f.hint && f.severity !== "pass") lines.push(dim(`        ↳ ${f.hint}`));
  return lines.join("\n");
}

export function renderReport(report: DomainReport): string {
  const out: string[] = [];
  out.push(bold(`Deliverability report for ${report.domain}`));
  out.push(dim(`checked at ${report.checkedAt}`));
  out.push("");

  for (const result of report.results) {
    out.push(bold(`■ ${result.title}`));
    for (const f of result.findings) out.push(renderFinding(f));
    out.push("");
  }

  const overall = reportSeverity(report);
  const counts = countFindings(report);
  out.push(
    `${bold("Overall:")} ${badge(overall)}  ` +
      dim(`(${counts.fail} fail, ${counts.warn} warn, ${counts.pass} pass)`),
  );
  return out.join("\n");
}

export function countFindings(report: DomainReport): { pass: number; warn: number; fail: number } {
  const all = report.results.flatMap((r) => r.findings);
  return {
    pass: all.filter((f) => f.severity === "pass").length,
    warn: all.filter((f) => f.severity === "warn").length,
    fail: all.filter((f) => f.severity === "fail").length,
  };
}

export function renderChecklist(list: ProviderChecklist): string {
  const out: string[] = [bold(`▤ ${list.providerLabel}`)];
  for (const item of list.items) {
    const mark =
      item.status === "met"
        ? green("✔ met    ")
        : item.status === "at-risk"
          ? yellow("△ at-risk")
          : item.status === "not-met"
            ? red("✘ not met")
            : dim("? unknown");
    out.push(`  ${mark}  ${item.requirement}`);
    out.push(dim(`             ${item.detail}`));
  }
  return out.join("\n");
}

export function renderChanges(changes: RecordChange[]): string {
  if (changes.length === 0) return green("No drift: live DNS matches the baseline.");
  const out: string[] = [bold(`${changes.length} change(s) since baseline:`)];
  for (const c of changes) {
    switch (c.kind) {
      case "added":
        out.push(green(`  + ${c.name}: ${c.after}`));
        break;
      case "removed":
        out.push(red(`  - ${c.name}: ${c.before}`));
        break;
      case "changed":
        out.push(yellow(`  ~ ${c.name}:`));
        out.push(red(`      - ${c.before}`));
        out.push(green(`      + ${c.after}`));
        break;
    }
  }
  return out.join("\n");
}

export function renderReportSummary(report: AggregateReport, summary: ReportSummary): string {
  const out: string[] = [];
  const range = `${report.begin.toISOString().slice(0, 10)} → ${report.end.toISOString().slice(0, 10)}`;
  out.push(bold(`DMARC aggregate report from ${report.reporter}`));
  out.push(dim(`domain ${report.domain} · ${range} · policy p=${report.policy.p}`));
  out.push("");

  const pct = (summary.passRate * 100).toFixed(1);
  const headline =
    summary.failMessages === 0
      ? green(`All ${summary.totalMessages} messages passed DMARC (${pct}%).`)
      : summary.passMessages === 0
        ? red(`All ${summary.totalMessages} messages FAILED DMARC.`)
        : yellow(
            `${summary.passMessages}/${summary.totalMessages} messages passed DMARC (${pct}%); ${summary.failMessages} failed.`,
          );
  out.push(headline);
  out.push("");

  out.push(bold("Per sending source:"));
  for (const src of summary.sources) {
    const mark = src.failed === 0 ? green("✔") : src.passed === 0 ? red("✘") : yellow("△");
    out.push(`  ${mark} ${src.sourceIp} — ${src.messages} msg(s), ${src.failed} failed`);
    out.push(dim(`      ${src.verdict}`));
  }
  return out.join("\n");
}
