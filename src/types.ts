/**
 * Shared result types used by every check module.
 */

/** Severity of a single finding. */
export type Severity = "pass" | "warn" | "fail" | "info";

/** One observation produced by a check (e.g. "SPF exceeds 10 DNS lookups"). */
export interface Finding {
  severity: Severity;
  /** Stable machine-readable code, e.g. "spf.lookup-limit". */
  code: string;
  /** One-line human readable message. */
  message: string;
  /** Optional remediation hint shown under the message. */
  hint?: string;
}

/** Result of one check area (spf, dkim, dmarc, ...). */
export interface CheckResult {
  /** Area identifier, e.g. "spf". */
  area: string;
  /** Human title, e.g. "SPF". */
  title: string;
  /** The raw record(s) this check inspected, when applicable. */
  records: string[];
  findings: Finding[];
}

/** Full report for one domain. */
export interface DomainReport {
  domain: string;
  checkedAt: string;
  results: CheckResult[];
}

/** Aggregate severity for a set of findings: fail > warn > pass. */
export function overallSeverity(findings: Finding[]): Severity {
  if (findings.some((f) => f.severity === "fail")) return "fail";
  if (findings.some((f) => f.severity === "warn")) return "warn";
  return "pass";
}

/** Aggregate severity for a whole report. */
export function reportSeverity(report: DomainReport): Severity {
  return overallSeverity(report.results.flatMap((r) => r.findings));
}

export function pass(code: string, message: string, hint?: string): Finding {
  return { severity: "pass", code, message, hint };
}
export function warn(code: string, message: string, hint?: string): Finding {
  return { severity: "warn", code, message, hint };
}
export function fail(code: string, message: string, hint?: string): Finding {
  return { severity: "fail", code, message, hint };
}
export function info(code: string, message: string, hint?: string): Finding {
  return { severity: "info", code, message, hint };
}
