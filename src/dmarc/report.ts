/**
 * DMARC aggregate (rua) report parser and translator.
 *
 * Aggregate reports are the XML files Gmail/Outlook/Yahoo mail you daily.
 * This module parses the feedback XML (optionally gzip-compressed), groups
 * rows per source IP, and renders a plain-language summary that answers the
 * only question people have: "who failed, and does it matter?"
 */
import { gunzipSync } from "node:zlib";
import { XMLParser } from "fast-xml-parser";

export interface ReportRow {
  sourceIp: string;
  count: number;
  disposition: string;
  dkimResult: string;
  spfResult: string;
  /** True when either DKIM or SPF passed in alignment (DMARC pass). */
  dmarcPass: boolean;
  headerFrom: string;
  /** Raw auth_results details (domain:result pairs) for display. */
  authDetails: string[];
}

export interface AggregateReport {
  reporter: string;
  reportId: string;
  domain: string;
  policy: {
    p: string;
    sp?: string;
    pct?: number;
    adkim?: string;
    aspf?: string;
  };
  begin: Date;
  end: Date;
  rows: ReportRow[];
}

export interface ReportSummary {
  totalMessages: number;
  passMessages: number;
  failMessages: number;
  /** Fraction 0-1. */
  passRate: number;
  /** Per-source aggregation, sorted by message count descending. */
  sources: Array<{
    sourceIp: string;
    messages: number;
    passed: number;
    failed: number;
    dispositions: string[];
    /** Human verdict for this source. */
    verdict: string;
  }>;
}

function asArray<T>(v: T | T[] | undefined): T[] {
  if (v === undefined) return [];
  return Array.isArray(v) ? v : [v];
}

function text(v: unknown): string {
  if (v === null || v === undefined) return "";
  return String(v).trim();
}

/** Detect gzip magic bytes. */
function isGzip(buf: Buffer): boolean {
  return buf.length > 2 && buf[0] === 0x1f && buf[1] === 0x8b;
}

/**
 * Parse a DMARC aggregate report from raw bytes (XML or gzipped XML).
 * Throws Error with a human-readable message on malformed input.
 */
export function parseAggregateReport(input: Buffer): AggregateReport {
  const xmlBuf = isGzip(input) ? gunzipSync(input) : input;
  const xml = xmlBuf.toString("utf8");

  const parser = new XMLParser({
    ignoreAttributes: true,
    parseTagValue: false,
    trimValues: true,
  });
  let doc: Record<string, unknown>;
  try {
    doc = parser.parse(xml) as Record<string, unknown>;
  } catch {
    throw new Error("file is not well-formed XML");
  }

  const feedback = doc["feedback"] as Record<string, unknown> | undefined;
  if (!feedback) {
    throw new Error('not a DMARC aggregate report (missing <feedback> root element)');
  }

  const meta = (feedback["report_metadata"] ?? {}) as Record<string, unknown>;
  const policyPublished = (feedback["policy_published"] ?? {}) as Record<string, unknown>;
  const dateRange = (meta["date_range"] ?? {}) as Record<string, unknown>;

  const beginTs = Number(text(dateRange["begin"]));
  const endTs = Number(text(dateRange["end"]));
  if (!Number.isFinite(beginTs) || !Number.isFinite(endTs) || beginTs === 0) {
    throw new Error("report has no valid <date_range>");
  }

  const rows: ReportRow[] = [];
  for (const rec of asArray(feedback["record"] as unknown)) {
    const r = rec as Record<string, unknown>;
    const row = (r["row"] ?? {}) as Record<string, unknown>;
    const policyEvaluated = (row["policy_evaluated"] ?? {}) as Record<string, unknown>;
    const identifiers = (r["identifiers"] ?? {}) as Record<string, unknown>;
    const authResults = (r["auth_results"] ?? {}) as Record<string, unknown>;

    const dkimEval = text(policyEvaluated["dkim"]) || "none";
    const spfEval = text(policyEvaluated["spf"]) || "none";

    const authDetails: string[] = [];
    for (const d of asArray(authResults["dkim"] as unknown)) {
      const dd = d as Record<string, unknown>;
      const sel = text(dd["selector"]);
      authDetails.push(
        `dkim ${text(dd["domain"])}${sel ? ` (s=${sel})` : ""}: ${text(dd["result"]) || "none"}`,
      );
    }
    for (const s of asArray(authResults["spf"] as unknown)) {
      const ss = s as Record<string, unknown>;
      authDetails.push(`spf ${text(ss["domain"])}: ${text(ss["result"]) || "none"}`);
    }

    rows.push({
      sourceIp: text(row["source_ip"]),
      count: Number(text(row["count"])) || 0,
      disposition: text(policyEvaluated["disposition"]) || "none",
      dkimResult: dkimEval,
      spfResult: spfEval,
      dmarcPass: dkimEval === "pass" || spfEval === "pass",
      headerFrom: text(identifiers["header_from"]),
      authDetails,
    });
  }

  const pct = text(policyPublished["pct"]);
  return {
    reporter: text(meta["org_name"]) || "unknown reporter",
    reportId: text(meta["report_id"]),
    domain: text(policyPublished["domain"]),
    policy: {
      p: text(policyPublished["p"]) || "none",
      sp: text(policyPublished["sp"]) || undefined,
      pct: pct ? Number(pct) : undefined,
      adkim: text(policyPublished["adkim"]) || undefined,
      aspf: text(policyPublished["aspf"]) || undefined,
    },
    begin: new Date(beginTs * 1000),
    end: new Date(endTs * 1000),
    rows,
  };
}

/** Aggregate rows per source IP and attach a human verdict to each. */
export function summarizeReport(report: AggregateReport): ReportSummary {
  const bySource = new Map<
    string,
    { messages: number; passed: number; failed: number; dispositions: Set<string> }
  >();

  let total = 0;
  let passed = 0;
  for (const row of report.rows) {
    total += row.count;
    if (row.dmarcPass) passed += row.count;
    const entry =
      bySource.get(row.sourceIp) ??
      { messages: 0, passed: 0, failed: 0, dispositions: new Set<string>() };
    entry.messages += row.count;
    if (row.dmarcPass) entry.passed += row.count;
    else entry.failed += row.count;
    entry.dispositions.add(row.disposition);
    bySource.set(row.sourceIp, entry);
  }

  const sources = [...bySource.entries()]
    .map(([sourceIp, s]) => ({
      sourceIp,
      messages: s.messages,
      passed: s.passed,
      failed: s.failed,
      dispositions: [...s.dispositions].sort(),
      verdict: verdictFor(s.passed, s.failed, [...s.dispositions]),
    }))
    .sort((a, b) => b.messages - a.messages);

  return {
    totalMessages: total,
    passMessages: passed,
    failMessages: total - passed,
    passRate: total === 0 ? 1 : passed / total,
    sources,
  };
}

function verdictFor(passed: number, failed: number, dispositions: string[]): string {
  if (failed === 0) return "authenticating correctly";
  const punished = dispositions.some((d) => d === "quarantine" || d === "reject");
  if (passed === 0) {
    return punished
      ? "all mail failed DMARC and was quarantined/rejected — either a forgotten sender or a spoofer"
      : "all mail failed DMARC (delivered only because policy is none) — fix SPF/DKIM for this source or it is a spoofer";
  }
  return "partially failing — likely a forwarding path or an intermittently signed stream";
}
