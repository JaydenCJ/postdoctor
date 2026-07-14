/**
 * Per-receiver compliance checklists.
 *
 * Gmail, Outlook and Yahoo each publish sender requirements (Gmail/Yahoo
 * bulk-sender rules from 2024, hardened enforcement 2025; Outlook 550
 * 5.7.515 for unauthenticated bulk senders since May 2025). This module maps
 * the findings of a DomainReport onto each receiver's requirement list so
 * users see exactly what a given mailbox provider will complain about.
 */
import type { DomainReport, Finding, Severity } from "./types.js";

export type Provider = "gmail" | "outlook" | "yahoo";

export interface ChecklistItem {
  requirement: string;
  status: "met" | "at-risk" | "not-met" | "unknown";
  detail: string;
}

export interface ProviderChecklist {
  provider: Provider;
  providerLabel: string;
  items: ChecklistItem[];
}

function findingsByPrefix(report: DomainReport, prefix: string): Finding[] {
  return report.results.flatMap((r) => r.findings).filter((f) => f.code.startsWith(prefix));
}

function worst(findings: Finding[]): Severity | undefined {
  if (findings.length === 0) return undefined;
  if (findings.some((f) => f.severity === "fail")) return "fail";
  if (findings.some((f) => f.severity === "warn")) return "warn";
  return "pass";
}

function statusFrom(sev: Severity | undefined): ChecklistItem["status"] {
  switch (sev) {
    case "fail":
      return "not-met";
    case "warn":
      return "at-risk";
    case "pass":
    case "info":
      return "met";
    default:
      return "unknown";
  }
}

function detailFrom(findings: Finding[], okText: string): string {
  const bad = findings.filter((f) => f.severity === "fail" || f.severity === "warn");
  if (bad.length === 0) return okText;
  return bad.map((f) => f.message).join("; ");
}

interface RequirementSpec {
  requirement: string;
  prefixes: string[];
  okText: string;
  /** Extra evaluator for requirements not directly keyed to one area. */
  custom?: (report: DomainReport) => ChecklistItem | undefined;
}

function buildItems(report: DomainReport, specs: RequirementSpec[]): ChecklistItem[] {
  return specs.map((spec) => {
    if (spec.custom) {
      const item = spec.custom(report);
      if (item) return item;
    }
    const findings = spec.prefixes.flatMap((p) => findingsByPrefix(report, p));
    return {
      requirement: spec.requirement,
      status: statusFrom(worst(findings)),
      detail: detailFrom(findings, spec.okText),
    };
  });
}

function dmarcPolicyItem(report: DomainReport, minimum: string): ChecklistItem {
  const missing = findingsByPrefix(report, "dmarc.missing");
  if (missing.length > 0) {
    return {
      requirement: `DMARC record published (at least p=${minimum})`,
      status: "not-met",
      detail: missing[0]!.message,
    };
  }
  const none = findingsByPrefix(report, "dmarc.policy-none");
  return {
    requirement: `DMARC record published (at least p=${minimum})`,
    status: "met",
    detail:
      none.length > 0
        ? "p=none satisfies the minimum requirement; quarantine/reject gives actual spoofing protection"
        : "DMARC policy present and enforcing",
  };
}

const COMMON_AUTH: RequirementSpec[] = [
  {
    requirement: "SPF record valid",
    prefixes: ["spf."],
    okText: "SPF present and within limits",
  },
  {
    requirement: "DKIM signing key published",
    prefixes: ["dkim."],
    okText: "DKIM key found and valid",
  },
];

export function buildChecklist(report: DomainReport, provider: Provider): ProviderChecklist {
  const rdnsSpec: RequirementSpec = {
    requirement: "Sending IPs have forward-confirmed reverse DNS",
    prefixes: ["rdns."],
    okText: "all sending IPs have matching PTR records",
  };
  const blocklistSpec: RequirementSpec = {
    requirement: "Sending IPs not on major blocklists",
    prefixes: ["dnsbl."],
    okText: "no blocklist hits",
  };

  switch (provider) {
    case "gmail":
      return {
        provider,
        providerLabel: "Gmail (Google sender guidelines)",
        items: buildItems(report, [
          ...COMMON_AUTH,
          {
            requirement: "DMARC required for bulk senders (5000+ msgs/day)",
            prefixes: [],
            okText: "",
            custom: (r) => dmarcPolicyItem(r, "none"),
          },
          rdnsSpec,
          blocklistSpec,
          {
            requirement: "TLS on delivery (MTA-STS recommended)",
            prefixes: ["mtasts.", "tlsrpt."],
            okText: "MTA-STS/TLS-RPT posture checked",
          },
        ]),
      };
    case "outlook":
      return {
        provider,
        providerLabel: "Outlook / Microsoft (550 5.7.515 policy)",
        items: buildItems(report, [
          ...COMMON_AUTH,
          {
            requirement: "SPF or DKIM must align for bulk senders (since 2025-05)",
            prefixes: [],
            okText: "",
            custom: (r) => dmarcPolicyItem(r, "none"),
          },
          rdnsSpec,
          blocklistSpec,
        ]),
      };
    case "yahoo":
      return {
        provider,
        providerLabel: "Yahoo (sender requirements)",
        items: buildItems(report, [
          ...COMMON_AUTH,
          {
            requirement: "DMARC required for bulk senders",
            prefixes: [],
            okText: "",
            custom: (r) => dmarcPolicyItem(r, "none"),
          },
          rdnsSpec,
        ]),
      };
  }
}

export const ALL_PROVIDERS: Provider[] = ["gmail", "outlook", "yahoo"];
