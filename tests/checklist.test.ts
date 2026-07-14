import { describe, expect, it } from "vitest";
import { ALL_PROVIDERS, buildChecklist } from "../src/checklist.js";
import type { DomainReport } from "../src/types.js";
import { fail, pass, warn } from "../src/types.js";

function reportWith(findings: Array<{ area: string; f: ReturnType<typeof pass> }>): DomainReport {
  const areas = new Map<string, ReturnType<typeof pass>[]>();
  for (const { area, f } of findings) {
    areas.set(area, [...(areas.get(area) ?? []), f]);
  }
  return {
    domain: "example.com",
    checkedAt: new Date().toISOString(),
    results: [...areas.entries()].map(([area, fs]) => ({
      area,
      title: area.toUpperCase(),
      records: [],
      findings: fs,
    })),
  };
}

const healthy = reportWith([
  { area: "spf", f: pass("spf.strict-all", "ok") },
  { area: "dkim", f: pass("dkim.key", "ok") },
  { area: "dmarc", f: pass("dmarc.policy", "ok") },
  { area: "mtasts", f: pass("mtasts.policy", "ok") },
  { area: "rdns", f: pass("rdns.fcrdns", "ok") },
  { area: "dnsbl", f: pass("dnsbl.clean", "ok") },
]);

describe("buildChecklist", () => {
  it("marks everything met for a healthy report", () => {
    for (const provider of ALL_PROVIDERS) {
      const list = buildChecklist(healthy, provider);
      expect(list.items.length).toBeGreaterThanOrEqual(4);
      expect(list.items.every((i) => i.status === "met"), provider).toBe(true);
    }
  });

  it("marks SPF requirement not-met when SPF fails", () => {
    const report = reportWith([
      { area: "spf", f: fail("spf.missing", "no SPF record found for example.com") },
      { area: "dkim", f: pass("dkim.key", "ok") },
      { area: "dmarc", f: pass("dmarc.policy", "ok") },
      { area: "rdns", f: pass("rdns.fcrdns", "ok") },
    ]);
    const list = buildChecklist(report, "gmail");
    const spfItem = list.items.find((i) => i.requirement.includes("SPF"))!;
    expect(spfItem.status).toBe("not-met");
    expect(spfItem.detail).toContain("no SPF record");
  });

  it("treats p=none as meeting the minimum DMARC requirement with a caveat", () => {
    const report = reportWith([
      { area: "spf", f: pass("spf.strict-all", "ok") },
      { area: "dkim", f: pass("dkim.key", "ok") },
      { area: "dmarc", f: warn("dmarc.policy-none", "policy is p=none") },
      { area: "rdns", f: pass("rdns.fcrdns", "ok") },
    ]);
    const list = buildChecklist(report, "gmail");
    const dmarcItem = list.items.find((i) => i.requirement.includes("DMARC"))!;
    expect(dmarcItem.status).toBe("met");
    expect(dmarcItem.detail).toContain("p=none");
  });

  it("marks DMARC not-met when the record is missing", () => {
    const report = reportWith([
      { area: "dmarc", f: fail("dmarc.missing", "no DMARC record at _dmarc.example.com") },
    ]);
    for (const provider of ALL_PROVIDERS) {
      const list = buildChecklist(report, provider);
      const dmarcItem = list.items.find((i) => i.detail.includes("_dmarc") || i.requirement.includes("DMARC") || i.requirement.includes("align"));
      expect(dmarcItem?.status, provider).toBe("not-met");
    }
  });

  it("flags blocklist hits as not-met for gmail and outlook", () => {
    const report = reportWith([
      { area: "dnsbl", f: fail("dnsbl.listed", "192.0.2.10 is listed on zen.spamhaus.org") },
    ]);
    for (const provider of ["gmail", "outlook"] as const) {
      const list = buildChecklist(report, provider);
      const item = list.items.find((i) => i.requirement.includes("blocklist"))!;
      expect(item.status).toBe("not-met");
      expect(item.detail).toContain("zen.spamhaus.org");
    }
  });

  it("reports unknown when an area was never checked", () => {
    const report = reportWith([{ area: "spf", f: pass("spf.strict-all", "ok") }]);
    const list = buildChecklist(report, "yahoo");
    const rdnsItem = list.items.find((i) => i.requirement.includes("reverse DNS"))!;
    expect(rdnsItem.status).toBe("unknown");
  });
});
