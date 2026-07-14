import { readFileSync } from "node:fs";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { parseAggregateReport, summarizeReport } from "../src/dmarc/report.js";

const XML_PATH = join(__dirname, "fixtures", "google-aggregate.xml");
const xml = readFileSync(XML_PATH);

describe("parseAggregateReport", () => {
  it("parses reporter metadata and policy", () => {
    const report = parseAggregateReport(xml);
    expect(report.reporter).toBe("google.com");
    expect(report.reportId).toBe("8293815353711483749");
    expect(report.domain).toBe("example.org");
    expect(report.policy.p).toBe("none");
    expect(report.policy.pct).toBe(100);
    expect(report.begin.toISOString()).toBe("2025-07-05T00:00:00.000Z");
    expect(report.end.toISOString()).toBe("2025-07-05T23:59:59.000Z");
  });

  it("parses rows with DMARC pass/fail evaluation", () => {
    const report = parseAggregateReport(xml);
    expect(report.rows).toHaveLength(3);
    const [good, forwarded, spoof] = report.rows;
    expect(good).toMatchObject({ sourceIp: "192.0.2.10", count: 42, dmarcPass: true });
    expect(good?.authDetails).toContain("dkim example.org (s=mail): pass");
    expect(forwarded).toMatchObject({ sourceIp: "198.51.100.77", count: 7, dmarcPass: false });
    expect(spoof).toMatchObject({ sourceIp: "203.0.113.5", count: 3, dmarcPass: false });
  });

  it("accepts gzip-compressed reports", () => {
    const report = parseAggregateReport(gzipSync(xml));
    expect(report.rows).toHaveLength(3);
    expect(report.reporter).toBe("google.com");
  });

  it("handles a single <record> element (not wrapped in an array)", () => {
    const single = Buffer.from(
      `<?xml version="1.0"?><feedback>
        <report_metadata><org_name>r</org_name><report_id>1</report_id>
          <date_range><begin>1700000000</begin><end>1700086400</end></date_range>
        </report_metadata>
        <policy_published><domain>d.example</domain><p>reject</p></policy_published>
        <record><row><source_ip>192.0.2.1</source_ip><count>5</count>
          <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
        </row><identifiers><header_from>d.example</header_from></identifiers>
        <auth_results><spf><domain>d.example</domain><result>pass</result></spf></auth_results>
        </record></feedback>`,
    );
    const report = parseAggregateReport(single);
    expect(report.rows).toHaveLength(1);
    expect(report.rows[0]?.count).toBe(5);
  });

  it("rejects non-XML input with a readable message", () => {
    expect(() => parseAggregateReport(Buffer.from("{}"))).toThrow(/feedback|XML/);
  });

  it("rejects XML that is not a DMARC report", () => {
    expect(() => parseAggregateReport(Buffer.from("<html><body/></html>"))).toThrow(
      /missing <feedback>/,
    );
  });

  it("rejects a report with no date range", () => {
    expect(() =>
      parseAggregateReport(Buffer.from("<feedback><report_metadata/></feedback>")),
    ).toThrow(/date_range/);
  });
});

describe("summarizeReport", () => {
  it("aggregates totals and pass rate", () => {
    const summary = summarizeReport(parseAggregateReport(xml));
    expect(summary.totalMessages).toBe(52);
    expect(summary.passMessages).toBe(42);
    expect(summary.failMessages).toBe(10);
    expect(summary.passRate).toBeCloseTo(42 / 52, 5);
  });

  it("sorts sources by volume and assigns verdicts", () => {
    const summary = summarizeReport(parseAggregateReport(xml));
    expect(summary.sources.map((s) => s.sourceIp)).toEqual([
      "192.0.2.10",
      "198.51.100.77",
      "203.0.113.5",
    ]);
    expect(summary.sources[0]?.verdict).toBe("authenticating correctly");
    expect(summary.sources[1]?.verdict).toContain("fix SPF/DKIM");
    expect(summary.sources[2]?.verdict).toContain("fix SPF/DKIM");
  });

  it("marks quarantined all-fail sources as spoofer-or-forgotten", () => {
    const report = parseAggregateReport(xml);
    const onlyBad = {
      ...report,
      rows: report.rows
        .filter((r) => !r.dmarcPass)
        .map((r) => ({ ...r, disposition: "reject" })),
    };
    const summary = summarizeReport(onlyBad);
    expect(summary.sources.every((s) => s.verdict.includes("quarantined/rejected"))).toBe(true);
  });
});
