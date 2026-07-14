import { describe, expect, it } from "vitest";
import { FixtureResolver } from "../src/net/fixture.js";
import { evaluateSpf } from "../src/spf/evaluator.js";

function resolver(dns: Record<string, unknown>): FixtureResolver {
  return new FixtureResolver(dns);
}

function codes(evaluation: { findings: Array<{ code: string }> }): string[] {
  return evaluation.findings.map((f) => f.code);
}

describe("evaluateSpf", () => {
  it("reports a missing record as a failure", async () => {
    const r = resolver({});
    const evaluation = await evaluateSpf(r, "example.com");
    expect(codes(evaluation)).toContain("spf.missing");
    expect(evaluation.record).toBe("");
  });

  it("counts DNS lookups through nested includes", async () => {
    const r = resolver({
      "TXT:example.com": [["v=spf1 include:a.example.com include:b.example.com -all"]],
      "TXT:a.example.com": [["v=spf1 a mx -all"]],
      "TXT:b.example.com": [["v=spf1 exists:%{i}.chk.example.com -all"]],
    });
    const evaluation = await evaluateSpf(r, "example.com");
    // include:a (1) + a (1) + mx (1) + include:b (1) + exists (1) = 5
    expect(evaluation.lookupCount).toBe(5);
    expect(codes(evaluation)).toContain("spf.lookups");
  });

  it("fails when the 10-lookup limit is exceeded", async () => {
    const includes = Array.from({ length: 11 }, (_, i) => `include:i${i}.example.com`).join(" ");
    const dns: Record<string, unknown> = {
      "TXT:example.com": [[`v=spf1 ${includes} -all`]],
    };
    for (let i = 0; i < 11; i++) dns[`TXT:i${i}.example.com`] = [["v=spf1 -all"]];
    const evaluation = await evaluateSpf(resolver(dns), "example.com");
    expect(evaluation.lookupCount).toBe(11);
    expect(codes(evaluation)).toContain("spf.lookup-limit");
  });

  it("warns when one lookup away from the limit", async () => {
    const includes = Array.from({ length: 9 }, (_, i) => `include:i${i}.example.com`).join(" ");
    const dns: Record<string, unknown> = {
      "TXT:example.com": [[`v=spf1 ${includes} -all`]],
    };
    for (let i = 0; i < 9; i++) dns[`TXT:i${i}.example.com`] = [["v=spf1 -all"]];
    const evaluation = await evaluateSpf(resolver(dns), "example.com");
    expect(codes(evaluation)).toContain("spf.lookup-near-limit");
  });

  it("follows redirect= and counts it as a lookup", async () => {
    const r = resolver({
      "TXT:example.com": [["v=spf1 redirect=_spf.example.com"]],
      "TXT:_spf.example.com": [["v=spf1 ip4:192.0.2.1 -all"]],
    });
    const evaluation = await evaluateSpf(r, "example.com");
    expect(evaluation.lookupCount).toBe(1);
    expect(evaluation.visited).toContain("_spf.example.com");
  });

  it("accepts diamond include graphs without a false loop finding (RFC 7208)", async () => {
    // root -> include:a + include:b, both -> include:common. Legal, not a loop.
    const r = resolver({
      "TXT:diamond.example": [["v=spf1 include:a.diamond.example include:b.diamond.example -all"]],
      "TXT:a.diamond.example": [["v=spf1 include:common.diamond.example -all"]],
      "TXT:b.diamond.example": [["v=spf1 include:common.diamond.example -all"]],
      "TXT:common.diamond.example": [["v=spf1 ip4:192.0.2.0/24 -all"]],
    });
    const evaluation = await evaluateSpf(r, "diamond.example");
    expect(codes(evaluation)).not.toContain("spf.include-loop");
    expect(evaluation.findings.filter((f) => f.severity === "fail")).toEqual([]);
    // include:a (1) + include:common (1) + include:b (1) + include:common (1) = 4,
    // charged per evaluation like a real receiver.
    expect(evaluation.lookupCount).toBe(4);
    expect(evaluation.visited).toEqual([
      "diamond.example",
      "a.diamond.example",
      "common.diamond.example",
      "b.diamond.example",
    ]);
  });

  it("re-counts a shared include's own lookup terms on every visit", async () => {
    const r = resolver({
      "TXT:example.com": [["v=spf1 include:x.example.com include:y.example.com -all"]],
      "TXT:x.example.com": [["v=spf1 include:shared.example.com -all"]],
      "TXT:y.example.com": [["v=spf1 include:shared.example.com -all"]],
      "TXT:shared.example.com": [["v=spf1 a mx -all"]],
    });
    const evaluation = await evaluateSpf(r, "example.com");
    // include:x (1) + include:shared (1) + a (1) + mx (1)
    // + include:y (1) + include:shared (1) + a (1) + mx (1) = 8
    expect(evaluation.lookupCount).toBe(8);
    expect(codes(evaluation)).not.toContain("spf.include-loop");
  });

  it("reports a shared broken include only once", async () => {
    const r = resolver({
      "TXT:example.com": [["v=spf1 include:x.example.com include:y.example.com -all"]],
      "TXT:x.example.com": [["v=spf1 include:gone.example.net -all"]],
      "TXT:y.example.com": [["v=spf1 include:gone.example.net -all"]],
    });
    const evaluation = await evaluateSpf(r, "example.com");
    const unresolvable = codes(evaluation).filter((c) => c === "spf.include-unresolvable");
    expect(unresolvable).toHaveLength(1);
  });

  it("detects include loops", async () => {
    const r = resolver({
      "TXT:example.com": [["v=spf1 include:loop.example.com -all"]],
      "TXT:loop.example.com": [["v=spf1 include:example.com -all"]],
    });
    const evaluation = await evaluateSpf(r, "example.com");
    expect(codes(evaluation)).toContain("spf.include-loop");
  });

  it("fails on unresolvable includes", async () => {
    const r = resolver({
      "TXT:example.com": [["v=spf1 include:gone.example.net -all"]],
    });
    const evaluation = await evaluateSpf(r, "example.com");
    expect(codes(evaluation)).toContain("spf.include-unresolvable");
  });

  it("fails on multiple SPF records at the same name", async () => {
    const r = resolver({
      "TXT:example.com": [["v=spf1 mx -all"], ["v=spf1 a -all"]],
    });
    const evaluation = await evaluateSpf(r, "example.com");
    expect(codes(evaluation)).toContain("spf.multiple-records");
  });

  it("joins multi-chunk TXT records before parsing", async () => {
    const r = resolver({
      "TXT:example.com": [["v=spf1 ip4:192.0.2.1 ", "-all"]],
    });
    const evaluation = await evaluateSpf(r, "example.com");
    expect(evaluation.record).toBe("v=spf1 ip4:192.0.2.1 -all");
    expect(codes(evaluation)).toContain("spf.strict-all");
  });

  it("ignores non-SPF TXT records at the same name", async () => {
    const r = resolver({
      "TXT:example.com": [["google-site-verification=xyz"], ["v=spf1 mx -all"]],
    });
    const evaluation = await evaluateSpf(r, "example.com");
    expect(evaluation.record).toBe("v=spf1 mx -all");
    expect(codes(evaluation)).not.toContain("spf.multiple-records");
  });

  it("grades the all qualifier", async () => {
    const cases: Array<[string, string]> = [
      ["v=spf1 mx +all", "spf.plus-all"],
      ["v=spf1 mx ?all", "spf.neutral-all"],
      ["v=spf1 mx ~all", "spf.softfail-all"],
      ["v=spf1 mx -all", "spf.strict-all"],
      ["v=spf1 mx", "spf.no-all"],
    ];
    for (const [record, expected] of cases) {
      const r = resolver({ "TXT:example.com": [[record]] });
      const evaluation = await evaluateSpf(r, "example.com");
      expect(codes(evaluation), record).toContain(expected);
    }
  });

  it("warns about the deprecated ptr mechanism", async () => {
    const r = resolver({ "TXT:example.com": [["v=spf1 ptr -all"]] });
    const evaluation = await evaluateSpf(r, "example.com");
    expect(codes(evaluation)).toContain("spf.ptr-mechanism");
  });
});
