import { describe, expect, it } from "vitest";
import {
  mxMatchesPolicy,
  parseMtaStsPolicy,
  parseStsDnsRecord,
  parseTlsRptRecord,
} from "../src/mtasts/policy.js";

describe("parseMtaStsPolicy", () => {
  it("parses a valid enforce policy", () => {
    const policy = parseMtaStsPolicy(
      "version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.backup.example.com\nmax_age: 604800\n",
    );
    expect(policy.errors).toEqual([]);
    expect(policy.mode).toBe("enforce");
    expect(policy.mx).toEqual(["mail.example.com", "*.backup.example.com"]);
    expect(policy.maxAge).toBe(604800);
  });

  it("accepts CRLF line endings", () => {
    const policy = parseMtaStsPolicy("version: STSv1\r\nmode: testing\r\nmx: mx.example.com\r\nmax_age: 86400\r\n");
    expect(policy.errors).toEqual([]);
  });

  it("reports missing required keys", () => {
    const policy = parseMtaStsPolicy("mode: enforce\nmx: a.example.com\n");
    expect(policy.errors).toContain("missing required key: version");
    expect(policy.errors).toContain("missing required key: max_age");
  });

  it("rejects unknown modes and keys", () => {
    const policy = parseMtaStsPolicy("version: STSv1\nmode:強制\nfoo: bar\nmax_age: 1\nmx: a.example.com\n");
    expect(policy.errors.some((e) => e.includes("mode must be"))).toBe(true);
    expect(policy.errors.some((e) => e.includes('unknown key "foo"'))).toBe(true);
  });

  it("requires mx entries unless mode is none", () => {
    expect(
      parseMtaStsPolicy("version: STSv1\nmode: enforce\nmax_age: 1\n").errors,
    ).toContain("policy lists no mx hosts");
    expect(parseMtaStsPolicy("version: STSv1\nmode: none\nmax_age: 1\n").errors).toEqual([]);
  });
});

describe("mxMatchesPolicy", () => {
  it("matches exact hosts case-insensitively", () => {
    expect(mxMatchesPolicy("Mail.Example.COM.", ["mail.example.com"])).toBe(true);
    expect(mxMatchesPolicy("other.example.com", ["mail.example.com"])).toBe(false);
  });

  it("matches wildcards for exactly one label", () => {
    expect(mxMatchesPolicy("mx1.example.com", ["*.example.com"])).toBe(true);
    expect(mxMatchesPolicy("deep.mx1.example.com", ["*.example.com"])).toBe(false);
    expect(mxMatchesPolicy("example.com", ["*.example.com"])).toBe(false);
  });
});

describe("parseStsDnsRecord", () => {
  it("parses a valid record", () => {
    const rec = parseStsDnsRecord("v=STSv1; id=20260708T120000");
    expect(rec.errors).toEqual([]);
    expect(rec.id).toBe("20260708T120000");
  });

  it("rejects missing or malformed id", () => {
    expect(parseStsDnsRecord("v=STSv1").errors.some((e) => e.includes("id="))).toBe(true);
    expect(
      parseStsDnsRecord("v=STSv1; id=has spaces!").errors.some((e) => e.includes("id=")),
    ).toBe(true);
  });
});

describe("parseTlsRptRecord", () => {
  it("parses mailto and https destinations", () => {
    const rec = parseTlsRptRecord("v=TLSRPTv1; rua=mailto:tls@example.com,https://report.example.com/tlsrpt");
    expect(rec.errors).toEqual([]);
    expect(rec.rua).toHaveLength(2);
  });

  it("requires a rua destination", () => {
    const rec = parseTlsRptRecord("v=TLSRPTv1");
    expect(rec.errors.some((e) => e.includes("rua"))).toBe(true);
  });

  it("rejects wrong version", () => {
    const rec = parseTlsRptRecord("v=TLSRPTv2; rua=mailto:a@b.example");
    expect(rec.errors.some((e) => e.includes("TLSRPTv1"))).toBe(true);
  });
});
