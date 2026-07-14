import { describe, expect, it } from "vitest";
import { looksLikeDmarc, parseDmarcRecord } from "../src/dmarc/record.js";

describe("parseDmarcRecord", () => {
  it("parses a full record", () => {
    const rec = parseDmarcRecord(
      "v=DMARC1; p=quarantine; sp=reject; pct=50; rua=mailto:agg@example.com,mailto:agg@thirdparty.net; adkim=s; aspf=r",
    );
    expect(rec.errors).toEqual([]);
    expect(rec.policy).toBe("quarantine");
    expect(rec.subdomainPolicy).toBe("reject");
    expect(rec.pct).toBe(50);
    expect(rec.rua).toEqual(["agg@example.com", "agg@thirdparty.net"]);
    expect(rec.adkim).toBe("s");
    expect(rec.aspf).toBe("r");
  });

  it("defaults pct to 100 and alignment to relaxed", () => {
    const rec = parseDmarcRecord("v=DMARC1; p=none");
    expect(rec.pct).toBe(100);
    expect(rec.adkim).toBe("r");
    expect(rec.aspf).toBe("r");
    expect(rec.errors).toEqual([]);
  });

  it("requires v=DMARC1 as the first tag", () => {
    const rec = parseDmarcRecord("p=none; v=DMARC1");
    expect(rec.errors.some((e) => e.includes("first tag"))).toBe(true);
  });

  it("requires the p= tag", () => {
    const rec = parseDmarcRecord("v=DMARC1; rua=mailto:a@b.example");
    expect(rec.errors.some((e) => e.includes("p="))).toBe(true);
    expect(rec.policy).toBeUndefined();
  });

  it("rejects invalid policy values", () => {
    const rec = parseDmarcRecord("v=DMARC1; p=block");
    expect(rec.errors.some((e) => e.includes("none, quarantine or reject"))).toBe(true);
  });

  it("rejects out-of-range pct", () => {
    expect(parseDmarcRecord("v=DMARC1; p=none; pct=150").errors).toHaveLength(1);
    expect(parseDmarcRecord("v=DMARC1; p=none; pct=-1").errors).toHaveLength(1);
    expect(parseDmarcRecord("v=DMARC1; p=none; pct=abc").errors).toHaveLength(1);
  });

  it("accepts rua with size limit suffix", () => {
    const rec = parseDmarcRecord("v=DMARC1; p=none; rua=mailto:agg@example.com!10m");
    expect(rec.rua).toEqual(["agg@example.com"]);
    expect(rec.errors).toEqual([]);
  });

  it("rejects non-mailto rua entries", () => {
    const rec = parseDmarcRecord("v=DMARC1; p=none; rua=https://example.com/report");
    expect(rec.errors.some((e) => e.includes("mailto"))).toBe(true);
    expect(rec.rua).toEqual([]);
  });

  it("flags unknown tags", () => {
    const rec = parseDmarcRecord("v=DMARC1; p=none; foo=bar");
    expect(rec.errors.some((e) => e.includes('unknown tag "foo"'))).toBe(true);
  });

  it("rejects invalid alignment modes", () => {
    const rec = parseDmarcRecord("v=DMARC1; p=none; adkim=x");
    expect(rec.errors.some((e) => e.includes("adkim"))).toBe(true);
  });
});

describe("looksLikeDmarc", () => {
  it("matches only DMARC records", () => {
    expect(looksLikeDmarc("v=DMARC1; p=none")).toBe(true);
    expect(looksLikeDmarc("v=DMARC1")).toBe(true);
    expect(looksLikeDmarc("v=spf1 -all")).toBe(false);
    expect(looksLikeDmarc("v=DMARC10; p=none")).toBe(false);
  });
});
