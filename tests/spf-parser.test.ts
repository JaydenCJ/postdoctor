import { describe, expect, it } from "vitest";
import { isValidIp4, isValidIp6, looksLikeSpf, parseSpf } from "../src/spf/parser.js";

describe("parseSpf", () => {
  it("parses a typical self-hosted record", () => {
    const rec = parseSpf("v=spf1 mx a ip4:192.0.2.10 include:_spf.example.net -all");
    expect(rec.errors).toEqual([]);
    expect(rec.terms).toHaveLength(5);
    expect(rec.allQualifier).toBe("-");
    const include = rec.terms.find((t) => t.type === "mechanism" && t.kind === "include");
    expect(include).toMatchObject({ value: "_spf.example.net" });
  });

  it("rejects records that do not start with v=spf1", () => {
    const rec = parseSpf("spf1 mx -all");
    expect(rec.errors[0]?.message).toContain("v=spf1");
    expect(rec.terms).toEqual([]);
  });

  it("parses qualifiers on mechanisms", () => {
    const rec = parseSpf("v=spf1 ?a ~mx -include:x.example +all");
    const quals = rec.terms
      .filter((t) => t.type === "mechanism")
      .map((t) => (t.type === "mechanism" ? t.qualifier : ""));
    expect(quals).toEqual(["?", "~", "-", "+"]);
    expect(rec.allQualifier).toBe("+");
  });

  it("parses CIDR suffixes on a and mx", () => {
    const rec = parseSpf("v=spf1 a/24 mx:mail.example.com/28 -all");
    const a = rec.terms[0];
    const mx = rec.terms[1];
    expect(a).toMatchObject({ kind: "a", cidr: "/24" });
    expect(mx).toMatchObject({ kind: "mx", value: "mail.example.com", cidr: "/28" });
    expect(rec.errors).toEqual([]);
  });

  it("rejects out-of-range CIDR prefix lengths", () => {
    const rec = parseSpf("v=spf1 ip4:192.0.2.0/33 -all");
    expect(rec.errors[0]?.message).toContain("/33");
  });

  it("validates ip4 addresses", () => {
    const rec = parseSpf("v=spf1 ip4:999.1.2.3 -all");
    expect(rec.errors[0]?.message).toContain("not a valid IPv4");
    expect(parseSpf("v=spf1 ip4:203.0.113.25 -all").errors).toEqual([]);
  });

  it("parses ip6 with prefix length without treating colons as separators", () => {
    const rec = parseSpf("v=spf1 ip6:2001:db8::1 ip6:2001:db8::/32 -all");
    expect(rec.errors).toEqual([]);
    const values = rec.terms
      .filter((t) => t.type === "mechanism" && t.kind === "ip6")
      .map((t) => (t.type === "mechanism" ? `${t.value}${t.cidr ?? ""}` : ""));
    expect(values).toEqual(["2001:db8::1", "2001:db8::/32"]);
  });

  it("accepts real-world ip6 networks with /64 prefixes", () => {
    // Regression: seen live at migadu.com — /64 on ip6 is an IPv6 prefix length.
    const rec = parseSpf("v=spf1 ip6:2001:41d0:1004:224b::/64 ip6:2001:41d0:700:1aac::1/64 -all");
    expect(rec.errors).toEqual([]);
    expect(parseSpf("v=spf1 ip6:2001:db8::/129 -all").errors[0]?.message).toContain("exceeds 128");
  });

  it("rejects malformed ip6 values", () => {
    expect(parseSpf("v=spf1 ip6:2001::db8::1 -all").errors).toHaveLength(1);
    expect(parseSpf("v=spf1 ip6:gggg::1 -all").errors).toHaveLength(1);
  });

  it("requires a value for include/ip4/ip6/exists", () => {
    for (const term of ["include", "ip4", "ip6", "exists"]) {
      const rec = parseSpf(`v=spf1 ${term} -all`);
      expect(rec.errors[0]?.message).toContain("requires a value");
    }
  });

  it("captures redirect modifier", () => {
    const rec = parseSpf("v=spf1 redirect=_spf.example.com");
    expect(rec.redirect).toBe("_spf.example.com");
    expect(rec.errors).toEqual([]);
  });

  it("flags redirect combined with all as ignored", () => {
    const rec = parseSpf("v=spf1 redirect=_spf.example.com -all");
    expect(rec.errors.some((e) => e.message.includes("redirect"))).toBe(true);
  });

  it("flags unknown mechanisms and unknown modifiers", () => {
    const rec = parseSpf("v=spf1 ipv4:1.2.3.4 foo=bar -all");
    expect(rec.errors.some((e) => e.message.includes('unknown mechanism "ipv4"'))).toBe(true);
    expect(rec.errors.some((e) => e.message.includes('unknown modifier "foo"'))).toBe(true);
  });

  it('rejects arguments on "all"', () => {
    const rec = parseSpf("v=spf1 all:example.com");
    expect(rec.errors[0]?.message).toContain('"all" takes no arguments');
  });

  it("handles an empty record body", () => {
    const rec = parseSpf("v=spf1");
    expect(rec.errors).toEqual([]);
    expect(rec.terms).toEqual([]);
    expect(rec.allQualifier).toBeUndefined();
  });
});

describe("helpers", () => {
  it("looksLikeSpf distinguishes SPF from verification records", () => {
    expect(looksLikeSpf("v=spf1 mx -all")).toBe(true);
    expect(looksLikeSpf("v=spf10 mx")).toBe(false);
    expect(looksLikeSpf("google-site-verification=abc")).toBe(false);
  });

  it("isValidIp4 enforces octet ranges", () => {
    expect(isValidIp4("255.255.255.255")).toBe(true);
    expect(isValidIp4("256.1.1.1")).toBe(false);
    expect(isValidIp4("1.2.3")).toBe(false);
  });

  it("isValidIp6 enforces group counts", () => {
    expect(isValidIp6("2001:db8::1")).toBe(true);
    expect(isValidIp6("::1")).toBe(true);
    expect(isValidIp6("1:2:3:4:5:6:7:8")).toBe(true);
    expect(isValidIp6("1:2:3:4:5:6:7:8:9")).toBe(false);
    expect(isValidIp6("2001:db8")).toBe(false);
  });
});
