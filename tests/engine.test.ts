import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { FixtureFetcher, FixtureResolver } from "../src/net/fixture.js";
import {
  checkDkim,
  checkDnsbl,
  checkMtaSts,
  checkRdns,
  discoverSendingIps,
  dnsblQueryName,
  runChecks,
} from "../src/engine.js";
import { overallSeverity, reportSeverity } from "../src/types.js";

const RSA_2048 = generateKeyPairSync("rsa", { modulusLength: 2048 })
  .publicKey.export({ type: "spki", format: "der" })
  .toString("base64");

/** A fully healthy self-hosted mail domain. */
function healthyDns(): Record<string, unknown> {
  return {
    "TXT:example.com": [["v=spf1 mx -all"]],
    "TXT:_dmarc.example.com": [["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]],
    "TXT:mail._domainkey.example.com": [[`v=DKIM1; k=rsa; p=${RSA_2048}`]],
    "TXT:_mta-sts.example.com": [["v=STSv1; id=20260701120000"]],
    "TXT:_smtp._tls.example.com": [["v=TLSRPTv1; rua=mailto:tls@example.com"]],
    "MX:example.com": [{ exchange: "mail.example.com", priority: 10 }],
    "A:mail.example.com": ["192.0.2.10"],
    "PTR:192.0.2.10": ["mail.example.com"],
  };
}

const STS_POLICY = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800\n";
const STS_URL = "https://mta-sts.example.com/.well-known/mta-sts.txt";

describe("checkDkim", () => {
  it("finds a key under a probed selector", async () => {
    const resolver = new FixtureResolver(healthyDns());
    const result = await checkDkim(resolver, "example.com", ["mail"]);
    expect(result.findings.some((f) => f.code === "dkim.key" && f.severity === "pass")).toBe(true);
  });

  it("fails when no selector matches", async () => {
    const resolver = new FixtureResolver(healthyDns());
    const result = await checkDkim(resolver, "example.com", ["default", "s1"]);
    expect(result.findings[0]?.code).toBe("dkim.missing");
    expect(result.findings[0]?.severity).toBe("fail");
  });

  it("ignores unrelated wildcard TXT records at selector names", async () => {
    // Regression: seen live — a bare provider marker TXT under *._domainkey.
    const resolver = new FixtureResolver({
      "TXT:default._domainkey.example.com": [["migadu"]],
    });
    const result = await checkDkim(resolver, "example.com", ["default"]);
    const codes = result.findings.map((f) => f.code);
    expect(codes).toContain("dkim.non-dkim-txt");
    expect(codes).toContain("dkim.missing");
    expect(result.findings.some((f) => f.message.includes("malformed"))).toBe(false);
  });

  it("warns on testing mode", async () => {
    const resolver = new FixtureResolver({
      "TXT:sel._domainkey.example.com": [[`v=DKIM1; t=y; p=${RSA_2048}`]],
    });
    const result = await checkDkim(resolver, "example.com", ["sel"]);
    expect(result.findings.some((f) => f.code === "dkim.testing")).toBe(true);
  });
});

describe("checkMtaSts", () => {
  it("passes with a valid policy that covers the MX", async () => {
    const resolver = new FixtureResolver(healthyDns());
    const fetcher = new FixtureFetcher({ [STS_URL]: STS_POLICY });
    const result = await checkMtaSts(resolver, fetcher, "example.com");
    expect(result.findings.some((f) => f.code === "mtasts.policy" && f.severity === "pass")).toBe(true);
    expect(result.findings.some((f) => f.code === "mtasts.mx-mismatch")).toBe(false);
  });

  it("fails when an MX host is outside the policy", async () => {
    const dns = healthyDns();
    dns["MX:example.com"] = [{ exchange: "other-mx.example.net", priority: 10 }];
    const resolver = new FixtureResolver(dns);
    const fetcher = new FixtureFetcher({ [STS_URL]: STS_POLICY });
    const result = await checkMtaSts(resolver, fetcher, "example.com");
    expect(result.findings.some((f) => f.code === "mtasts.mx-mismatch")).toBe(true);
  });

  it("fails when the policy file is unreachable", async () => {
    const resolver = new FixtureResolver(healthyDns());
    const fetcher = new FixtureFetcher({});
    const result = await checkMtaSts(resolver, fetcher, "example.com");
    expect(result.findings.some((f) => f.code === "mtasts.policy-fetch")).toBe(true);
  });

  it("is informational when MTA-STS is absent entirely", async () => {
    const resolver = new FixtureResolver({});
    const fetcher = new FixtureFetcher({});
    const result = await checkMtaSts(resolver, fetcher, "example.com");
    expect(overallSeverity(result.findings)).toBe("pass");
  });
});

describe("rDNS", () => {
  it("discovers sending IPs from MX records", async () => {
    const resolver = new FixtureResolver(healthyDns());
    const { ips } = await discoverSendingIps(resolver, "example.com");
    expect(ips).toEqual(["192.0.2.10"]);
  });

  it("confirms FCrDNS on a healthy setup", async () => {
    const resolver = new FixtureResolver(healthyDns());
    const result = await checkRdns(resolver, "example.com", ["192.0.2.10"]);
    expect(result.findings[0]?.code).toBe("rdns.fcrdns");
    expect(result.findings[0]?.severity).toBe("pass");
  });

  it("fails on a missing PTR", async () => {
    const resolver = new FixtureResolver({});
    const result = await checkRdns(resolver, "example.com", ["192.0.2.99"]);
    expect(result.findings[0]?.code).toBe("rdns.missing-ptr");
  });

  it("fails when PTR does not forward-confirm", async () => {
    const resolver = new FixtureResolver({
      "PTR:192.0.2.10": ["mail.example.com"],
      "A:mail.example.com": ["203.0.113.1"],
    });
    const result = await checkRdns(resolver, "example.com", ["192.0.2.10"]);
    expect(result.findings[0]?.code).toBe("rdns.not-confirmed");
  });
});

describe("DNSBL", () => {
  it("builds reversed query names", () => {
    expect(dnsblQueryName("192.0.2.10", "zen.spamhaus.org")).toBe("10.2.0.192.zen.spamhaus.org");
    expect(dnsblQueryName("2001:db8::1", "zen.spamhaus.org")).toBeUndefined();
  });

  it("reports clean IPs", async () => {
    const resolver = new FixtureResolver({});
    const result = await checkDnsbl(resolver, ["192.0.2.10"], ["bl.example.net"]);
    expect(result.findings[0]?.code).toBe("dnsbl.clean");
  });

  it("treats 127.255.255.x answers as query-refused, not a listing", async () => {
    const resolver = new FixtureResolver({
      "A:10.2.0.192.zen.spamhaus.org": ["127.255.255.254"],
    });
    const result = await checkDnsbl(resolver, ["192.0.2.10"], ["zen.spamhaus.org"]);
    const codes = result.findings.map((f) => f.code);
    expect(codes).toContain("dnsbl.query-refused");
    expect(codes).toContain("dnsbl.clean");
    expect(codes).not.toContain("dnsbl.listed");
  });

  it("reports listed IPs with the answer code", async () => {
    const resolver = new FixtureResolver({
      "A:10.2.0.192.bl.example.net": ["127.0.0.2"],
    });
    const result = await checkDnsbl(resolver, ["192.0.2.10"], ["bl.example.net"]);
    expect(result.findings[0]?.code).toBe("dnsbl.listed");
    expect(result.findings[0]?.message).toContain("127.0.0.2");
  });
});

describe("runChecks (full engine)", () => {
  it("produces an all-green report for a healthy domain", async () => {
    const resolver = new FixtureResolver(healthyDns());
    const fetcher = new FixtureFetcher({ [STS_URL]: STS_POLICY });
    const report = await runChecks(resolver, fetcher, "example.com", {
      selectors: ["mail"],
      dnsblZones: ["bl.example.net"],
    });
    expect(report.results.map((r) => r.area)).toEqual([
      "spf",
      "dkim",
      "dmarc",
      "mtasts",
      "rdns",
      "dnsbl",
    ]);
    expect(reportSeverity(report)).toBe("pass");
  });

  it("degrades to fail when records are broken", async () => {
    const dns = healthyDns();
    dns["TXT:example.com"] = [["v=spf1 mx +all"]];
    delete dns["TXT:_dmarc.example.com"];
    const resolver = new FixtureResolver(dns);
    const fetcher = new FixtureFetcher({ [STS_URL]: STS_POLICY });
    const report = await runChecks(resolver, fetcher, "example.com", {
      selectors: ["mail"],
      skipDnsbl: true,
    });
    const allCodes = report.results.flatMap((r) => r.findings).map((f) => f.code);
    expect(allCodes).toContain("spf.plus-all");
    expect(allCodes).toContain("dmarc.missing");
    expect(reportSeverity(report)).toBe("fail");
  });
});
