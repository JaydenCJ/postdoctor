import { describe, expect, it } from "vitest";
import { generateRecords, quoteTxt, toZoneFile } from "../src/gen/generate.js";
import { diffSnapshots, takeSnapshot } from "../src/gen/diff.js";
import type { DnsSnapshot } from "../src/gen/diff.js";
import { FixtureResolver } from "../src/net/fixture.js";
import { parseSpf } from "../src/spf/parser.js";
import { parseDmarcRecord } from "../src/dmarc/record.js";

describe("generateRecords", () => {
  it("generates SPF from explicit IPs and includes", () => {
    const set = generateRecords({
      domain: "example.com",
      ips: ["192.0.2.10", "2001:db8::25"],
      includes: ["_spf.relay.example.net"],
    });
    const spf = set.records.find((r) => r.name === "example.com")!;
    expect(spf.value).toBe(
      "v=spf1 ip4:192.0.2.10 ip6:2001:db8::25 include:_spf.relay.example.net -all",
    );
    // The generated record must satisfy our own parser.
    expect(parseSpf(spf.value).errors).toEqual([]);
  });

  it("falls back to mx when no sources are given", () => {
    const set = generateRecords({ domain: "example.com" });
    const spf = set.records.find((r) => r.name === "example.com")!;
    expect(spf.value).toBe("v=spf1 mx -all");
  });

  it("rejects invalid IPs and domains with readable errors", () => {
    expect(() => generateRecords({ domain: "example.com", ips: ["999.9.9.9"] })).toThrow(
      /not a valid IPv4 or IPv6/,
    );
    expect(() => generateRecords({ domain: "not a domain" })).toThrow(/not a valid domain/);
  });

  it("generates a parseable DMARC record with the requested policy", () => {
    const set = generateRecords({ domain: "example.com", policy: "quarantine", rua: "agg@example.com" });
    const dmarc = set.records.find((r) => r.name === "_dmarc.example.com")!;
    const parsed = parseDmarcRecord(dmarc.value);
    expect(parsed.errors).toEqual([]);
    expect(parsed.policy).toBe("quarantine");
    expect(parsed.rua).toEqual(["agg@example.com"]);
  });

  it("emits a DKIM record when selector and key are given", () => {
    const set = generateRecords({
      domain: "example.com",
      selector: "mail",
      dkimPublicKey: "MIIBIjANBg",
    });
    const dkim = set.records.find((r) => r.name === "mail._domainkey.example.com");
    expect(dkim?.value).toBe("v=DKIM1; k=rsa; p=MIIBIjANBg");
  });

  it("emits MTA-STS records plus a policy file, and can skip them", () => {
    const withSts = generateRecords({ domain: "example.com", mxHosts: ["mx1.example.com"] });
    expect(withSts.records.some((r) => r.name === "_mta-sts.example.com")).toBe(true);
    expect(withSts.mtaStsPolicyFile).toContain("mx: mx1.example.com");

    const withoutSts = generateRecords({ domain: "example.com", mtaSts: false });
    expect(withoutSts.records.some((r) => r.name === "_mta-sts.example.com")).toBe(false);
    expect(withoutSts.mtaStsPolicyFile).toBeUndefined();
  });

  it("renders zone-file output with comments", () => {
    const zone = toZoneFile(generateRecords({ domain: "example.com" }));
    expect(zone).toContain("example.com. 3600 IN TXT");
    expect(zone).toContain("; SPF:");
  });
});

describe("quoteTxt", () => {
  it("splits values over 255 chars into chunks", () => {
    const long = "a".repeat(300);
    const quoted = quoteTxt(long);
    expect(quoted).toBe(`"${"a".repeat(255)}" "${"a".repeat(45)}"`);
  });

  it("escapes embedded quotes", () => {
    expect(quoteTxt('say "hi"')).toBe('"say \\"hi\\""');
  });
});

describe("snapshot + diff", () => {
  const baseDns = {
    "TXT:example.com": [["v=spf1 mx -all"]],
    "TXT:_dmarc.example.com": [["v=DMARC1; p=none; rua=mailto:d@example.com"]],
    "MX:example.com": [{ exchange: "mail.example.com", priority: 10 }],
  };

  it("takes a snapshot of watched names", async () => {
    const snapshot = await takeSnapshot(new FixtureResolver(baseDns), "example.com", ["mail"]);
    expect(snapshot.txt["example.com"]).toEqual(["v=spf1 mx -all"]);
    expect(snapshot.mx).toEqual(["10 mail.example.com"]);
    expect(snapshot.txt["_mta-sts.example.com"]).toBeUndefined();
  });

  it("reports no drift for identical state", async () => {
    const resolver = new FixtureResolver(baseDns);
    const a = await takeSnapshot(resolver, "example.com", ["mail"]);
    const b = await takeSnapshot(resolver, "example.com", ["mail"]);
    expect(diffSnapshots(a, b)).toEqual([]);
  });

  it("detects changed, added and removed records", async () => {
    const before = await takeSnapshot(new FixtureResolver(baseDns), "example.com", ["mail"]);
    const after: DnsSnapshot = {
      domain: "example.com",
      takenAt: new Date().toISOString(),
      txt: {
        "example.com": ["v=spf1 mx include:evil.example.net -all"],
        "_mta-sts.example.com": ["v=STSv1; id=1"],
      },
      mx: ["10 mail.example.com"],
    };
    const changes = diffSnapshots(before, after);
    const kinds = changes.map((c) => `${c.kind}:${c.name}`).sort();
    expect(kinds).toEqual([
      "added:_mta-sts.example.com",
      "changed:example.com",
      "removed:_dmarc.example.com",
    ]);
    const changed = changes.find((c) => c.kind === "changed")!;
    expect(changed.before).toBe("v=spf1 mx -all");
    expect(changed.after).toContain("evil.example.net");
  });

  it("detects MX changes", async () => {
    const before = await takeSnapshot(new FixtureResolver(baseDns), "example.com", []);
    const after = await takeSnapshot(
      new FixtureResolver({
        ...baseDns,
        "MX:example.com": [{ exchange: "mx.attacker.example", priority: 5 }],
      }),
      "example.com",
      [],
    );
    const changes = diffSnapshots(before, after);
    expect(changes).toHaveLength(1);
    expect(changes[0]?.name).toContain("(MX)");
    expect(changes[0]?.after).toContain("mx.attacker.example");
  });
});
