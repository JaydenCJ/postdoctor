import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { FixtureFetcher, FixtureResolver } from "../src/net/fixture.js";
import type { DnsResolver, MxRecord } from "../src/net/resolver.js";
import { ntfyChannel, telegramChannel, watch } from "../src/watch.js";

const RSA_2048 = generateKeyPairSync("rsa", { modulusLength: 2048 })
  .publicKey.export({ type: "spki", format: "der" })
  .toString("base64");

function healthyDns(): Record<string, unknown> {
  return {
    "TXT:example.com": [["v=spf1 mx -all"]],
    "TXT:_dmarc.example.com": [["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]],
    "TXT:mail._domainkey.example.com": [[`v=DKIM1; k=rsa; p=${RSA_2048}`]],
    "MX:example.com": [{ exchange: "mail.example.com", priority: 10 }],
    "A:mail.example.com": ["192.0.2.10"],
    "PTR:192.0.2.10": ["mail.example.com"],
  };
}

/** Resolver whose backing data can be swapped between cycles. */
class MutableResolver implements DnsResolver {
  public inner: FixtureResolver;
  constructor(dns: Record<string, unknown>) {
    this.inner = new FixtureResolver(dns);
  }
  swap(dns: Record<string, unknown>): void {
    this.inner = new FixtureResolver(dns);
  }
  resolveTxt(name: string): Promise<string[][]> {
    return this.inner.resolveTxt(name);
  }
  resolveMx(name: string): Promise<MxRecord[]> {
    return this.inner.resolveMx(name);
  }
  resolveA(name: string): Promise<string[]> {
    return this.inner.resolveA(name);
  }
  resolveAaaa(name: string): Promise<string[]> {
    return this.inner.resolveAaaa(name);
  }
  reverse(ip: string): Promise<string[]> {
    return this.inner.reverse(ip);
  }
}

const noSleep = async () => {};

describe("watch", () => {
  it("stays quiet across cycles when nothing changes", async () => {
    const resolver = new MutableResolver(healthyDns());
    const fetcher = new FixtureFetcher({});
    const logs: string[] = [];
    const outcomes = await watch(resolver, fetcher, "example.com", {
      selectors: ["mail"],
      skipDnsbl: true,
      maxCycles: 2,
      intervalSeconds: 1,
      sleep: noSleep,
      log: (l) => logs.push(l),
      channels: [ntfyChannel(fetcher, "https://ntfy.local/topic")],
    });
    expect(outcomes).toHaveLength(2);
    expect(outcomes.flatMap((o) => o.alerts)).toEqual([]);
    expect(fetcher.posts).toEqual([]);
    expect(logs.filter((l) => l.includes("cycle"))).toHaveLength(2);
  });

  it("alerts once when a record breaks between cycles", async () => {
    const resolver = new MutableResolver(healthyDns());
    const fetcher = new FixtureFetcher({});
    let cycle = 0;
    const outcomes = await watch(resolver, fetcher, "example.com", {
      selectors: ["mail"],
      skipDnsbl: true,
      maxCycles: 2,
      intervalSeconds: 1,
      sleep: async () => {
        // Between cycle 1 and 2 the SPF record is replaced with +all.
        cycle += 1;
        if (cycle === 1) {
          const broken = healthyDns();
          broken["TXT:example.com"] = [["v=spf1 mx +all"]];
          resolver.swap(broken);
        }
      },
      channels: [ntfyChannel(fetcher, "https://ntfy.local/topic")],
      log: () => {},
    });
    expect(outcomes[0]?.alerts).toEqual([]);
    expect(outcomes[1]?.alerts.length).toBeGreaterThanOrEqual(1);
    const bodies = fetcher.posts.map((p) => p.body).join("\n");
    expect(bodies).toContain("spf.plus-all");
    expect(bodies).toContain("DNS records changed");
  });

  it("reports pre-existing failures once on the first cycle", async () => {
    const dns = healthyDns();
    delete dns["TXT:_dmarc.example.com"];
    const resolver = new MutableResolver(dns);
    const fetcher = new FixtureFetcher({});
    const outcomes = await watch(resolver, fetcher, "example.com", {
      selectors: ["mail"],
      skipDnsbl: true,
      maxCycles: 2,
      intervalSeconds: 1,
      sleep: noSleep,
      channels: [ntfyChannel(fetcher, "https://ntfy.local/topic")],
      log: () => {},
    });
    expect(outcomes[0]?.alerts[0]).toContain("existing failure");
    expect(outcomes[1]?.alerts).toEqual([]);
    expect(fetcher.posts).toHaveLength(1);
  });

  it("delivers telegram alerts with the token only in the URL, never the body", async () => {
    const dns = healthyDns();
    delete dns["TXT:example.com"];
    const resolver = new MutableResolver(dns);
    const fetcher = new FixtureFetcher({});
    await watch(resolver, fetcher, "example.com", {
      selectors: ["mail"],
      skipDnsbl: true,
      maxCycles: 1,
      sleep: noSleep,
      channels: [telegramChannel(fetcher, "123:SECRETTOKEN", "42")],
      log: () => {},
    });
    expect(fetcher.posts).toHaveLength(1);
    const post = fetcher.posts[0]!;
    expect(post.url).toContain("bot123:SECRETTOKEN/sendMessage");
    expect(post.body).not.toContain("SECRETTOKEN");
    expect(JSON.parse(post.body)).toMatchObject({ chat_id: "42" });
  });

  it("keeps running when an alert channel throws", async () => {
    const dns = healthyDns();
    delete dns["TXT:example.com"];
    const resolver = new MutableResolver(dns);
    const fetcher = new FixtureFetcher({});
    const logs: string[] = [];
    const outcomes = await watch(resolver, fetcher, "example.com", {
      selectors: ["mail"],
      skipDnsbl: true,
      maxCycles: 1,
      sleep: noSleep,
      channels: [
        {
          name: "broken",
          send: async () => {
            throw new Error("boom");
          },
        },
      ],
      log: (l) => logs.push(l),
    });
    expect(outcomes).toHaveLength(1);
    expect(logs.some((l) => l.includes("alert via broken failed"))).toBe(true);
  });
});
