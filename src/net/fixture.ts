/**
 * Fixture-backed DnsResolver / HttpFetcher.
 *
 * A fixture file is a JSON snapshot of DNS answers and HTTP bodies, e.g.:
 *
 * {
 *   "dns": {
 *     "TXT:example.com": [["v=spf1 mx -all"]],
 *     "MX:example.com": [{ "exchange": "mail.example.com", "priority": 10 }],
 *     "A:mail.example.com": ["192.0.2.10"],
 *     "PTR:192.0.2.10": ["mail.example.com"]
 *   },
 *   "http": {
 *     "https://mta-sts.example.com/.well-known/mta-sts.txt": "version: STSv1\n..."
 *   }
 * }
 *
 * Keys absent from the map behave as NXDOMAIN. This powers `--dns-fixture`
 * (deterministic offline runs) and all recorded-fixture unit tests.
 */
import { readFile } from "node:fs/promises";

import { DnsNotFoundError, type DnsResolver, type MxRecord } from "./resolver.js";
import type { HttpFetcher, HttpResponse } from "./fetcher.js";

export interface FixtureData {
  dns?: Record<string, unknown>;
  http?: Record<string, string>;
}

function lower(name: string): string {
  return name.toLowerCase().replace(/\.$/, "");
}

export class FixtureResolver implements DnsResolver {
  constructor(private readonly data: Record<string, unknown>) {}

  private lookup<T>(rrtype: string, name: string): T {
    const key = `${rrtype}:${lower(name)}`;
    const found = Object.entries(this.data).find(([k]) => {
      const [t, n = ""] = k.split(/:(.*)/s);
      return t === rrtype && lower(n) === lower(name);
    });
    if (!found) throw new DnsNotFoundError(name, rrtype);
    return found[1] as T;
  }

  async resolveTxt(name: string): Promise<string[][]> {
    const value = this.lookup<unknown>("TXT", name);
    // Accept both [["chunk1","chunk2"]] and ["record"] for authoring convenience.
    if (Array.isArray(value)) {
      return value.map((v) => (Array.isArray(v) ? v.map(String) : [String(v)]));
    }
    return [[String(value)]];
  }

  async resolveMx(name: string): Promise<MxRecord[]> {
    return this.lookup<MxRecord[]>("MX", name);
  }

  async resolveA(name: string): Promise<string[]> {
    return this.lookup<string[]>("A", name);
  }

  async resolveAaaa(name: string): Promise<string[]> {
    return this.lookup<string[]>("AAAA", name);
  }

  async reverse(ip: string): Promise<string[]> {
    return this.lookup<string[]>("PTR", ip);
  }
}

export class FixtureFetcher implements HttpFetcher {
  public readonly posts: Array<{ url: string; body: string }> = [];

  constructor(private readonly bodies: Record<string, string> = {}) {}

  async get(url: string): Promise<HttpResponse> {
    const body = this.bodies[url];
    if (body === undefined) return { status: 404, body: "" };
    return { status: 200, body };
  }

  async post(url: string, body: string): Promise<HttpResponse> {
    this.posts.push({ url, body });
    return { status: 200, body: "" };
  }
}

/** Load a fixture JSON file from disk and build resolver + fetcher from it. */
export async function loadFixture(
  path: string,
): Promise<{ resolver: FixtureResolver; fetcher: FixtureFetcher }> {
  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch {
    throw new Error(`cannot read fixture file: ${path}`);
  }
  let parsed: FixtureData;
  try {
    parsed = JSON.parse(raw) as FixtureData;
  } catch {
    throw new Error(`fixture file is not valid JSON: ${path}`);
  }
  return {
    resolver: new FixtureResolver(parsed.dns ?? {}),
    fetcher: new FixtureFetcher(parsed.http ?? {}),
  };
}
