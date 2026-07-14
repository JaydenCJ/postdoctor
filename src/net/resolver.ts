/**
 * DNS access is isolated behind the DnsResolver interface so that:
 *  - unit tests run against recorded fixtures and never touch the network;
 *  - `--dns-fixture` gives users a deterministic offline mode for CI.
 */
import { promises as dns } from "node:dns";

export interface MxRecord {
  exchange: string;
  priority: number;
}

/** Interface every check consumes. Implementations: NodeDnsResolver, FixtureResolver. */
export interface DnsResolver {
  /** TXT record sets; each record is the list of its character strings (not joined). */
  resolveTxt(name: string): Promise<string[][]>;
  resolveMx(name: string): Promise<MxRecord[]>;
  resolveA(name: string): Promise<string[]>;
  resolveAaaa(name: string): Promise<string[]>;
  /** PTR names for an IP address (v4 or v6). */
  reverse(ip: string): Promise<string[]>;
}

/** Error thrown by resolvers for NXDOMAIN / no-data, so checks can distinguish it. */
export class DnsNotFoundError extends Error {
  constructor(public readonly queryName: string, public readonly rrtype: string) {
    super(`no ${rrtype} record found for ${queryName}`);
  }
}

/** Error thrown for transport-level DNS failures (timeout, SERVFAIL, no route). */
export class DnsLookupError extends Error {
  constructor(public readonly queryName: string, public readonly rrtype: string, cause: string) {
    super(`DNS lookup for ${rrtype} ${queryName} failed: ${cause}`);
  }
}

const NOT_FOUND_CODES = new Set(["ENOTFOUND", "ENODATA"]);

function translate(err: unknown, name: string, rrtype: string): Error {
  const code = (err as NodeJS.ErrnoException)?.code ?? "";
  if (NOT_FOUND_CODES.has(code)) return new DnsNotFoundError(name, rrtype);
  const msg = err instanceof Error ? err.message : String(err);
  return new DnsLookupError(name, rrtype, code || msg);
}

/** Production resolver backed by node:dns. */
export class NodeDnsResolver implements DnsResolver {
  async resolveTxt(name: string): Promise<string[][]> {
    try {
      return await dns.resolveTxt(name);
    } catch (err) {
      throw translate(err, name, "TXT");
    }
  }

  async resolveMx(name: string): Promise<MxRecord[]> {
    try {
      return await dns.resolveMx(name);
    } catch (err) {
      throw translate(err, name, "MX");
    }
  }

  async resolveA(name: string): Promise<string[]> {
    try {
      return await dns.resolve4(name);
    } catch (err) {
      throw translate(err, name, "A");
    }
  }

  async resolveAaaa(name: string): Promise<string[]> {
    try {
      return await dns.resolve6(name);
    } catch (err) {
      throw translate(err, name, "AAAA");
    }
  }

  async reverse(ip: string): Promise<string[]> {
    try {
      return await dns.reverse(ip);
    } catch (err) {
      throw translate(err, ip, "PTR");
    }
  }
}
