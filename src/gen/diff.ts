/**
 * DNS record snapshot + diff.
 *
 * `postdoctor diff <domain> --save` records the current live state of every
 * deliverability-relevant record into a baseline JSON file; later runs
 * compare live DNS against the baseline and report drift — the "someone
 * touched the DNS panel" alarm. The watch daemon reuses this diff engine.
 */
import { DnsNotFoundError } from "../net/resolver.js";
import type { DnsResolver } from "../net/resolver.js";

/** Snapshot of all mail-related records of a domain. */
export interface DnsSnapshot {
  domain: string;
  takenAt: string;
  /** name -> sorted TXT values (joined chunks). */
  txt: Record<string, string[]>;
  /** MX entries formatted "<priority> <exchange>". */
  mx: string[];
}

export interface RecordChange {
  kind: "added" | "removed" | "changed";
  name: string;
  before?: string;
  after?: string;
}

/** Names whose TXT records matter for deliverability. */
export function watchedNames(domain: string, selectors: string[]): string[] {
  return [
    domain,
    `_dmarc.${domain}`,
    `_mta-sts.${domain}`,
    `_smtp._tls.${domain}`,
    ...selectors.map((s) => `${s}._domainkey.${domain}`),
  ];
}

export async function takeSnapshot(
  resolver: DnsResolver,
  domain: string,
  selectors: string[],
): Promise<DnsSnapshot> {
  const txt: Record<string, string[]> = {};
  for (const name of watchedNames(domain, selectors)) {
    try {
      const values = (await resolver.resolveTxt(name)).map((c) => c.join("")).sort();
      if (values.length > 0) txt[name] = values;
    } catch (err) {
      if (!(err instanceof DnsNotFoundError)) throw err;
    }
  }

  let mx: string[] = [];
  try {
    mx = (await resolver.resolveMx(domain))
      .map((m) => `${m.priority} ${m.exchange.toLowerCase()}`)
      .sort();
  } catch (err) {
    if (!(err instanceof DnsNotFoundError)) throw err;
  }

  return { domain, takenAt: new Date().toISOString(), txt, mx };
}

/** Compare two snapshots; empty result means no drift. */
export function diffSnapshots(baseline: DnsSnapshot, current: DnsSnapshot): RecordChange[] {
  const changes: RecordChange[] = [];
  const names = new Set([...Object.keys(baseline.txt), ...Object.keys(current.txt)]);

  for (const name of [...names].sort()) {
    const before = baseline.txt[name];
    const after = current.txt[name];
    if (before === undefined && after !== undefined) {
      for (const v of after) changes.push({ kind: "added", name, after: v });
    } else if (before !== undefined && after === undefined) {
      for (const v of before) changes.push({ kind: "removed", name, before: v });
    } else if (before !== undefined && after !== undefined) {
      const beforeSet = new Set(before);
      const afterSet = new Set(after);
      const removed = before.filter((v) => !afterSet.has(v));
      const added = after.filter((v) => !beforeSet.has(v));
      if (removed.length === 1 && added.length === 1) {
        changes.push({ kind: "changed", name, before: removed[0], after: added[0] });
      } else {
        for (const v of removed) changes.push({ kind: "removed", name, before: v });
        for (const v of added) changes.push({ kind: "added", name, after: v });
      }
    }
  }

  const beforeMx = baseline.mx.join(", ");
  const afterMx = current.mx.join(", ");
  if (beforeMx !== afterMx) {
    changes.push({
      kind: "changed",
      name: `${baseline.domain} (MX)`,
      before: beforeMx || "(none)",
      after: afterMx || "(none)",
    });
  }

  return changes;
}
