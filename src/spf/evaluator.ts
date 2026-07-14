/**
 * SPF evaluator: walks a parsed record recursively through the resolver,
 * counting DNS-querying terms against the RFC 7208 limit of 10, and
 * collecting deliverability findings (missing record, +all, ptr, long
 * include chains, records that no longer resolve, ...).
 */
import { DnsNotFoundError } from "../net/resolver.js";
import type { DnsResolver } from "../net/resolver.js";
import { looksLikeSpf, parseSpf } from "./parser.js";
import type { SpfRecord } from "./parser.js";
import type { Finding } from "../types.js";
import { fail, info, pass, warn } from "../types.js";

export interface SpfEvaluation {
  /** Raw SPF record found at the root domain ("" when none). */
  record: string;
  /** Parsed root record (undefined when no record found). */
  parsed?: SpfRecord;
  /** Number of terms that cost a DNS lookup (include/a/mx/ptr/exists/redirect), recursive. */
  lookupCount: number;
  /** Domains visited via include/redirect, deduplicated, in first-visit order. */
  visited: string[];
  findings: Finding[];
}

const LOOKUP_LIMIT = 10;

/** Fetch all TXT records at a name and return the joined SPF candidates. */
async function fetchSpfRecords(resolver: DnsResolver, domain: string): Promise<string[]> {
  let txt: string[][];
  try {
    txt = await resolver.resolveTxt(domain);
  } catch (err) {
    if (err instanceof DnsNotFoundError) return [];
    throw err;
  }
  return txt.map((chunks) => chunks.join("")).filter((v) => looksLikeSpf(v));
}

interface WalkState {
  lookups: number;
  visited: string[];
  findings: Finding[];
  /** Per-domain SPF record cache so shared includes are fetched from DNS once. */
  records: Map<string, string[]>;
  /** Domains whose record-level findings were already emitted (dedupe on re-visits). */
  reported: Set<string>;
  /** Domains already flagged as part of a loop (dedupe repeated loop findings). */
  loopFlagged: Set<string>;
}

const MAX_DEPTH = 20;

/**
 * Recursively count DNS-querying terms below one domain's record.
 *
 * Loop detection compares against `path` — the ancestor chain of the current
 * recursion only, NOT a global visited set. RFC 7208 allows the same domain to
 * be included from several sibling branches (a "diamond" graph, common when
 * multiple vendor includes share infrastructure records); only a domain that
 * includes/redirects back to one of its own ancestors is a true loop. Shared
 * includes are re-walked so their DNS-querying terms count once per evaluation,
 * matching how real receivers charge the 10-lookup budget, while the record
 * cache and the `reported` set keep DNS traffic and findings deduplicated.
 */
async function walk(
  resolver: DnsResolver,
  domain: string,
  state: WalkState,
  path: string[],
): Promise<void> {
  if (path.length > MAX_DEPTH) return; // Hard stop; the lookup limit finding will already have fired.
  if (path.includes(domain)) {
    if (!state.loopFlagged.has(domain)) {
      state.loopFlagged.add(domain);
      state.findings.push(
        fail(
          "spf.include-loop",
          `include/redirect loop detected at ${domain} (chain: ${[...path, domain].join(" -> ")})`,
        ),
      );
    }
    return;
  }
  if (!state.visited.includes(domain)) state.visited.push(domain);

  let records = state.records.get(domain);
  if (records === undefined) {
    records = await fetchSpfRecords(resolver, domain);
    state.records.set(domain, records);
  }
  const firstVisit = !state.reported.has(domain);
  state.reported.add(domain);

  if (path.length > 0 && records.length === 0) {
    if (firstVisit) {
      state.findings.push(
        fail(
          "spf.include-unresolvable",
          `included domain ${domain} has no SPF record`,
          "Remove the include or fix the target domain; evaluators return permerror for it.",
        ),
      );
    }
    return;
  }
  if (firstVisit && records.length > 1) {
    state.findings.push(
      fail(
        "spf.multiple-records",
        `${domain} publishes ${records.length} SPF records; receivers treat this as permerror`,
        "Merge them into a single v=spf1 TXT record.",
      ),
    );
  }
  const record = records[0];
  if (!record) return;

  const parsed = parseSpf(record);
  if (firstVisit) {
    for (const e of parsed.errors) {
      state.findings.push(
        fail("spf.syntax", `syntax error in SPF at ${domain}: ${e.message} (term "${e.term}")`),
      );
    }
  }

  const childPath = [...path, domain];
  for (const term of parsed.terms) {
    if (term.type === "modifier") {
      if (term.name === "redirect" && term.value && parsed.allQualifier === undefined) {
        state.lookups += 1;
        await walk(resolver, term.value.toLowerCase(), state, childPath);
      }
      continue;
    }
    switch (term.kind) {
      case "include":
        state.lookups += 1;
        if (term.value) await walk(resolver, term.value.toLowerCase(), state, childPath);
        break;
      case "a":
      case "mx":
      case "exists":
      case "ptr":
        state.lookups += 1;
        break;
      default:
        break; // ip4/ip6/all cost nothing.
    }
  }
}

/** Evaluate the SPF posture of a domain. */
export async function evaluateSpf(
  resolver: DnsResolver,
  domain: string,
): Promise<SpfEvaluation> {
  const findings: Finding[] = [];
  const records = await fetchSpfRecords(resolver, domain);

  if (records.length === 0) {
    findings.push(
      fail(
        "spf.missing",
        `no SPF record found for ${domain}`,
        `Publish a TXT record like "v=spf1 mx -all". Gmail and Outlook reject unauthenticated mail.`,
      ),
    );
    return { record: "", lookupCount: 0, visited: [domain], findings };
  }

  const record = records[0]!;
  const parsed = parseSpf(record);

  // Root-level structural findings.
  if (records.length === 1) {
    findings.push(pass("spf.present", `SPF record found: ${truncate(record, 80)}`));
  }
  if (record.length > 450) {
    findings.push(
      warn(
        "spf.record-length",
        `SPF record is ${record.length} characters; approaching UDP answer size limits`,
        "Flatten includes or trim mechanisms.",
      ),
    );
  }

  const state: WalkState = {
    lookups: 0,
    visited: [],
    findings,
    records: new Map([[domain.toLowerCase(), records]]),
    reported: new Set(),
    loopFlagged: new Set(),
  };
  await walk(resolver, domain.toLowerCase(), state, []);

  if (state.lookups > LOOKUP_LIMIT) {
    findings.push(
      fail(
        "spf.lookup-limit",
        `SPF resolves ${state.lookups} DNS lookups; RFC 7208 permits at most ${LOOKUP_LIMIT} (permerror)`,
        "Flatten includes: replace nested includes with ip4/ip6 mechanisms.",
      ),
    );
  } else if (state.lookups >= LOOKUP_LIMIT - 1) {
    findings.push(
      warn(
        "spf.lookup-near-limit",
        `SPF uses ${state.lookups}/${LOOKUP_LIMIT} DNS lookups; one more include will break it`,
      ),
    );
  } else {
    findings.push(pass("spf.lookups", `DNS lookups within limit (${state.lookups}/${LOOKUP_LIMIT})`));
  }

  // Policy strength.
  switch (parsed.allQualifier) {
    case "+":
      findings.push(
        fail(
          "spf.plus-all",
          `record ends with "+all": any server on the internet may send as ${domain}`,
          'Use "-all" (or "~all" while testing).',
        ),
      );
      break;
    case "?":
      findings.push(
        warn("spf.neutral-all", `"?all" is neutral; receivers gain no signal from your SPF`),
      );
      break;
    case "~":
      findings.push(
        info("spf.softfail-all", `"~all" (softfail) is accepted; "-all" is stricter once you trust the record`),
      );
      break;
    case "-":
      findings.push(pass("spf.strict-all", `record ends with "-all" (strict)`));
      break;
    default:
      if (parsed.redirect === undefined) {
        findings.push(
          warn(
            "spf.no-all",
            `record has neither an "all" mechanism nor redirect=; unmatched senders default to neutral`,
            'Terminate the record with "-all" or "~all".',
          ),
        );
      }
  }

  if (parsed.terms.some((t) => t.type === "mechanism" && t.kind === "ptr")) {
    findings.push(
      warn("spf.ptr-mechanism", `"ptr" mechanism is deprecated by RFC 7208 and often ignored`),
    );
  }

  return {
    record,
    parsed,
    lookupCount: state.lookups,
    visited: state.visited,
    findings,
  };
}

function truncate(s: string, n: number): string {
  return s.length <= n ? s : `${s.slice(0, n - 1)}…`;
}
