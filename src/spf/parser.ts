/**
 * SPF record parser per RFC 7208.
 *
 * Parses a raw TXT record value into a structured list of mechanisms and
 * modifiers, reporting syntax errors with positions. Evaluation (lookup
 * counting, include recursion) lives in evaluator.ts.
 */

export type SpfQualifier = "+" | "-" | "~" | "?";

export type SpfMechanismKind =
  | "all"
  | "include"
  | "a"
  | "mx"
  | "ptr"
  | "ip4"
  | "ip6"
  | "exists";

export interface SpfMechanism {
  type: "mechanism";
  kind: SpfMechanismKind;
  qualifier: SpfQualifier;
  /** Domain-spec or ip value after ":" (undefined when omitted). */
  value?: string;
  /** CIDR suffix for a/mx/ip4/ip6, e.g. "/24" or dual "/24//64". */
  cidr?: string;
  /** The raw term as written. */
  raw: string;
}

export interface SpfModifier {
  type: "modifier";
  name: string;
  value: string;
  raw: string;
}

export type SpfTerm = SpfMechanism | SpfModifier;

export interface SpfParseError {
  term: string;
  message: string;
}

export interface SpfRecord {
  raw: string;
  terms: SpfTerm[];
  errors: SpfParseError[];
  /** Value of a redirect= modifier if present. */
  redirect?: string;
  /** Qualifier of the `all` mechanism if present. */
  allQualifier?: SpfQualifier;
}

const MECHANISM_KINDS: ReadonlySet<string> = new Set([
  "all",
  "include",
  "a",
  "mx",
  "ptr",
  "ip4",
  "ip6",
  "exists",
]);

/** Mechanisms that require a value after ":". */
const VALUE_REQUIRED: ReadonlySet<string> = new Set(["include", "ip4", "ip6", "exists"]);

const IP4_RE =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
// Liberal IPv6 shape check: hex groups and at most one "::".
const IP6_RE = /^[0-9a-fA-F:]{2,45}$/;

export function isValidIp4(ip: string): boolean {
  return IP4_RE.test(ip);
}

export function isValidIp6(ip: string): boolean {
  if (!IP6_RE.test(ip) || !ip.includes(":")) return false;
  const doubleColons = ip.split("::").length - 1;
  if (doubleColons > 1) return false;
  const groups = ip.replace("::", ":").split(":").filter((g) => g.length > 0);
  if (groups.some((g) => g.length > 4)) return false;
  if (doubleColons === 0 && groups.length !== 8) return false;
  if (doubleColons === 1 && groups.length > 7) return false;
  return true;
}

/** True when the TXT value looks like it wants to be an SPF record. */
export function looksLikeSpf(txt: string): boolean {
  return /^v=spf1(\s|$)/i.test(txt.trim());
}

function parseCidr(kind: string, rest: string): { value?: string; cidr?: string } {
  // Split a trailing CIDR ("/24", "//64" or "/24//64") off a domain-spec.
  const slash = rest.search(/\/(\d|\/)/);
  if (slash === -1) return { value: rest || undefined };
  const value = rest.slice(0, slash) || undefined;
  const cidr = rest.slice(slash);
  return { value, cidr };
}

function validateCidr(cidr: string | undefined, kind: SpfMechanismKind): string | null {
  if (!cidr) return null;
  const m = cidr.match(/^(?:\/(\d{1,3}))?(?:\/\/(\d{1,3}))?$/);
  if (!m || (m[1] === undefined && m[2] === undefined)) {
    return `invalid CIDR suffix "${cidr}"`;
  }
  const first = m[1] !== undefined ? Number(m[1]) : undefined;
  const second = m[2] !== undefined ? Number(m[2]) : undefined;
  if (kind === "ip4" && second !== undefined) return `ip4 mechanism cannot take an IPv6 prefix length`;
  if (kind === "ip6") {
    // For ip6, a single "/N" IS the IPv6 prefix length.
    if (first !== undefined && second !== undefined) {
      return `ip6 mechanism takes a single prefix length`;
    }
    const v6 = first ?? second;
    if (v6 !== undefined && v6 > 128) return `IPv6 prefix length /${v6} exceeds 128`;
    return null;
  }
  if (first !== undefined && first > 32) return `IPv4 prefix length /${first} exceeds 32`;
  if (second !== undefined && second > 128) return `IPv6 prefix length //${second} exceeds 128`;
  return null;
}

/**
 * Parse one SPF record string (already joined from TXT chunks).
 * Never throws: malformed terms are collected into `errors`.
 */
export function parseSpf(raw: string): SpfRecord {
  const record: SpfRecord = { raw, terms: [], errors: [] };
  const trimmed = raw.trim();

  if (!/^v=spf1(\s|$)/i.test(trimmed)) {
    record.errors.push({ term: trimmed.slice(0, 20), message: 'record must start with "v=spf1"' });
    return record;
  }

  const body = trimmed.slice("v=spf1".length).trim();
  if (body.length === 0) return record;

  for (const term of body.split(/\s+/)) {
    // Modifier: name=value (name is alphanumeric, first char alpha).
    const mod = term.match(/^([a-zA-Z][a-zA-Z0-9-_.]*)=(.*)$/);
    if (mod) {
      const name = mod[1]!.toLowerCase();
      const value = mod[2]!;
      record.terms.push({ type: "modifier", name, value, raw: term });
      if (name === "redirect") {
        if (value.length === 0) {
          record.errors.push({ term, message: "redirect= requires a domain" });
        } else {
          record.redirect = value;
        }
      } else if (name !== "exp" && !name.includes(".")) {
        // Unknown modifiers are permitted by RFC 7208 but usually typos.
        record.errors.push({ term, message: `unknown modifier "${name}"` });
      }
      continue;
    }

    // Mechanism: [qualifier]name[:value][cidr]
    let qualifier: SpfQualifier = "+";
    let rest = term;
    const first = term.charAt(0);
    if (first === "+" || first === "-" || first === "~" || first === "?") {
      qualifier = first;
      rest = term.slice(1);
    }

    const colon = rest.indexOf(":");
    let name = (colon === -1 ? rest : rest.slice(0, colon)).toLowerCase();
    let after = colon === -1 ? "" : rest.slice(colon + 1);

    // a/24 and mx/24 have CIDR directly on the name.
    let inlineCidr: string | undefined;
    const slashInName = name.search(/\//);
    if (slashInName !== -1) {
      inlineCidr = name.slice(slashInName);
      name = name.slice(0, slashInName);
    }

    if (!MECHANISM_KINDS.has(name)) {
      record.errors.push({ term, message: `unknown mechanism "${name || term}"` });
      continue;
    }
    const kind = name as SpfMechanismKind;

    let value: string | undefined;
    let cidr: string | undefined = inlineCidr;
    if (after.length > 0) {
      if (kind === "ip6") {
        // IPv6 values contain colons; only a trailing /N is a prefix length.
        const m = after.match(/^(.*?)(\/\d{1,3})?$/);
        value = m?.[1] || undefined;
        cidr = m?.[2] ?? cidr;
      } else {
        const split = parseCidr(kind, after);
        value = split.value;
        cidr = split.cidr ?? cidr;
      }
    }

    if (VALUE_REQUIRED.has(kind) && !value) {
      record.errors.push({ term, message: `${kind} requires a value (e.g. "${kind}:example.com")` });
      continue;
    }
    if (kind === "all" && (value || cidr)) {
      record.errors.push({ term, message: `"all" takes no arguments` });
      continue;
    }
    if (kind === "ip4" && value && !isValidIp4(value)) {
      record.errors.push({ term, message: `"${value}" is not a valid IPv4 address` });
      continue;
    }
    if (kind === "ip6" && value && !isValidIp6(value)) {
      record.errors.push({ term, message: `"${value}" is not a valid IPv6 address` });
      continue;
    }
    const cidrError = validateCidr(cidr, kind);
    if (cidrError) {
      record.errors.push({ term, message: cidrError });
      continue;
    }

    const mech: SpfMechanism = { type: "mechanism", kind, qualifier, value, cidr, raw: term };
    record.terms.push(mech);
    if (kind === "all") record.allQualifier = qualifier;
  }

  if (record.allQualifier !== undefined && record.redirect !== undefined) {
    record.errors.push({
      term: "redirect",
      message: 'redirect= is ignored when the record contains an "all" mechanism',
    });
  }

  return record;
}
