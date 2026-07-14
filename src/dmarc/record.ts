/**
 * DMARC policy record parsing per RFC 7489 §6.3.
 *
 * Parses the tag=value list published at _dmarc.<domain> and validates tag
 * values (policy names, pct range, URI syntax, alignment modes, ...).
 */
import { parseTagValueList } from "../dkim/record.js";

export type DmarcPolicy = "none" | "quarantine" | "reject";

export interface DmarcRecord {
  raw: string;
  tags: Record<string, string>;
  policy?: DmarcPolicy;
  subdomainPolicy?: DmarcPolicy;
  /** Sampling percentage 0-100 (default 100). */
  pct: number;
  /** Parsed rua mailto addresses. */
  rua: string[];
  /** Parsed ruf mailto addresses. */
  ruf: string[];
  /** DKIM alignment: relaxed "r" (default) or strict "s". */
  adkim: "r" | "s";
  /** SPF alignment: relaxed "r" (default) or strict "s". */
  aspf: "r" | "s";
  errors: string[];
}

const POLICIES: ReadonlySet<string> = new Set(["none", "quarantine", "reject"]);
const KNOWN_TAGS: ReadonlySet<string> = new Set([
  "v",
  "p",
  "sp",
  "np",
  "pct",
  "rua",
  "ruf",
  "adkim",
  "aspf",
  "fo",
  "rf",
  "ri",
]);

/** Parse a "mailto:a@b,mailto:c@d" URI list; invalid entries land in errors. */
function parseUriList(value: string, tag: string, errors: string[]): string[] {
  const out: string[] = [];
  for (const part of value.split(",")) {
    const uri = part.trim();
    if (uri.length === 0) continue;
    // A size limit suffix like "!10m" is allowed by RFC 7489.
    const m = uri.match(/^mailto:([^!]+)(![0-9]+[kmgt]?)?$/i);
    if (!m) {
      errors.push(`${tag}= entry "${uri}" is not a mailto: URI`);
      continue;
    }
    const addr = m[1]!;
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(addr)) {
      errors.push(`${tag}= address "${addr}" does not look like an email address`);
      continue;
    }
    out.push(addr);
  }
  return out;
}

/** True when the TXT value looks like a DMARC record. */
export function looksLikeDmarc(txt: string): boolean {
  return /^v=DMARC1(\s*;|$)/i.test(txt.trim());
}

export function parseDmarcRecord(raw: string): DmarcRecord {
  const { tags, errors } = parseTagValueList(raw);
  const record: DmarcRecord = {
    raw,
    tags,
    pct: 100,
    rua: [],
    ruf: [],
    adkim: "r",
    aspf: "r",
    errors,
  };

  if (tags["v"] !== "DMARC1") {
    errors.push(`record must start with "v=DMARC1"`);
    return record;
  }
  // RFC 7489: v must be first, p should come second.
  const firstTag = raw.split(";")[0]?.trim() ?? "";
  if (!/^v\s*=\s*DMARC1$/i.test(firstTag)) {
    errors.push(`"v=DMARC1" must be the first tag`);
  }

  for (const name of Object.keys(tags)) {
    if (!KNOWN_TAGS.has(name)) errors.push(`unknown tag "${name}"`);
  }

  const p = tags["p"];
  if (p === undefined) {
    errors.push("required tag p= (policy) is missing");
  } else if (!POLICIES.has(p.toLowerCase())) {
    errors.push(`p= must be none, quarantine or reject (got "${p}")`);
  } else {
    record.policy = p.toLowerCase() as DmarcPolicy;
  }

  const sp = tags["sp"];
  if (sp !== undefined) {
    if (!POLICIES.has(sp.toLowerCase())) {
      errors.push(`sp= must be none, quarantine or reject (got "${sp}")`);
    } else {
      record.subdomainPolicy = sp.toLowerCase() as DmarcPolicy;
    }
  }

  const pct = tags["pct"];
  if (pct !== undefined) {
    const n = Number(pct);
    if (!Number.isInteger(n) || n < 0 || n > 100) {
      errors.push(`pct= must be an integer 0-100 (got "${pct}")`);
    } else {
      record.pct = n;
    }
  }

  if (tags["rua"] !== undefined) record.rua = parseUriList(tags["rua"], "rua", errors);
  if (tags["ruf"] !== undefined) record.ruf = parseUriList(tags["ruf"], "ruf", errors);

  for (const [tag, key] of [
    ["adkim", "adkim"],
    ["aspf", "aspf"],
  ] as const) {
    const v = tags[tag];
    if (v !== undefined) {
      if (v !== "r" && v !== "s") {
        errors.push(`${tag}= must be "r" or "s" (got "${v}")`);
      } else {
        record[key] = v;
      }
    }
  }

  return record;
}
