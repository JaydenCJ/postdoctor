/**
 * MTA-STS (RFC 8461) and TLS-RPT (RFC 8460) parsing.
 *
 * - The DNS side: `_mta-sts.<domain>` TXT ("v=STSv1; id=...") and
 *   `_smtp._tls.<domain>` TXT ("v=TLSRPTv1; rua=...").
 * - The HTTPS side: the policy file at
 *   https://mta-sts.<domain>/.well-known/mta-sts.txt
 */

export interface MtaStsPolicy {
  version?: string;
  mode?: "enforce" | "testing" | "none";
  mx: string[];
  maxAge?: number;
  errors: string[];
}

/** Parse the key/value policy file body ("version: STSv1\nmode: enforce\n..."). */
export function parseMtaStsPolicy(body: string): MtaStsPolicy {
  const policy: MtaStsPolicy = { mx: [], errors: [] };
  const seen = new Set<string>();

  for (const rawLine of body.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line.length === 0) continue;
    const colon = line.indexOf(":");
    if (colon === -1) {
      policy.errors.push(`malformed line "${line.slice(0, 40)}" (missing ":")`);
      continue;
    }
    const key = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();

    switch (key) {
      case "version":
        if (value !== "STSv1") policy.errors.push(`version must be "STSv1" (got "${value}")`);
        policy.version = value;
        break;
      case "mode":
        if (value === "enforce" || value === "testing" || value === "none") {
          policy.mode = value;
        } else {
          policy.errors.push(`mode must be enforce, testing or none (got "${value}")`);
        }
        break;
      case "mx":
        if (value.length === 0) {
          policy.errors.push("mx line has no value");
        } else {
          policy.mx.push(value.toLowerCase());
        }
        break;
      case "max_age": {
        const n = Number(value);
        if (!Number.isInteger(n) || n < 0) {
          policy.errors.push(`max_age must be a non-negative integer (got "${value}")`);
        } else {
          policy.maxAge = n;
        }
        break;
      }
      default:
        policy.errors.push(`unknown key "${key}"`);
    }
    if (key !== "mx" && seen.has(key)) policy.errors.push(`duplicate key "${key}"`);
    seen.add(key);
  }

  if (policy.version === undefined) policy.errors.push("missing required key: version");
  if (policy.mode === undefined) policy.errors.push("missing required key: mode");
  if (policy.maxAge === undefined) policy.errors.push("missing required key: max_age");
  if (policy.mode !== "none" && policy.mx.length === 0) {
    policy.errors.push("policy lists no mx hosts");
  }

  return policy;
}

/** Check whether an MX hostname is covered by a policy mx pattern (supports "*." prefix). */
export function mxMatchesPolicy(mxHost: string, patterns: string[]): boolean {
  const host = mxHost.toLowerCase().replace(/\.$/, "");
  for (const pattern of patterns) {
    if (pattern.startsWith("*.")) {
      const suffix = pattern.slice(1); // ".example.com"
      // Wildcard covers exactly one left-most label.
      if (host.endsWith(suffix) && !host.slice(0, -suffix.length).includes(".")) return true;
    } else if (host === pattern) {
      return true;
    }
  }
  return false;
}

export interface StsDnsRecord {
  version?: string;
  id?: string;
  errors: string[];
}

/** Parse the `_mta-sts` TXT record ("v=STSv1; id=20240101T000000"). */
export function parseStsDnsRecord(raw: string): StsDnsRecord {
  const rec: StsDnsRecord = { errors: [] };
  for (const part of raw.split(";")) {
    const item = part.trim();
    if (item.length === 0) continue;
    const eq = item.indexOf("=");
    if (eq === -1) {
      rec.errors.push(`malformed tag "${item.slice(0, 30)}"`);
      continue;
    }
    const name = item.slice(0, eq).trim();
    const value = item.slice(eq + 1).trim();
    if (name === "v") rec.version = value;
    else if (name === "id") rec.id = value;
  }
  if (rec.version !== "STSv1") rec.errors.push(`v= must be "STSv1"`);
  if (!rec.id || !/^[a-zA-Z0-9]{1,32}$/.test(rec.id)) {
    rec.errors.push("id= must be 1-32 alphanumeric characters");
  }
  return rec;
}

export interface TlsRptRecord {
  version?: string;
  rua: string[];
  errors: string[];
}

/** Parse the `_smtp._tls` TXT record ("v=TLSRPTv1; rua=mailto:tls@example.com"). */
export function parseTlsRptRecord(raw: string): TlsRptRecord {
  const rec: TlsRptRecord = { rua: [], errors: [] };
  for (const part of raw.split(";")) {
    const item = part.trim();
    if (item.length === 0) continue;
    const eq = item.indexOf("=");
    if (eq === -1) {
      rec.errors.push(`malformed tag "${item.slice(0, 30)}"`);
      continue;
    }
    const name = item.slice(0, eq).trim();
    const value = item.slice(eq + 1).trim();
    if (name === "v") {
      rec.version = value;
    } else if (name === "rua") {
      for (const uri of value.split(",")) {
        const u = uri.trim();
        if (/^(mailto:[^@\s]+@[^@\s]+|https:\/\/\S+)$/i.test(u)) rec.rua.push(u);
        else rec.errors.push(`rua entry "${u.slice(0, 40)}" is not a mailto: or https: URI`);
      }
    }
  }
  if (rec.version !== "TLSRPTv1") rec.errors.push(`v= must be "TLSRPTv1"`);
  if (rec.rua.length === 0 && !rec.errors.some((e) => e.startsWith("rua"))) {
    rec.errors.push("rua= (report destination) is missing");
  }
  return rec;
}
