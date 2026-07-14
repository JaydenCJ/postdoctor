/**
 * DKIM key record parsing per RFC 6376 §3.6.1.
 *
 * Parses the tag=value list published at <selector>._domainkey.<domain>,
 * validates the public key material, and measures RSA key size by decoding
 * the DER SubjectPublicKeyInfo structure (no crypto library needed — we only
 * read the modulus length).
 */

export interface DkimKeyRecord {
  raw: string;
  tags: Record<string, string>;
  /** Key type: "rsa" (default) or "ed25519". */
  keyType: string;
  /** True when p= is present but empty — the key is revoked. */
  revoked: boolean;
  /** RSA modulus size in bits (undefined for ed25519 or unparseable keys). */
  keyBits?: number;
  /** True when the t= flags include "y" (testing mode). */
  testing: boolean;
  errors: string[];
}

/** Parse a tag=value list ("k=rsa; p=MIG...") into a map, validating shape. */
export function parseTagValueList(raw: string): { tags: Record<string, string>; errors: string[] } {
  const tags: Record<string, string> = {};
  const errors: string[] = [];
  for (const part of raw.split(";")) {
    const item = part.trim();
    if (item.length === 0) continue;
    const eq = item.indexOf("=");
    if (eq === -1) {
      errors.push(`malformed tag "${truncate(item)}" (missing "=")`);
      continue;
    }
    const name = item.slice(0, eq).trim();
    const value = item.slice(eq + 1).trim();
    if (!/^[a-zA-Z][a-zA-Z0-9_]*$/.test(name)) {
      errors.push(`invalid tag name "${truncate(name)}"`);
      continue;
    }
    if (name in tags) {
      errors.push(`duplicate tag "${name}"`);
      continue;
    }
    tags[name] = value;
  }
  return { tags, errors };
}

/**
 * Extract the RSA modulus bit length from a base64 SubjectPublicKeyInfo.
 * Returns undefined when the DER structure cannot be walked.
 */
export function rsaKeyBits(p: string): number | undefined {
  let der: Buffer;
  try {
    der = Buffer.from(p, "base64");
  } catch {
    return undefined;
  }
  if (der.length < 20) return undefined;

  // Minimal DER reader: [pos, lengthOfContent] after a tag byte.
  const readLen = (pos: number): [number, number] | undefined => {
    const first = der[pos];
    if (first === undefined) return undefined;
    if (first < 0x80) return [pos + 1, first];
    const n = first & 0x7f;
    if (n === 0 || n > 4 || pos + 1 + n > der.length) return undefined;
    let len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + der[pos + 1 + i]!;
    return [pos + 1 + n, len];
  };

  // SEQUENCE { SEQUENCE { OID... }, BIT STRING { SEQUENCE { INTEGER modulus, ... } } }
  if (der[0] !== 0x30) return undefined;
  let r = readLen(1);
  if (!r) return undefined;
  let pos = r[0];

  if (der[pos] !== 0x30) return undefined; // AlgorithmIdentifier
  r = readLen(pos + 1);
  if (!r) return undefined;
  pos = r[0] + r[1]; // skip it entirely

  if (der[pos] !== 0x03) return undefined; // BIT STRING
  r = readLen(pos + 1);
  if (!r) return undefined;
  pos = r[0] + 1; // skip unused-bits byte

  if (der[pos] !== 0x30) return undefined; // RSAPublicKey SEQUENCE
  r = readLen(pos + 1);
  if (!r) return undefined;
  pos = r[0];

  if (der[pos] !== 0x02) return undefined; // INTEGER modulus
  r = readLen(pos + 1);
  if (!r) return undefined;
  let [start, len] = r;
  // Strip leading zero byte (sign padding).
  while (len > 0 && der[start] === 0x00) {
    start += 1;
    len -= 1;
  }
  if (len === 0) return undefined;
  const firstByte = der[start]!;
  let bits = len * 8;
  // Subtract leading zero bits of the first byte.
  for (let mask = 0x80; mask > 0 && (firstByte & mask) === 0; mask >>= 1) bits -= 1;
  return bits;
}

const BASE64_RE = /^[A-Za-z0-9+/=\s]+$/;

/**
 * True when a TXT value looks like a DKIM key record. Selector names often
 * carry unrelated wildcard TXT records (e.g. a bare provider marker), which
 * must not be reported as broken DKIM keys.
 */
export function looksLikeDkim(txt: string): boolean {
  const t = txt.trim();
  return /^v\s*=\s*DKIM1\s*(;|$)/i.test(t) || /(^|;)\s*p\s*=/.test(t);
}

/** Parse a DKIM key TXT record value. */
export function parseDkimRecord(raw: string): DkimKeyRecord {
  const { tags, errors } = parseTagValueList(raw);
  const record: DkimKeyRecord = {
    raw,
    tags,
    keyType: (tags["k"] ?? "rsa").toLowerCase(),
    revoked: false,
    testing: false,
    errors,
  };

  if (tags["v"] !== undefined && tags["v"] !== "DKIM1") {
    errors.push(`v= must be "DKIM1" when present (got "${truncate(tags["v"])}")`);
  }

  const flags = (tags["t"] ?? "").split(":").map((f) => f.trim());
  record.testing = flags.includes("y");

  const p = tags["p"];
  if (p === undefined) {
    errors.push("required tag p= (public key) is missing");
    return record;
  }
  const compact = p.replace(/\s+/g, "");
  if (compact.length === 0) {
    record.revoked = true;
    return record;
  }
  if (!BASE64_RE.test(compact) || compact.length % 4 !== 0) {
    errors.push("p= is not valid base64");
    return record;
  }

  if (record.keyType === "rsa") {
    const bits = rsaKeyBits(compact);
    if (bits === undefined) {
      errors.push("p= does not decode as an RSA SubjectPublicKeyInfo");
    } else {
      record.keyBits = bits;
    }
  } else if (record.keyType === "ed25519") {
    const decoded = Buffer.from(compact, "base64");
    if (decoded.length !== 32) {
      errors.push(`ed25519 key must be 32 raw bytes (got ${decoded.length})`);
    }
  } else {
    errors.push(`unknown key type k=${record.keyType}`);
  }

  return record;
}

function truncate(s: string): string {
  return s.length <= 40 ? s : `${s.slice(0, 39)}…`;
}
