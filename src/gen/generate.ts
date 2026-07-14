/**
 * DNS record generation: given the facts of a mail setup (domain, sending
 * IPs, DKIM selector/key, report address), emit the recommended record set
 * in zone-file format so it can be pasted into any DNS panel.
 */
import { isValidIp4, isValidIp6 } from "../spf/parser.js";

export interface GenerateOptions {
  domain: string;
  /** IPv4/IPv6 addresses allowed to send. */
  ips?: string[];
  /** SPF include targets (e.g. a relay provider's SPF domain). */
  includes?: string[];
  /** Add "mx" to the SPF record (default true when no ips/includes given). */
  useMx?: boolean;
  /** Address that receives DMARC aggregate reports. */
  rua?: string;
  /** DMARC policy to publish (default "none" — start observing, then tighten). */
  policy?: "none" | "quarantine" | "reject";
  /** DKIM selector; when no key is given, a follow-up note is emitted instead of a record. */
  selector?: string;
  /** Base64 DKIM public key (from your MTA's key generation). */
  dkimPublicKey?: string;
  /** Emit MTA-STS + TLS-RPT records (default true). */
  mtaSts?: boolean;
  /** MX hostnames for the MTA-STS policy file. */
  mxHosts?: string[];
}

export interface GeneratedRecord {
  /** DNS owner name, e.g. "_dmarc.example.com". */
  name: string;
  type: "TXT";
  value: string;
  /** What this record does, one line. */
  comment: string;
}

export interface GeneratedSet {
  records: GeneratedRecord[];
  /** Body of /.well-known/mta-sts.txt when MTA-STS was requested. */
  mtaStsPolicyFile?: string;
  /** Follow-up actions that cannot be expressed as DNS records. */
  notes: string[];
}

export function generateRecords(options: GenerateOptions): GeneratedSet {
  const { domain } = options;
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(domain)) {
    throw new Error(`"${domain}" is not a valid domain name`);
  }

  const records: GeneratedRecord[] = [];
  const notes: string[] = [];

  // --- SPF ---
  const parts: string[] = ["v=spf1"];
  const ips = options.ips ?? [];
  for (const ip of ips) {
    if (isValidIp4(ip)) parts.push(`ip4:${ip}`);
    else if (isValidIp6(ip)) parts.push(`ip6:${ip}`);
    else throw new Error(`"${ip}" is not a valid IPv4 or IPv6 address`);
  }
  for (const inc of options.includes ?? []) parts.push(`include:${inc}`);
  const useMx = options.useMx ?? (ips.length === 0 && (options.includes ?? []).length === 0);
  if (useMx) parts.splice(1, 0, "mx");
  parts.push("-all");
  records.push({
    name: domain,
    type: "TXT",
    value: parts.join(" "),
    comment: "SPF: which servers may send mail as this domain",
  });

  // --- DMARC ---
  const rua = options.rua ?? `dmarc@${domain}`;
  const policy = options.policy ?? "none";
  records.push({
    name: `_dmarc.${domain}`,
    type: "TXT",
    value: `v=DMARC1; p=${policy}; rua=mailto:${rua}; adkim=r; aspf=r`,
    comment:
      policy === "none"
        ? "DMARC: observe mode; read reports for 2-4 weeks, then move to p=quarantine"
        : `DMARC: enforce ${policy} on failing mail`,
  });
  if (policy === "none") {
    notes.push(
      "DMARC starts at p=none so legitimate mail is never lost. After reports show your own mail passing, re-run with --policy quarantine.",
    );
  }

  // --- DKIM ---
  if (options.selector && options.dkimPublicKey) {
    const key = options.dkimPublicKey.replace(/\s+/g, "");
    records.push({
      name: `${options.selector}._domainkey.${domain}`,
      type: "TXT",
      value: `v=DKIM1; k=rsa; p=${key}`,
      comment: `DKIM public key for selector "${options.selector}"`,
    });
  } else {
    notes.push(
      "DKIM: generate a 2048-bit key pair in your MTA (mailcow: E-Mail > Configuration > ARC/DKIM keys; stalwart: 'stalwart-cli dkim create'), then re-run gen with --selector and --dkim-key to get the TXT record.",
    );
  }

  // --- MTA-STS + TLS-RPT ---
  let mtaStsPolicyFile: string | undefined;
  if (options.mtaSts ?? true) {
    const id = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
    records.push({
      name: `_mta-sts.${domain}`,
      type: "TXT",
      value: `v=STSv1; id=${id}`,
      comment: "MTA-STS: bump id= whenever the policy file changes",
    });
    records.push({
      name: `_smtp._tls.${domain}`,
      type: "TXT",
      value: `v=TLSRPTv1; rua=mailto:${rua}`,
      comment: "TLS-RPT: receive reports when senders fail to negotiate TLS with you",
    });
    const mxHosts = options.mxHosts ?? [`mail.${domain}`];
    mtaStsPolicyFile = [
      "version: STSv1",
      "mode: testing",
      ...mxHosts.map((h) => `mx: ${h}`),
      "max_age: 86400",
      "",
    ].join("\n");
    notes.push(
      `MTA-STS: serve the policy file at https://mta-sts.${domain}/.well-known/mta-sts.txt (any static host works). Switch "mode: testing" to "mode: enforce" and raise max_age once TLS-RPT reports look clean.`,
    );
  }

  return { records, mtaStsPolicyFile, notes };
}

/** Render generated records as zone-file lines. */
export function toZoneFile(set: GeneratedSet): string {
  const lines: string[] = [];
  for (const rec of set.records) {
    lines.push(`; ${rec.comment}`);
    lines.push(`${rec.name}. 3600 IN TXT ${quoteTxt(rec.value)}`);
    lines.push("");
  }
  return lines.join("\n");
}

/** Split a TXT value into quoted 255-byte chunks as zone files require. */
export function quoteTxt(value: string): string {
  const chunks: string[] = [];
  for (let i = 0; i < value.length; i += 255) {
    chunks.push(`"${value.slice(i, i + 255).replace(/"/g, '\\"')}"`);
  }
  return chunks.join(" ");
}
