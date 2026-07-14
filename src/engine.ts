/**
 * Check engine: runs each deliverability check area against a resolver /
 * fetcher pair and assembles a DomainReport. All network access goes through
 * the injected interfaces, so the whole engine runs identically against live
 * DNS, a --dns-fixture snapshot, or in-memory test fakes.
 */
import { DnsLookupError, DnsNotFoundError } from "./net/resolver.js";
import type { DnsResolver } from "./net/resolver.js";
import type { HttpFetcher } from "./net/fetcher.js";
import { evaluateSpf } from "./spf/evaluator.js";
import { looksLikeDkim, parseDkimRecord } from "./dkim/record.js";
import { looksLikeDmarc, parseDmarcRecord } from "./dmarc/record.js";
import {
  mxMatchesPolicy,
  parseMtaStsPolicy,
  parseStsDnsRecord,
  parseTlsRptRecord,
} from "./mtasts/policy.js";
import type { CheckResult, DomainReport, Finding } from "./types.js";
import { fail, info, pass, warn } from "./types.js";

export interface CheckOptions {
  /** DKIM selectors to inspect (default: common self-hosted selectors). */
  selectors?: string[];
  /** Sending IPs to verify rDNS + blocklists for (default: derived from MX). */
  ips?: string[];
  /** DNSBL zones to query (default: DEFAULT_DNSBL_ZONES). */
  dnsblZones?: string[];
  /** Skip DNSBL queries entirely (they are slow on live DNS). */
  skipDnsbl?: boolean;
}

/** Selectors probed when the user does not name one (mailcow/stalwart/common defaults). */
export const DEFAULT_SELECTORS = ["default", "dkim", "mail", "s1", "selector1", "selector2"];

/** Widely used, non-commercial-key DNS blocklists. */
export const DEFAULT_DNSBL_ZONES = [
  "zen.spamhaus.org",
  "bl.spamcop.net",
  "b.barracudacentral.org",
  "psbl.surriel.com",
];

function joinTxt(chunks: string[][]): string[] {
  return chunks.map((c) => c.join(""));
}

async function txtOrEmpty(resolver: DnsResolver, name: string): Promise<string[]> {
  try {
    return joinTxt(await resolver.resolveTxt(name));
  } catch (err) {
    if (err instanceof DnsNotFoundError) return [];
    throw err;
  }
}

/** SPF area. */
export async function checkSpf(resolver: DnsResolver, domain: string): Promise<CheckResult> {
  const evaluation = await evaluateSpf(resolver, domain);
  return {
    area: "spf",
    title: "SPF",
    records: evaluation.record ? [evaluation.record] : [],
    findings: evaluation.findings,
  };
}

/** DKIM area: probe each selector at <selector>._domainkey.<domain>. */
export async function checkDkim(
  resolver: DnsResolver,
  domain: string,
  selectors: string[],
): Promise<CheckResult> {
  const findings: Finding[] = [];
  const records: string[] = [];
  let found = 0;

  for (const selector of selectors) {
    const name = `${selector}._domainkey.${domain}`;
    const values = await txtOrEmpty(resolver, name);
    if (values.length === 0) continue;
    const dkimValues = values.filter((v) => looksLikeDkim(v));
    if (dkimValues.length === 0) {
      // Wildcard/unrelated TXT at the selector name — not a DKIM key.
      findings.push(
        info(
          "dkim.non-dkim-txt",
          `TXT at ${name} exists but is not a DKIM key record ("${values[0]!.slice(0, 40)}"); ignored`,
        ),
      );
      continue;
    }
    found += 1;
    const raw = dkimValues[0]!;
    records.push(raw);
    const rec = parseDkimRecord(raw);

    for (const e of rec.errors) {
      findings.push(fail("dkim.record", `selector "${selector}": ${e}`));
    }
    if (rec.revoked) {
      findings.push(
        warn("dkim.revoked", `selector "${selector}" has an empty p= (key revoked)`),
      );
      continue;
    }
    if (rec.testing) {
      findings.push(
        warn(
          "dkim.testing",
          `selector "${selector}" is in testing mode (t=y); receivers may ignore signatures`,
          "Remove t=y once signing works.",
        ),
      );
    }
    if (rec.keyType === "rsa" && rec.keyBits !== undefined) {
      if (rec.keyBits < 1024) {
        findings.push(
          fail(
            "dkim.key-weak",
            `selector "${selector}": RSA key is only ${rec.keyBits} bits; receivers ignore keys under 1024 bits`,
            "Rotate to a 2048-bit key.",
          ),
        );
      } else if (rec.keyBits < 2048) {
        findings.push(
          warn(
            "dkim.key-short",
            `selector "${selector}": RSA-${rec.keyBits} key found; 2048 bits is the current baseline`,
          ),
        );
      } else {
        findings.push(
          pass("dkim.key", `selector "${selector}": valid RSA-${rec.keyBits} key`),
        );
      }
    } else if (rec.keyType === "ed25519" && rec.errors.length === 0) {
      findings.push(pass("dkim.key", `selector "${selector}": valid ed25519 key`));
    }
  }

  if (found === 0) {
    findings.push(
      fail(
        "dkim.missing",
        `no DKIM key found under any probed selector (${selectors.join(", ")})`,
        "Pass your actual selector with --selector, or configure DKIM signing in your MTA. Gmail/Yahoo bulk-sender rules require DKIM.",
      ),
    );
  }

  return { area: "dkim", title: "DKIM", records, findings };
}

/** DMARC area. */
export async function checkDmarc(resolver: DnsResolver, domain: string): Promise<CheckResult> {
  const findings: Finding[] = [];
  const values = (await txtOrEmpty(resolver, `_dmarc.${domain}`)).filter(looksLikeDmarc);

  if (values.length === 0) {
    findings.push(
      fail(
        "dmarc.missing",
        `no DMARC record at _dmarc.${domain}`,
        `Publish at least "v=DMARC1; p=none; rua=mailto:dmarc@${domain}" — Gmail/Yahoo require DMARC for bulk senders since 2024, and enforcement hardened in 2025.`,
      ),
    );
    return { area: "dmarc", title: "DMARC", records: [], findings };
  }
  if (values.length > 1) {
    findings.push(
      fail("dmarc.multiple", `${values.length} DMARC records published; receivers ignore all of them`),
    );
  }

  const record = parseDmarcRecord(values[0]!);
  for (const e of record.errors) {
    findings.push(fail("dmarc.syntax", `syntax: ${e}`));
  }

  switch (record.policy) {
    case "reject":
      findings.push(pass("dmarc.policy", "policy is p=reject (strongest)"));
      break;
    case "quarantine":
      findings.push(pass("dmarc.policy", "policy is p=quarantine"));
      break;
    case "none":
      findings.push(
        warn(
          "dmarc.policy-none",
          "policy is p=none: you receive reports but spoofed mail is still delivered",
          "Move to p=quarantine once reports show your own mail passing.",
        ),
      );
      break;
    default:
      break; // Missing p= already reported as a syntax failure.
  }

  if (record.rua.length === 0) {
    findings.push(
      warn(
        "dmarc.no-rua",
        "no rua= aggregate report address: you are flying blind on who sends as your domain",
        `Add rua=mailto:dmarc@${domain} and read reports with "postdoctor dmarc-report".`,
      ),
    );
  } else {
    findings.push(pass("dmarc.rua", `aggregate reports go to ${record.rua.join(", ")}`));
    for (const addr of record.rua) {
      const ruaDomain = addr.split("@")[1]?.toLowerCase() ?? "";
      if (ruaDomain && ruaDomain !== domain.toLowerCase() && !ruaDomain.endsWith(`.${domain.toLowerCase()}`)) {
        findings.push(
          info(
            "dmarc.external-rua",
            `rua destination ${addr} is external; it must publish a ${domain}._report._dmarc.${ruaDomain} authorization record`,
          ),
        );
      }
    }
  }

  if (record.pct < 100) {
    findings.push(
      warn("dmarc.pct", `pct=${record.pct}: policy only applies to ${record.pct}% of failing mail`),
    );
  }

  return { area: "dmarc", title: "DMARC", records: values, findings };
}

/** MTA-STS + TLS-RPT area. */
export async function checkMtaSts(
  resolver: DnsResolver,
  fetcher: HttpFetcher,
  domain: string,
): Promise<CheckResult> {
  const findings: Finding[] = [];
  const records: string[] = [];

  const stsTxt = (await txtOrEmpty(resolver, `_mta-sts.${domain}`)).filter((v) =>
    v.startsWith("v=STSv1"),
  );

  if (stsTxt.length === 0) {
    findings.push(
      info(
        "mtasts.missing",
        `no MTA-STS record at _mta-sts.${domain} (optional, but protects inbound mail from TLS downgrade)`,
        `Generate one with "postdoctor gen".`,
      ),
    );
  } else {
    records.push(stsTxt[0]!);
    const rec = parseStsDnsRecord(stsTxt[0]!);
    for (const e of rec.errors) findings.push(fail("mtasts.dns", `_mta-sts record: ${e}`));

    const url = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;
    let policyBody: string | undefined;
    try {
      const res = await fetcher.get(url);
      if (res.status === 200) policyBody = res.body;
      else findings.push(fail("mtasts.policy-fetch", `policy fetch ${url} returned HTTP ${res.status}`));
    } catch (err) {
      findings.push(
        fail(
          "mtasts.policy-fetch",
          `cannot fetch ${url}: ${err instanceof Error ? err.message : String(err)}`,
        ),
      );
    }

    if (policyBody !== undefined) {
      const policy = parseMtaStsPolicy(policyBody);
      for (const e of policy.errors) findings.push(fail("mtasts.policy", `policy file: ${e}`));
      if (policy.errors.length === 0) {
        findings.push(
          pass("mtasts.policy", `MTA-STS policy valid (mode=${policy.mode}, ${policy.mx.length} mx)`),
        );
        if (policy.mode === "testing") {
          findings.push(
            info("mtasts.testing", "MTA-STS is in testing mode; switch to enforce when confident"),
          );
        }
        // Cross-check the policy mx list against the live MX set.
        try {
          const mx = await resolver.resolveMx(domain);
          for (const m of mx) {
            if (!mxMatchesPolicy(m.exchange, policy.mx)) {
              findings.push(
                fail(
                  "mtasts.mx-mismatch",
                  `MX host ${m.exchange} is not covered by the MTA-STS policy (${policy.mx.join(", ")}); enforcing senders will refuse to deliver to it`,
                ),
              );
            }
          }
        } catch (err) {
          if (!(err instanceof DnsNotFoundError)) throw err;
        }
      }
    }
  }

  const tlsrpt = (await txtOrEmpty(resolver, `_smtp._tls.${domain}`)).filter((v) =>
    v.startsWith("v=TLSRPTv1"),
  );
  if (tlsrpt.length === 0) {
    findings.push(
      info("tlsrpt.missing", `no TLS-RPT record at _smtp._tls.${domain} (optional; get TLS failure reports)`),
    );
  } else {
    records.push(tlsrpt[0]!);
    const rec = parseTlsRptRecord(tlsrpt[0]!);
    for (const e of rec.errors) findings.push(fail("tlsrpt.syntax", `TLS-RPT record: ${e}`));
    if (rec.errors.length === 0) {
      findings.push(pass("tlsrpt.present", `TLS-RPT reports go to ${rec.rua.join(", ")}`));
    }
  }

  return { area: "mtasts", title: "MTA-STS / TLS-RPT", records, findings };
}

/** Resolve the candidate sending IPs for a domain (MX hosts' A/AAAA records). */
export async function discoverSendingIps(
  resolver: DnsResolver,
  domain: string,
): Promise<{ ips: string[]; findings: Finding[] }> {
  const findings: Finding[] = [];
  let mx;
  try {
    mx = await resolver.resolveMx(domain);
  } catch (err) {
    if (err instanceof DnsNotFoundError) {
      findings.push(
        warn("rdns.no-mx", `${domain} has no MX record; cannot infer sending IPs (pass --ip)`),
      );
      return { ips: [], findings };
    }
    throw err;
  }

  const ips: string[] = [];
  for (const rec of mx.sort((a, b) => a.priority - b.priority)) {
    for (const method of ["resolveA", "resolveAaaa"] as const) {
      try {
        for (const ip of await resolver[method](rec.exchange)) {
          if (!ips.includes(ip)) ips.push(ip);
        }
      } catch (err) {
        if (!(err instanceof DnsNotFoundError)) throw err;
      }
    }
  }
  if (ips.length === 0) {
    findings.push(fail("rdns.mx-unresolvable", `none of the MX hosts of ${domain} resolve to an IP`));
  }
  return { ips, findings };
}

/** rDNS area: PTR presence + forward-confirmation (FCrDNS) for each sending IP. */
export async function checkRdns(
  resolver: DnsResolver,
  domain: string,
  ips: string[],
  extraFindings: Finding[] = [],
): Promise<CheckResult> {
  const findings: Finding[] = [...extraFindings];

  for (const ip of ips) {
    let ptrs: string[];
    try {
      ptrs = await resolver.reverse(ip);
    } catch (err) {
      if (err instanceof DnsNotFoundError) {
        findings.push(
          fail(
            "rdns.missing-ptr",
            `${ip} has no PTR record; Gmail rejects mail from IPs without valid rDNS`,
            "Ask your hosting provider to set the PTR to your mail hostname.",
          ),
        );
        continue;
      }
      throw err;
    }

    let confirmed = false;
    for (const ptr of ptrs) {
      const host = ptr.replace(/\.$/, "");
      let forward: string[] = [];
      try {
        forward = await resolver.resolveA(host);
      } catch (err) {
        if (!(err instanceof DnsNotFoundError)) throw err;
      }
      if (forward.length === 0) {
        try {
          forward = await resolver.resolveAaaa(host);
        } catch (err) {
          if (!(err instanceof DnsNotFoundError)) throw err;
        }
      }
      if (forward.includes(ip)) {
        confirmed = true;
        findings.push(pass("rdns.fcrdns", `${ip} → ${host} → ${ip} (forward-confirmed rDNS)`));
        break;
      }
    }
    if (!confirmed && ptrs.length > 0) {
      findings.push(
        fail(
          "rdns.not-confirmed",
          `${ip} has PTR ${ptrs.join(", ")} but the name does not resolve back to ${ip}`,
          "PTR and A/AAAA must agree (FCrDNS); fix the forward record.",
        ),
      );
    }
  }

  if (ips.length === 0 && findings.length === 0) {
    findings.push(warn("rdns.no-ips", "no sending IPs to check (pass --ip)"));
  }

  return { area: "rdns", title: "Reverse DNS", records: [], findings };
}

/** Expand an IPv4 address into the DNSBL query name for a zone. */
export function dnsblQueryName(ip: string, zone: string): string | undefined {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return undefined; // IPv6 blocklist coverage varies; we only query IPv4.
  return `${m[4]}.${m[3]}.${m[2]}.${m[1]}.${zone}`;
}

/** DNSBL area: query each IPv4 against each blocklist zone. */
export async function checkDnsbl(
  resolver: DnsResolver,
  ips: string[],
  zones: string[] = DEFAULT_DNSBL_ZONES,
): Promise<CheckResult> {
  const findings: Finding[] = [];
  const v4 = ips.filter((ip) => dnsblQueryName(ip, "x") !== undefined);

  for (const ip of v4) {
    let listedAnywhere = false;
    for (const zone of zones) {
      const name = dnsblQueryName(ip, zone)!;
      try {
        const answers = await resolver.resolveA(name);
        // Spamhaus answers 127.255.255.x when the query came through a
        // public/blocked resolver — that is an error signal, not a listing.
        const errorCodes = answers.filter((a) => a.startsWith("127.255.255."));
        const listings = answers.filter((a) => !a.startsWith("127.255.255."));
        if (errorCodes.length > 0) {
          findings.push(
            info(
              "dnsbl.query-refused",
              `${zone} refused the query for ${ip} (${errorCodes.join(", ")}); use a non-public DNS resolver for reliable results`,
            ),
          );
        }
        if (listings.length > 0) {
          listedAnywhere = true;
          findings.push(
            fail(
              "dnsbl.listed",
              `${ip} is listed on ${zone} (${listings.join(", ")})`,
              `Request delisting at the ${zone} website after fixing the underlying cause.`,
            ),
          );
        }
      } catch (err) {
        if (err instanceof DnsNotFoundError) continue; // NXDOMAIN = not listed.
        if (err instanceof DnsLookupError) {
          findings.push(
            info("dnsbl.unreachable", `${zone} did not answer for ${ip} (${err.message})`),
          );
          continue;
        }
        throw err;
      }
    }
    if (!listedAnywhere) {
      findings.push(pass("dnsbl.clean", `${ip} is not listed on ${zones.length} checked blocklists`));
    }
  }

  if (v4.length === 0) {
    findings.push(info("dnsbl.skipped", "no IPv4 sending addresses found; blocklist check skipped"));
  }

  return { area: "dnsbl", title: "Blocklists (DNSBL)", records: [], findings };
}

/** Run every check area and assemble the full report. */
export async function runChecks(
  resolver: DnsResolver,
  fetcher: HttpFetcher,
  domain: string,
  options: CheckOptions = {},
): Promise<DomainReport> {
  const selectors = options.selectors?.length ? options.selectors : DEFAULT_SELECTORS;

  const spf = await checkSpf(resolver, domain);
  const dkim = await checkDkim(resolver, domain, selectors);
  const dmarc = await checkDmarc(resolver, domain);
  const mtasts = await checkMtaSts(resolver, fetcher, domain);

  let ips = options.ips ?? [];
  let discoveryFindings: Finding[] = [];
  if (ips.length === 0) {
    const discovered = await discoverSendingIps(resolver, domain);
    ips = discovered.ips;
    discoveryFindings = discovered.findings;
  }
  const rdns = await checkRdns(resolver, domain, ips, discoveryFindings);

  const results = [spf, dkim, dmarc, mtasts, rdns];
  if (!options.skipDnsbl) {
    results.push(await checkDnsbl(resolver, ips, options.dnsblZones));
  }

  return { domain, checkedAt: new Date().toISOString(), results };
}
