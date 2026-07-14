#!/usr/bin/env node
/**
 * postdoctor CLI.
 *
 * Exit codes:
 *   0  command succeeded and no failing findings
 *   1  command succeeded but failing findings / drift were detected
 *   2  execution error (bad arguments, unreadable file, DNS transport error)
 */
import { readFile, writeFile } from "node:fs/promises";
import { Command, CommanderError } from "commander";

import { NodeDnsResolver } from "./net/resolver.js";
import type { DnsResolver } from "./net/resolver.js";
import { NodeHttpFetcher } from "./net/fetcher.js";
import type { HttpFetcher } from "./net/fetcher.js";
import { loadFixture } from "./net/fixture.js";
import { runChecks } from "./engine.js";
import { reportSeverity } from "./types.js";
import { generateRecords, toZoneFile } from "./gen/generate.js";
import { diffSnapshots, takeSnapshot } from "./gen/diff.js";
import type { DnsSnapshot } from "./gen/diff.js";
import { parseAggregateReport, summarizeReport } from "./dmarc/report.js";
import { ALL_PROVIDERS, buildChecklist } from "./checklist.js";
import type { Provider } from "./checklist.js";
import {
  renderChanges,
  renderChecklist,
  renderReport,
  renderReportSummary,
} from "./format.js";
import { ntfyChannel, telegramChannel, watch } from "./watch.js";
import type { AlertChannel } from "./watch.js";

const VERSION = "0.1.0";

/** Error whose message is safe to show the user as-is. */
class CliError extends Error {}

async function backends(
  fixturePath: string | undefined,
): Promise<{ resolver: DnsResolver; fetcher: HttpFetcher }> {
  if (fixturePath) return loadFixture(fixturePath);
  return { resolver: new NodeDnsResolver(), fetcher: new NodeHttpFetcher() };
}

function collect(value: string, previous: string[]): string[] {
  return [...previous, value];
}

function validateDomain(domain: string): string {
  const d = domain.trim().toLowerCase().replace(/\.$/, "");
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(d)) {
    throw new CliError(`"${domain}" is not a valid domain name`);
  }
  return d;
}

const program = new Command();

program
  .name("postdoctor")
  .description(
    "Deliverability doctor for self-hosted email: check SPF/DKIM/DMARC/rDNS/MTA-STS, generate and diff DNS records, translate DMARC reports, monitor continuously.",
  )
  .version(VERSION)
  .exitOverride()
  .configureOutput({ writeErr: (str) => process.stderr.write(str) });

program
  .command("check")
  .description("run a full deliverability health check for a domain")
  .argument("<domain>", "domain to check, e.g. example.com")
  .option("-s, --selector <selector>", "DKIM selector to inspect (repeatable)", collect, [])
  .option("--ip <ip>", "sending IP to verify (repeatable; default: derived from MX)", collect, [])
  .option("--no-dnsbl", "skip DNS blocklist queries")
  .option("--json", "print the report as JSON")
  .option("--dns-fixture <file>", "answer DNS/HTTP from a fixture JSON (offline mode)")
  .action(async (domainArg: string, opts) => {
    const domain = validateDomain(domainArg);
    const { resolver, fetcher } = await backends(opts.dnsFixture);
    const report = await runChecks(resolver, fetcher, domain, {
      selectors: opts.selector,
      ips: opts.ip,
      skipDnsbl: opts.dnsbl === false,
    });
    if (opts.json) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log(renderReport(report));
    }
    process.exitCode = reportSeverity(report) === "fail" ? 1 : 0;
  });

program
  .command("gen")
  .description("generate the recommended DNS record set for a domain")
  .argument("<domain>", "domain to generate records for")
  .option("--ip <ip>", "IP allowed to send (repeatable)", collect, [])
  .option("--include <domain>", "SPF include target, e.g. a relay provider (repeatable)", collect, [])
  .option("--mx-host <host>", "MX hostname for the MTA-STS policy (repeatable)", collect, [])
  .option("--rua <email>", "address for DMARC/TLS reports (default dmarc@<domain>)")
  .option("--policy <p>", "DMARC policy: none | quarantine | reject", "none")
  .option("--selector <selector>", "DKIM selector (with --dkim-key)")
  .option("--dkim-key <base64>", "DKIM public key from your MTA")
  .option("--no-mta-sts", "skip MTA-STS / TLS-RPT records")
  .option("--json", "print records as JSON")
  .action(async (domainArg: string, opts) => {
    const domain = validateDomain(domainArg);
    if (!["none", "quarantine", "reject"].includes(opts.policy)) {
      throw new CliError(`--policy must be none, quarantine or reject (got "${opts.policy}")`);
    }
    const set = generateRecords({
      domain,
      ips: opts.ip,
      includes: opts.include,
      mxHosts: opts.mxHost.length > 0 ? opts.mxHost : undefined,
      rua: opts.rua,
      policy: opts.policy,
      selector: opts.selector,
      dkimPublicKey: opts.dkimKey,
      mtaSts: opts.mtaSts,
    });
    if (opts.json) {
      console.log(JSON.stringify(set, null, 2));
      return;
    }
    console.log(toZoneFile(set));
    if (set.mtaStsPolicyFile) {
      console.log(`; --- serve this at https://mta-sts.${domain}/.well-known/mta-sts.txt ---`);
      console.log(set.mtaStsPolicyFile);
    }
    for (const note of set.notes) console.log(`; NOTE: ${note}`);
  });

program
  .command("diff")
  .description("compare live DNS against a saved baseline and report drift")
  .argument("<domain>", "domain to diff")
  .option("-b, --baseline <file>", "baseline JSON file", "postdoctor-baseline.json")
  .option("--save", "write the current live state as the new baseline")
  .option("-s, --selector <selector>", "DKIM selector to include (repeatable)", collect, [])
  .option("--dns-fixture <file>", "answer DNS from a fixture JSON (offline mode)")
  .action(async (domainArg: string, opts) => {
    const domain = validateDomain(domainArg);
    const { resolver } = await backends(opts.dnsFixture);
    const selectors: string[] = opts.selector.length > 0 ? opts.selector : ["default", "dkim", "mail"];
    const current = await takeSnapshot(resolver, domain, selectors);

    if (opts.save) {
      await writeFile(opts.baseline, `${JSON.stringify(current, null, 2)}\n`, "utf8");
      console.log(`Baseline saved to ${opts.baseline} (${Object.keys(current.txt).length} TXT names, ${current.mx.length} MX).`);
      return;
    }

    let raw: string;
    try {
      raw = await readFile(opts.baseline, "utf8");
    } catch {
      throw new CliError(
        `baseline file "${opts.baseline}" not found — create one first with: postdoctor diff ${domain} --save`,
      );
    }
    let baseline: DnsSnapshot;
    try {
      baseline = JSON.parse(raw) as DnsSnapshot;
    } catch {
      throw new CliError(`baseline file "${opts.baseline}" is not valid JSON`);
    }
    if (baseline.domain !== domain) {
      throw new CliError(
        `baseline is for "${baseline.domain}", not "${domain}" — use a separate baseline file per domain`,
      );
    }
    const changes = diffSnapshots(baseline, current);
    console.log(renderChanges(changes));
    process.exitCode = changes.length > 0 ? 1 : 0;
  });

program
  .command("dmarc-report")
  .description("translate a DMARC aggregate report (XML or .xml.gz) into plain language")
  .argument("<file>", "report file as mailed by Gmail/Outlook/Yahoo")
  .option("--json", "print the parsed report as JSON")
  .action(async (file: string, opts) => {
    let buf: Buffer;
    try {
      buf = await readFile(file);
    } catch {
      throw new CliError(`cannot read report file: ${file}`);
    }
    let report;
    try {
      report = parseAggregateReport(buf);
    } catch (err) {
      throw new CliError(
        `${file}: ${err instanceof Error ? err.message : String(err)} (expected a DMARC aggregate XML, optionally gzipped; unzip .zip attachments first)`,
      );
    }
    const summary = summarizeReport(report);
    if (opts.json) {
      console.log(JSON.stringify({ report, summary }, null, 2));
    } else {
      console.log(renderReportSummary(report, summary));
    }
    process.exitCode = summary.failMessages > 0 ? 1 : 0;
  });

program
  .command("checklist")
  .description("per-receiver compliance checklist (Gmail / Outlook / Yahoo)")
  .argument("<domain>", "domain to check")
  .option("-p, --provider <provider>", "gmail | outlook | yahoo (default: all)")
  .option("-s, --selector <selector>", "DKIM selector to inspect (repeatable)", collect, [])
  .option("--ip <ip>", "sending IP to verify (repeatable)", collect, [])
  .option("--dns-fixture <file>", "answer DNS/HTTP from a fixture JSON (offline mode)")
  .action(async (domainArg: string, opts) => {
    const domain = validateDomain(domainArg);
    const providers: Provider[] = opts.provider ? [opts.provider as Provider] : ALL_PROVIDERS;
    if (opts.provider && !ALL_PROVIDERS.includes(opts.provider as Provider)) {
      throw new CliError(`--provider must be one of: ${ALL_PROVIDERS.join(", ")}`);
    }
    const { resolver, fetcher } = await backends(opts.dnsFixture);
    const report = await runChecks(resolver, fetcher, domain, {
      selectors: opts.selector,
      ips: opts.ip,
    });
    let anyNotMet = false;
    for (const provider of providers) {
      const list = buildChecklist(report, provider);
      console.log(renderChecklist(list));
      console.log("");
      if (list.items.some((i) => i.status === "not-met")) anyNotMet = true;
    }
    process.exitCode = anyNotMet ? 1 : 0;
  });

program
  .command("watch")
  .description("monitor a domain in the foreground and alert on new failures or DNS drift")
  .argument("<domain>", "domain to monitor")
  .option("-i, --interval <seconds>", "seconds between cycles", "900")
  .option("--max-cycles <n>", "stop after N cycles (0 = forever)", "0")
  .option("-s, --selector <selector>", "DKIM selector to inspect (repeatable)", collect, [])
  .option("--ip <ip>", "sending IP to verify (repeatable)", collect, [])
  .option("--no-dnsbl", "skip DNS blocklist queries")
  .option("--ntfy <url>", "ntfy topic URL to alert, e.g. https://ntfy.sh/mytopic")
  .option("--telegram-token <token>", "Telegram bot token (or set POSTDOCTOR_TELEGRAM_TOKEN)")
  .option("--telegram-chat <chatId>", "Telegram chat id")
  .option("--dns-fixture <file>", "answer DNS/HTTP from a fixture JSON (offline mode)")
  .action(async (domainArg: string, opts) => {
    const domain = validateDomain(domainArg);
    const interval = Number(opts.interval);
    const maxCycles = Number(opts.maxCycles);
    if (!Number.isInteger(interval) || interval < 1) {
      throw new CliError(`--interval must be a positive integer of seconds (got "${opts.interval}")`);
    }
    if (!Number.isInteger(maxCycles) || maxCycles < 0) {
      throw new CliError(`--max-cycles must be a non-negative integer (got "${opts.maxCycles}")`);
    }

    const { resolver, fetcher } = await backends(opts.dnsFixture);
    const channels: AlertChannel[] = [];
    if (opts.ntfy) channels.push(ntfyChannel(fetcher, opts.ntfy));
    const tgToken: string | undefined = opts.telegramToken ?? process.env["POSTDOCTOR_TELEGRAM_TOKEN"];
    if (tgToken || opts.telegramChat) {
      if (!tgToken || !opts.telegramChat) {
        throw new CliError("Telegram alerts need both a token (--telegram-token or POSTDOCTOR_TELEGRAM_TOKEN) and --telegram-chat");
      }
      channels.push(telegramChannel(fetcher, tgToken, opts.telegramChat));
    }

    console.log(
      `[watch] monitoring ${domain} every ${interval}s` +
        (maxCycles > 0 ? ` for ${maxCycles} cycle(s)` : "") +
        (channels.length > 0 ? ` — alerts via ${channels.map((c) => c.name).join(", ")}` : " — no alert channel configured (logging only)"),
    );
    const outcomes = await watch(resolver, fetcher, domain, {
      selectors: opts.selector,
      ips: opts.ip,
      skipDnsbl: opts.dnsbl === false,
      intervalSeconds: interval,
      maxCycles,
      channels,
    });
    const lastReport = outcomes[outcomes.length - 1]?.report;
    process.exitCode = lastReport && reportSeverity(lastReport) === "fail" ? 1 : 0;
  });

async function main(): Promise<void> {
  try {
    await program.parseAsync(process.argv);
  } catch (err) {
    if (err instanceof CommanderError) {
      // commander already printed help/error text; map its exit code.
      process.exitCode = err.exitCode === 0 ? 0 : 2;
      return;
    }
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`postdoctor: error: ${message}\n`);
    process.exitCode = 2;
  }
}

void main();
