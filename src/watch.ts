/**
 * Watch mode: a foreground monitoring loop.
 *
 * Every cycle it re-runs the health checks and the DNS drift diff. When the
 * overall state degrades (new fail findings) or any watched record changes,
 * it sends an alert through the configured channels (ntfy topic and/or
 * Telegram bot) and logs to stdout. Runs in the foreground so it is
 * container/systemd/compose friendly; `--max-cycles` bounds it for smoke
 * tests and one-shot cron usage.
 */
import type { DnsResolver } from "./net/resolver.js";
import type { HttpFetcher } from "./net/fetcher.js";
import { runChecks } from "./engine.js";
import type { CheckOptions } from "./engine.js";
import { DEFAULT_SELECTORS } from "./engine.js";
import { diffSnapshots, takeSnapshot } from "./gen/diff.js";
import type { DnsSnapshot } from "./gen/diff.js";
import { reportSeverity } from "./types.js";
import type { DomainReport } from "./types.js";

export interface AlertChannel {
  name: string;
  send(title: string, body: string): Promise<void>;
}

/** ntfy.sh (or self-hosted ntfy) topic channel. */
export function ntfyChannel(fetcher: HttpFetcher, url: string): AlertChannel {
  return {
    name: "ntfy",
    async send(title, body) {
      await fetcher.post(url, body, { Title: title, Priority: "high" });
    },
  };
}

/** Telegram bot channel. The token is passed to the API URL, never logged. */
export function telegramChannel(
  fetcher: HttpFetcher,
  botToken: string,
  chatId: string,
): AlertChannel {
  return {
    name: "telegram",
    async send(title, body) {
      await fetcher.post(
        `https://api.telegram.org/bot${botToken}/sendMessage`,
        JSON.stringify({ chat_id: chatId, text: `${title}\n\n${body}` }),
        { "Content-Type": "application/json" },
      );
    },
  };
}

export interface WatchOptions extends CheckOptions {
  /** Seconds between cycles (default 900 = 15 min). */
  intervalSeconds?: number;
  /** Stop after N cycles (0 = run forever). */
  maxCycles?: number;
  channels?: AlertChannel[];
  /** Log sink (default console.log). */
  log?: (line: string) => void;
  /** Sleep implementation, injectable for tests. */
  sleep?: (ms: number) => Promise<void>;
}

export interface CycleOutcome {
  cycle: number;
  report: DomainReport;
  /** Alert messages sent this cycle (empty = all quiet). */
  alerts: string[];
}

function failCodes(report: DomainReport): Set<string> {
  return new Set(
    report.results
      .flatMap((r) => r.findings)
      .filter((f) => f.severity === "fail")
      .map((f) => `${f.code}: ${f.message}`),
  );
}

const defaultSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/**
 * Run the watch loop. Resolves when maxCycles is reached; runs indefinitely
 * when maxCycles is 0. Returns the outcome of every executed cycle.
 */
export async function watch(
  resolver: DnsResolver,
  fetcher: HttpFetcher,
  domain: string,
  options: WatchOptions = {},
): Promise<CycleOutcome[]> {
  const log = options.log ?? ((line: string) => console.log(line));
  const sleep = options.sleep ?? defaultSleep;
  const intervalMs = (options.intervalSeconds ?? 900) * 1000;
  const maxCycles = options.maxCycles ?? 0;
  const channels = options.channels ?? [];
  const selectors = options.selectors?.length ? options.selectors : DEFAULT_SELECTORS;

  let previousFails: Set<string> | undefined;
  let previousSnapshot: DnsSnapshot | undefined;
  const outcomes: CycleOutcome[] = [];

  for (let cycle = 1; maxCycles === 0 || cycle <= maxCycles; cycle++) {
    const startedAt = new Date().toISOString();
    const report = await runChecks(resolver, fetcher, domain, options);
    const snapshot = await takeSnapshot(resolver, domain, selectors);
    const fails = failCodes(report);
    const alerts: string[] = [];

    // New failures compared with the previous cycle.
    if (previousFails !== undefined) {
      const newFails = [...fails].filter((f) => !previousFails!.has(f));
      if (newFails.length > 0) {
        alerts.push(`New failure(s) on ${domain}:\n${newFails.map((f) => `- ${f}`).join("\n")}`);
      }
      const resolved = [...previousFails].filter((f) => !fails.has(f));
      if (resolved.length > 0) {
        log(`[watch] ${resolved.length} previous failure(s) resolved`);
      }
    } else if (fails.size > 0) {
      // First cycle: report the starting position once.
      alerts.push(
        `Watch started for ${domain} with ${fails.size} existing failure(s):\n${[...fails]
          .map((f) => `- ${f}`)
          .join("\n")}`,
      );
    }

    // DNS drift compared with the previous cycle.
    if (previousSnapshot !== undefined) {
      const changes = diffSnapshots(previousSnapshot, snapshot);
      if (changes.length > 0) {
        const lines = changes.map((c) =>
          c.kind === "changed"
            ? `~ ${c.name}: "${c.before}" -> "${c.after}"`
            : c.kind === "added"
              ? `+ ${c.name}: "${c.after}"`
              : `- ${c.name}: "${c.before}"`,
        );
        alerts.push(`DNS records changed on ${domain}:\n${lines.join("\n")}`);
      }
    }

    for (const alert of alerts) {
      for (const channel of channels) {
        try {
          await channel.send(`postdoctor: ${domain}`, alert);
        } catch (err) {
          log(`[watch] alert via ${channel.name} failed: ${err instanceof Error ? err.message : String(err)}`);
        }
      }
    }

    const overall = reportSeverity(report);
    log(
      `[watch] cycle ${cycle} at ${startedAt}: overall=${overall} fails=${fails.size} alerts=${alerts.length}`,
    );

    outcomes.push({ cycle, report, alerts });
    previousFails = fails;
    previousSnapshot = snapshot;

    const isLast = maxCycles !== 0 && cycle >= maxCycles;
    if (!isLast) await sleep(intervalMs);
  }

  return outcomes;
}
