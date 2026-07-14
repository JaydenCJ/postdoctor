/**
 * Public library surface of postdoctor.
 *
 * Everything here is usable programmatically:
 *
 *   import { runChecks, NodeDnsResolver, NodeHttpFetcher } from "postdoctor";
 *   const report = await runChecks(new NodeDnsResolver(), new NodeHttpFetcher(), "example.com");
 */
export * from "./types.js";
export * from "./net/resolver.js";
export * from "./net/fetcher.js";
export * from "./net/fixture.js";
export { parseSpf, looksLikeSpf, isValidIp4, isValidIp6 } from "./spf/parser.js";
export type {
  SpfRecord,
  SpfTerm,
  SpfMechanism,
  SpfModifier,
  SpfQualifier,
  SpfMechanismKind,
} from "./spf/parser.js";
export { evaluateSpf } from "./spf/evaluator.js";
export type { SpfEvaluation } from "./spf/evaluator.js";
export { parseDkimRecord, parseTagValueList, rsaKeyBits, looksLikeDkim } from "./dkim/record.js";
export type { DkimKeyRecord } from "./dkim/record.js";
export { parseDmarcRecord, looksLikeDmarc } from "./dmarc/record.js";
export type { DmarcRecord, DmarcPolicy } from "./dmarc/record.js";
export { parseAggregateReport, summarizeReport } from "./dmarc/report.js";
export type { AggregateReport, ReportRow, ReportSummary } from "./dmarc/report.js";
export {
  parseMtaStsPolicy,
  parseStsDnsRecord,
  parseTlsRptRecord,
  mxMatchesPolicy,
} from "./mtasts/policy.js";
export type { MtaStsPolicy, StsDnsRecord, TlsRptRecord } from "./mtasts/policy.js";
export {
  runChecks,
  checkSpf,
  checkDkim,
  checkDmarc,
  checkMtaSts,
  checkRdns,
  checkDnsbl,
  discoverSendingIps,
  dnsblQueryName,
  DEFAULT_SELECTORS,
  DEFAULT_DNSBL_ZONES,
} from "./engine.js";
export type { CheckOptions } from "./engine.js";
export { generateRecords, toZoneFile, quoteTxt } from "./gen/generate.js";
export type { GenerateOptions, GeneratedRecord, GeneratedSet } from "./gen/generate.js";
export { takeSnapshot, diffSnapshots, watchedNames } from "./gen/diff.js";
export type { DnsSnapshot, RecordChange } from "./gen/diff.js";
export { buildChecklist, ALL_PROVIDERS } from "./checklist.js";
export type { Provider, ProviderChecklist, ChecklistItem } from "./checklist.js";
export { watch, ntfyChannel, telegramChannel } from "./watch.js";
export type { WatchOptions, CycleOutcome, AlertChannel } from "./watch.js";
