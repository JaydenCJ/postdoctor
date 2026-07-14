/**
 * HTTPS access (MTA-STS policy download, ntfy/Telegram alert delivery) is
 * isolated behind HttpFetcher so tests can use in-memory fakes.
 */

export interface HttpResponse {
  status: number;
  body: string;
}

export interface HttpFetcher {
  /** GET a URL and return status + body as text. */
  get(url: string, timeoutMs?: number): Promise<HttpResponse>;
  /** POST a payload (used for alert webhooks). */
  post(
    url: string,
    body: string,
    headers?: Record<string, string>,
    timeoutMs?: number,
  ): Promise<HttpResponse>;
}

const DEFAULT_TIMEOUT_MS = 10_000;

/** Production fetcher backed by global fetch. */
export class NodeHttpFetcher implements HttpFetcher {
  async get(url: string, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<HttpResponse> {
    const res = await fetch(url, {
      signal: AbortSignal.timeout(timeoutMs),
      redirect: "manual",
    });
    return { status: res.status, body: await res.text() };
  }

  async post(
    url: string,
    body: string,
    headers: Record<string, string> = {},
    timeoutMs = DEFAULT_TIMEOUT_MS,
  ): Promise<HttpResponse> {
    const res = await fetch(url, {
      method: "POST",
      body,
      headers,
      signal: AbortSignal.timeout(timeoutMs),
    });
    return { status: res.status, body: await res.text() };
  }
}
