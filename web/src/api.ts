// Raylane Web UI — same-origin API client.
//
// T009: talks ONLY to the same-origin HTTPS management API under /api/v1.
// The session is an HttpOnly, Secure, SameSite=Strict cookie: this client
// never reads, stores or transmits the token, and never touches any
// localStorage/sessionStorage/cookie. Requests are same-origin with the
// browser-managed Origin header (no spoofed headers, no CSRF token — the
// settled wire contract).

export interface RuntimeReadiness {
  management: boolean;
  dns: boolean;
  engine: boolean;
  classification: boolean;
}

export interface RuntimeState {
  phase: string;
  readiness: RuntimeReadiness;
  draftRevisionId?: string;
  activeRevisionId?: string;
  // activeGeneration is an INTEGER 0..9007199254740991 on the wire (0 is a
  // meaningful value), NOT a string.
  activeGeneration?: number;
  lastErrorCode?: string;
  lastErrorMessage?: string;
}

// ProbeResult: `auth` (401) is the ONLY authentication-negative signal;
// `unknown` means the transport failed, timed out, or the server answered an
// unexpected status/shape. `unknown` NEVER proves the session ended — the
// caller keeps a retained snapshot and offers a read-only Retry, never an
// auto-retry, a sign-out, or a mutation replay.
export type ProbeResult =
  | { kind: 'ok'; state: RuntimeState }
  | { kind: 'auth' }
  | { kind: 'unknown'; retained: boolean };

const JSON_HEADERS = { 'Content-Type': 'application/json' };

export async function probeState(signal: AbortSignal | null = null): Promise<ProbeResult> {
  let res: Response;
  try {
    res = await fetch('/api/v1/state', {
      method: 'GET',
      credentials: 'same-origin',
      cache: 'no-store',
      signal,
    });
  } catch {
    return { kind: 'unknown', retained: true };
  }
  if (res.status === 401) return { kind: 'auth' };
  if (!res.ok) return { kind: 'unknown', retained: true };
  try {
    const data = (await res.json()) as RuntimeState;
    if (!data || typeof data.phase !== 'string' || !data.readiness) {
      return { kind: 'unknown', retained: true };
    }
    return { kind: 'ok', state: data };
  } catch {
    return { kind: 'unknown', retained: true };
  }
}

export type LoginResult =
  | { kind: 'ok' }
  | { kind: 'invalid' } // 401 — generic, no per-field oracle
  | { kind: 'tooLarge' } // 413
  | { kind: 'rateLimited'; retryAfter: number | null } // 429, optional Retry-After
  | { kind: 'csrf' } // 403 Origin rejected
  | { kind: 'unknown' };

// loginBody is THE single JSON encoder for the login payload. The form
// validates the serialized size with this exact function before sending, so
// client-side checking and the wire can never disagree (and the server's own
// 413 remains an independent second enforcement of the same bound).
export function loginBody(username: string, password: string): string {
  return JSON.stringify({ username, password });
}

export async function login(
  username: string,
  password: string,
  signal: AbortSignal | null = null,
): Promise<LoginResult> {
  let res: Response;
  try {
    res = await fetch('/api/v1/session', {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: JSON_HEADERS,
      body: loginBody(username, password),
      signal,
    });
  } catch {
    return { kind: 'unknown' };
  }
  if (res.status === 204) return { kind: 'ok' };
  if (res.status === 401) return { kind: 'invalid' };
  if (res.status === 413) return { kind: 'tooLarge' };
  if (res.status === 403) return { kind: 'csrf' };
  if (res.status === 429) {
    const ra = res.headers.get('Retry-After');
    const n = ra ? Number.parseInt(ra, 10) : NaN;
    return { kind: 'rateLimited', retryAfter: Number.isInteger(n) && n > 0 ? n : null };
  }
  return { kind: 'unknown' };
}

// LogoutResult: `confirmed` (204 or 401) means the session is invalidated /
// already invalid — a truthful signed-out state. `unknown` is a network
// failure and is NOT a confirmed revocation.
export type LogoutResult = { kind: 'confirmed' } | { kind: 'unknown' };

export async function logout(signal: AbortSignal | null = null): Promise<LogoutResult> {
  let res: Response;
  try {
    res = await fetch('/api/v1/session', {
      method: 'DELETE',
      credentials: 'same-origin',
      cache: 'no-store',
      signal,
    });
  } catch {
    return { kind: 'unknown' };
  }
  if (res.status === 204 || res.status === 401) return { kind: 'confirmed' };
  return { kind: 'unknown' };
}
