// Raylane Web UI — same-origin authentication + application shell.
//
// T009: one administrator signs in over the SAME trusted HTTPS origin, sees a
// truthful status panel, and recovers from session failure without losing
// still-open in-page state or applying anything accidentally. There is no node
// editor here: the stateful child below is a test-only canary that proves the
// RAM-preservation boundary (D5) without inventing a production editor.
//
// Design (cmw handoff + Apple Design skill): solid quiet surfaces, system
// font, visible focus, text not colour alone, reduced motion respected. No
// motion framework, no glass, no theme toggle.
import { useCallback, useEffect, useRef, useState } from 'react';

import {
  login,
  logout,
  probeState,
  type LoginResult,
  type RuntimeReadiness,
  type RuntimeState,
} from './api';

// AuthView is the coarse authorization state. `unknown` means the transport
// or an unexpected response prevented a definitive read: we keep any retained
// snapshot and offer a read-only Retry, never auto-retry or sign out.
type AuthView = 'unknown' | 'signedOut' | 'signedIn' | 'reauth';

interface SessionFlags {
  pending: boolean;
}

// Stateful canary standing in for a future editor. It holds ephemeral,
// in-RAM-only state (including a secret) that must survive an auth boundary
// (401/restart) without remount, and must be discarded only on an EXPLICIT
// user Discard — never autosaved, persisted or replayed.
interface CanaryState {
  text: string;
  secret: string;
  dirty: boolean;
}

function initialCanary(): CanaryState {
  return { text: '', secret: '', dirty: false };
}

const COPY = {
  product: 'Raylane',
  signInHeading: 'Sign in',
  username: 'Username',
  password: 'Password',
  signIn: 'Sign in',
  signingIn: 'Signing in…',
  genericAuthError: 'Invalid username or password.',
  tooLarge: 'The credentials exceed the size limit.',
  csrf: 'The request was rejected. Reload the page and try again.',
  rateLimited: 'Too many attempts. Try again later.',
  retryAfter: (s: number) => `Too many attempts. Try again in ${s} seconds.`,
  unknownError: 'Something went wrong. Check the connection and retry.',
  reauthHeading: 'Session expired',
  reauthBody: 'Sign in again to continue. Your unsaved changes are still here.',
  overview: 'Overview',
  status: 'Status',
  savedDraft: 'Saved draft',
  activeConfig: 'Active configuration',
  validation: 'Validation',
  runtime: 'Runtime',
  readiness: 'Readiness',
  notReported: 'Not reported',
  notRunning: 'Not running',
  signOut: 'Sign out',
  admin: 'Administrator',
  skip: 'Skip to content',
  stateLoading: 'Checking session…',
  stateUnknown: 'Connection problem',
  stateUnknownBody: 'The current status could not be refreshed. You can retry.',
  retry: 'Retry',
  retainedSnapshot: 'Showing the last known status.',
  unsavedChanges: 'You have unsaved changes.',
  stay: 'Stay',
  discardSignOut: 'Discard and sign out',
  cancel: 'Cancel',
  canaryLabel: 'Working notes (in-memory only)',
  canarySecretLabel: 'Sensitive note (in-memory only)',
  canaryHelp: 'Kept only in this page’s memory. Leaving or refreshing discards it.',
  discard: 'Discard',
  dirtyFlag: 'Unsaved changes present',
  noDraft: 'No saved draft',
  noActive: 'No active configuration',
  validationNotRun: 'Validation has not run',
  close: 'Close',
} as const;

export function App() {
  const [auth, setAuth] = useState<AuthView>('unknown');
  const [state, setState] = useState<RuntimeState | null>(null);
  const [retained, setRetained] = useState(false);
  const [probeError, setProbeError] = useState(false);
  const [canary, setCanary] = useState<CanaryState>(initialCanary);
  // Sign-out confirmation with a dirty canary: null = no dialog; otherwise the
  // pending sign-out waits for an explicit Stay / Discard+sign out decision.
  const [confirmSignOut, setConfirmSignOut] = useState(false);
  const flags = useRef<SessionFlags>({ pending: false });
  // Monotonic token so a late probe/login response can never overwrite a newer
  // auth state (stale-response protection).
  const generation = useRef(0);

  const refresh = useCallback(
    async (into: AuthView | 'auto' = 'auto') => {
      const myGen = ++generation.current;
      const result = await probeState();
      if (myGen !== generation.current) return; // stale response
      if (result.kind === 'ok') {
        setAuth(into === 'reauth' || into === 'auto' ? 'signedIn' : into);
        setState(result.state);
        setRetained(false);
        setProbeError(false);
      } else if (result.kind === 'auth') {
        // 401 only: move to the reauth gate, preserving the canary in RAM.
        setAuth(into === 'signedIn' ? 'reauth' : 'signedOut');
        setRetained(false);
        setProbeError(false);
      } else {
        // unknown: keep retained snapshot, do NOT sign out.
        if (into !== 'signedOut') {
          setAuth('unknown');
        }
        setRetained(true);
        setProbeError(true);
      }
    },
    [],
  );

  useEffect(() => {
    void refresh('auto');
  }, [refresh]);

  // Focus the main heading on auth-view transitions (not on background
  // refreshes, which must not steal focus).
  const mainRef = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    if (auth === 'signedOut' || auth === 'signedIn' || auth === 'reauth') {
      mainRef.current?.focus();
    }
  }, [auth]);

  const onLoggedIn = useCallback(() => {
    // After a successful (re)auth, re-read state before showing privileged
    // content; a failed follow-up read surfaces as unknown + Retry, never a
    // silent privileged render.
    void refresh('signedIn');
  }, [refresh]);

  const requestSignOut = useCallback(() => {
    if (canary.dirty) {
      setConfirmSignOut(true);
      return;
    }
    void doSignOut();
  }, [canary.dirty]);

  const doSignOut = useCallback(async () => {
    if (flags.current.pending) return;
    flags.current.pending = true;
    const result = await logout();
    flags.current.pending = false;
    if (result.kind === 'confirmed') {
      setConfirmSignOut(false);
      setCanary(initialCanary());
      setState(null);
      setRetained(false);
      setAuth('signedOut');
    } else {
      // Network failure is NOT a confirmed revocation: stay signed in, keep
      // the canary, and surface a persistent (non-toast) error.
      setConfirmSignOut(false);
      setProbeError(true);
    }
  }, []);

  return (
    <div className="app">
      <a className="skip" href="#main">
        {COPY.skip}
      </a>
      {(auth === 'signedIn' || auth === 'reauth' || auth === 'unknown') && (
        <header className="app__header">
          <span className="app__brand">{COPY.product}</span>
          <span className="app__user">{COPY.admin}</span>
          {auth === 'signedIn' && (
            <button type="button" className="button button--ghost" onClick={requestSignOut}>
              {COPY.signOut}
            </button>
          )}
        </header>
      )}

      {auth === 'unknown' && (
        <main className="main" id="main">
          <h1 className="main__heading" tabIndex={-1} ref={mainRef}>
            {COPY.stateUnknown}
          </h1>
          <section className="panel" aria-label={COPY.status}>
            <p className="panel__text">{COPY.stateUnknownBody}</p>
            {retained && state && (
              <p className="panel__text panel__text--muted">{COPY.retainedSnapshot}</p>
            )}
            {retained && state && <StatusPanel state={state} />}
            <button
              type="button"
              className="button"
              onClick={() => void refresh('auto')}
              disabled={flags.current.pending}
            >
              {COPY.retry}
            </button>
          </section>
        </main>
      )}

      {auth === 'signedOut' && (
        <main className="main main--center" id="main">
          <LoginForm onLoggedIn={onLoggedIn} headingRef={mainRef} />
        </main>
      )}

      {auth === 'reauth' && (
        <main className="main main--center" id="main">
          <LoginForm
            onLoggedIn={onLoggedIn}
            headingRef={mainRef}
            reauth
          />
          {/* The canary stays mounted across the auth boundary: its RAM state
              (including the secret) is preserved, proving D5 without a real
              editor. */}
          <Canary
            canary={canary}
            onChange={setCanary}
            hiddenPrivileged
            hiddenReason={COPY.reauthHeading}
          />
        </main>
      )}

      {auth === 'signedIn' && (
        <main className="main" id="main">
          <h1 className="main__heading" tabIndex={-1} ref={mainRef}>
            {COPY.overview}
          </h1>
          {probeError && (
            <p className="banner" role="alert">
              {COPY.stateUnknownBody}{' '}
              <button type="button" className="button button--ghost" onClick={() => void refresh('signedIn')}>
                {COPY.retry}
              </button>
            </p>
          )}
          <StatusPanel state={state} retained={retained} onRefresh={() => void refresh('signedIn')} />
          <Canary canary={canary} onChange={setCanary} />
        </main>
      )}

      {confirmSignOut && (
        <div className="dialog__backdrop" role="presentation">
          <div
            className="dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="signout-title"
          >
            <h2 className="dialog__title" id="signout-title">
              {COPY.unsavedChanges}
            </h2>
            <p className="panel__text">{COPY.canaryHelp}</p>
            <div className="dialog__actions">
              <button
                type="button"
                className="button"
                onClick={() => setConfirmSignOut(false)}
                autoFocus
              >
                {COPY.stay}
              </button>
              <button
                type="button"
                className="button button--danger"
                onClick={() => void doSignOut()}
              >
                {COPY.discardSignOut}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function LoginForm(props: {
  onLoggedIn: () => void;
  headingRef: React.RefObject<HTMLHeadingElement | null>;
  reauth?: boolean;
}) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const local = useRef<SessionFlags>({ pending: false });

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    // One POST per deliberate submit: guard duplicate Enter/click while busy.
    if (busy || local.current.pending) return;
    setError(null);
    setBusy(true);
    local.current.pending = true;
    const result: LoginResult = await login(username, password);
    local.current.pending = false;
    setBusy(false);
    switch (result.kind) {
      case 'ok':
        setPassword(''); // 204 clears the password; state is re-read by parent.
        props.onLoggedIn();
        return;
      case 'invalid':
        setError(COPY.genericAuthError);
        return;
      case 'tooLarge':
        setError(COPY.tooLarge);
        return;
      case 'csrf':
        setError(COPY.csrf);
        return;
      case 'rateLimited':
        setError(result.retryAfter ? COPY.retryAfter(result.retryAfter) : COPY.rateLimited);
        return;
      default:
        setError(COPY.unknownError);
    }
  };

  return (
    <section className="panel panel--auth" aria-labelledby="login-heading">
      <h1 className="main__heading" id="login-heading" tabIndex={-1} ref={props.headingRef}>
        {props.reauth ? COPY.reauthHeading : COPY.signInHeading}
      </h1>
      {props.reauth && <p className="panel__text">{COPY.reauthBody}</p>}
      <form className="form" onSubmit={(e) => void submit(e)}>
        <div className="field">
          <label className="field__label" htmlFor="username">
            {COPY.username}
          </label>
          <input
            id="username"
            name="username"
            type="text"
            autoComplete="username"
            required
            minLength={1}
            maxLength={256}
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            disabled={busy}
          />
        </div>
        <div className="field">
          <label className="field__label" htmlFor="password">
            {COPY.password}
          </label>
          <input
            id="password"
            name="password"
            type="password"
            autoComplete="current-password"
            required
            minLength={1}
            maxLength={1024}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={busy}
          />
        </div>
        {error && (
          <p className="field__error" role="alert">
            {error}
          </p>
        )}
        <button type="submit" className="button button--primary" disabled={busy}>
          {busy ? COPY.signingIn : props.reauth ? COPY.signIn : COPY.signIn}
        </button>
      </form>
      <p className="panel__text panel__text--muted">{COPY.canaryHelp}</p>
    </section>
  );
}

function StatusPanel(props: {
  state: RuntimeState | null;
  retained?: boolean;
  onRefresh?: () => void;
}) {
  const s = props.state;
  const readiness = s?.readiness;
  return (
    <section className="panel" aria-labelledby="status-heading">
      <div className="canary__head">
        <h2 className="panel__title" id="status-heading">
          {COPY.status}
        </h2>
        {props.onRefresh && (
          <button type="button" className="button button--ghost" onClick={props.onRefresh} data-testid="status-refresh">
            {COPY.retry}
          </button>
        )}
      </div>
      <dl className="status">
        <div className="status__row">
          <dt>{COPY.savedDraft}</dt>
          <dd>{s?.draftRevisionId ?? COPY.noDraft}</dd>
        </div>
        <div className="status__row">
          <dt>{COPY.activeConfig}</dt>
          <dd>{s?.activeRevisionId ?? COPY.noActive}</dd>
        </div>
        <div className="status__row">
          <dt>{COPY.validation}</dt>
          <dd>{COPY.validationNotRun}</dd>
        </div>
        <div className="status__row">
          <dt>{COPY.runtime}</dt>
          <dd>{s?.phase ?? COPY.notRunning}</dd>
        </div>
        <div className="status__row">
          <dt>{COPY.readiness}</dt>
          <dd>
            {readiness ? (
              <ul className="readiness">
                {(Object.keys(readiness) as (keyof RuntimeReadiness)[]).map((k) => (
                  <li key={k}>
                    {k}: {String(readiness[k])}
                  </li>
                ))}
              </ul>
            ) : (
              COPY.notReported
            )}
          </dd>
        </div>
      </dl>
      {s?.lastErrorCode && (
        <p className="panel__text" role="alert">
          {s.lastErrorCode}
          {s.lastErrorMessage ? `: ${s.lastErrorMessage}` : ''}
        </p>
      )}
      {props.retained && <p className="panel__text panel__text--muted">{COPY.retainedSnapshot}</p>}
    </section>
  );
}

// Canary is the test-only stateful child. `hiddenPrivileged` renders it inert
// and hidden while reauthenticating: its RAM state is preserved across the
// boundary but privileged content is not shown until access is reconfirmed.
function Canary(props: {
  canary: CanaryState;
  onChange: (c: CanaryState) => void;
  hiddenPrivileged?: boolean;
  hiddenReason?: string;
}) {
  const { canary, onChange } = props;
  const [expanded, setExpanded] = useState(true);
  if (props.hiddenPrivileged) {
    return (
      <section className="canary canary--hidden" aria-label={COPY.canaryLabel} inert>
        <p className="panel__text panel__text--muted">
          {props.hiddenReason ?? COPY.reauthHeading}
        </p>
        {/* Hidden mirror inputs keep the values mounted (RAM) without exposing
            privileged content; they are inert and not focusable. */}
        <input type="hidden" value={canary.text} readOnly aria-hidden="true" />
        <input type="hidden" value={canary.secret} readOnly aria-hidden="true" />
      </section>
    );
  }
  return (
    <section className="panel" aria-labelledby="canary-heading">
      <div className="canary__head">
        <h2 className="panel__title" id="canary-heading">
          {COPY.canaryLabel}
        </h2>
        {canary.dirty && (
          <span className="flag" role="status">
            {COPY.dirtyFlag}
          </span>
        )}
        <button
          type="button"
          className="button button--ghost"
          onClick={() => setExpanded((v) => !v)}
          aria-expanded={expanded}
        >
          {expanded ? COPY.close : COPY.overview}
        </button>
      </div>
      {expanded && (
        <>
          <label className="field__label" htmlFor="canary-text">
            {COPY.canaryLabel}
          </label>
          <textarea
            id="canary-text"
            className="canary__area"
            value={canary.text}
            onChange={(e) => onChange({ ...canary, text: e.target.value, dirty: true })}
          />
          <label className="field__label" htmlFor="canary-secret">
            {COPY.canarySecretLabel}
          </label>
          <input
            id="canary-secret"
            type="password"
            value={canary.secret}
            onChange={(e) => onChange({ ...canary, secret: e.target.value, dirty: true })}
            autoComplete="off"
          />
          <p className="panel__text panel__text--muted">{COPY.canaryHelp}</p>
          <button
            type="button"
            className="button button--ghost"
            onClick={() => onChange(initialCanary())}
            disabled={!canary.dirty}
          >
            {COPY.discard}
          </button>
        </>
      )}
    </section>
  );
}
