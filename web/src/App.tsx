// Raylane Web UI — same-origin authentication + application shell.
//
// T009: one administrator signs in over the SAME trusted HTTPS origin and sees
// a truthful status panel. Session failure recovers IN PLACE (reauth) without
// losing still-open in-page state, and nothing is applied or persisted
// accidentally. There is NO node editor and NO fake production editor here.
//
// Design (cmw handoff + Apple Design skill): solid quiet surfaces, system
// font, visible focus, text not colour alone, reduced motion respected. No
// motion framework, no glass, no theme toggle.
//
// D5 (foundation): still-open consuming-child state must survive an auth
// boundary (401 / restart) without remount, and be discarded only on an
// EXPLICIT user decision — never autosaved, persisted or replayed. That
// behavior lives in the auth/state-owner boundary below. The stateful child
// that DEMONSTRATES it is a test-only fixture, compiled ONLY into the isolated
// test build (`VITE_TEST_CHILD`); the normal production bundle tree-shakes it
// out entirely, so ordinary production output has no fake notes/secret field.
import { useCallback, useEffect, useRef, useState } from 'react';

import {
  login,
  loginBody,
  logout,
  probeState,
  type LoginResult,
  type RuntimeReadiness,
  type RuntimeState,
} from './api';
import { TestChild } from './test-child';

// AuthView is the coarse authorization state. `unknown` means the transport
// or an unexpected response prevented a definitive read: we keep any retained
// snapshot and offer a read-only Retry, never auto-retry or sign out.
type AuthView = 'unknown' | 'signedOut' | 'signedIn' | 'reauth';

interface SessionFlags {
  pending: boolean;
}

// D5 dirty state: a consuming child signals it holds unsaved in-RAM work. In
// production there is no editor, so this stays inert; a test-only child sets
// it to exercise the dirty sign-out boundary. It is NEVER persisted.
interface DirtyState {
  dirty: boolean;
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
  rejected: 'The request was rejected. Check the connection and try again.',
  rateLimited: 'Too many attempts. Try again later.',
  retryAfter: (s: number) => `Too many attempts. Try again in ${s} seconds.`,
  unknownError: 'Something went wrong. Check the connection and try again.',
  // 403 on login/reauth is an Origin/CSRF rejection, NOT proof the session
  // expired; the copy is a neutral rejection + retry, never "reload" (which
  // would silently destroy retained in-page RAM) and never an assumed cause.
  reauthHeading: 'Sign in required',
  reauthBody: 'Your session is no longer valid. Sign in again to continue — your unsaved changes are still here.',
  overview: 'Overview',
  status: 'Status',
  savedDraft: 'Saved draft',
  activeConfig: 'Active configuration',
  activeGeneration: 'Active generation',
  validation: 'Validation',
  runtime: 'Runtime',
  readiness: 'Readiness',
  notReported: 'Not reported',
  unavailable: 'Unavailable',
  notRunning: 'Not running',
  signOut: 'Sign out',
  signOutRetry: 'Retry sign out',
  signOutFailed: 'Sign-out was not confirmed. Your session may still be active.',
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
  close: 'Close',
  // Credential length guidance is in CODEPOINTS (not UTF-16 units), matching
  // the wire contract: username 1–256, password 1–1024 codepoints, plus a
  // separate 4096-byte serialized-body bound enforced by the API.
  usernameTooLong: 'Username must be 1–256 characters.',
  passwordTooLong: 'Password must be 1–1024 characters.',
} as const;

const LOGIN_BODY_MAX_BYTES = 4096;

// serializedLoginBodyBytes measures the EXACT wire payload — the single JSON
// encoder shared with api.login(), so validation and transport can never
// disagree (the T008 single-encoder discipline: api.loginBody is THE encoder).
function serializedLoginBodyBytes(username: string, password: string): number {
  return new TextEncoder().encode(loginBody(username, password)).length;
}

// countCodepoints counts Unicode code points (not UTF-16 units), so astral
// characters count as one. This matches the server's codepoint bound and
// avoids the native maxLength UTF-16 truncation bug.
export function countCodepoints(s: string): number {
  let n = 0;
  for (const _ of s) n++;
  return n;
}

const USERNAME_MAX = 256;
const PASSWORD_MAX = 1024;

export function App() {
  const [auth, setAuth] = useState<AuthView>('unknown');
  const [state, setState] = useState<RuntimeState | null>(null);
  const [retained, setRetained] = useState(false);
  const [probeError, setProbeError] = useState(false);
  const [dirty, setDirty] = useState<DirtyState>({ dirty: false });
  // Sign-out confirmation while a child holds unsaved in-RAM work.
  const [confirmSignOut, setConfirmSignOut] = useState(false);
  // Sign-out reached the server but the result was uncertain (network/5xx):
  // the session may still be active, so we stay signed in and say so.
  const [signOutUncertain, setSignOutUncertain] = useState(false);
  const flags = useRef<SessionFlags>({ pending: false });
  // Monotonic token so a late probe/login/logout response can never overwrite
  // a newer auth state (stale-response protection).
  const generation = useRef(0);
  // The invoker that opened the dirty sign-out dialog, to restore focus on
  // cancel/close (APG: return focus to the invoking element).
  const signOutInvokerRef = useRef<HTMLButtonElement | null>(null);

  const refresh = useCallback(
    async (into: AuthView | 'auto' = 'auto') => {
      const myGen = ++generation.current;
      const result = await probeState();
      if (myGen !== generation.current) return; // stale response
      // Isolated-test observation seam (NO production behaviour): an E2E run
      // may stage one canned /state payload to exercise the presentation of
      // values the local runtime can never legally produce here (42, or a
      // MAX_SAFE_INTEGER generation, long distinct IDs). Applied to this one
      // in-flight response only; the wire contract and rendering rules below
      // are unchanged. Guarded by the same VITE_TEST_CHILD build flag as the
      // D5 test child, so the production bundle tree-shakes it out.
      if (import.meta.env.VITE_TEST_CHILD && result.kind === 'ok') {
        const w = window as unknown as {
          __raylaneStateTestHook?: ((s: RuntimeState) => RuntimeState | null) | undefined;
        };
        if (typeof w.__raylaneStateTestHook === 'function') {
          const staged = w.__raylaneStateTestHook(result.state);
          w.__raylaneStateTestHook = undefined;
          if (staged) {
            setAuth(into === 'reauth' || into === 'auto' ? 'signedIn' : into);
            setState(staged);
            setRetained(false);
            setProbeError(false);
            return;
          }
        }
      }
      if (result.kind === 'ok') {
        setAuth(into === 'reauth' || into === 'auto' ? 'signedIn' : into);
        setState(result.state);
        setRetained(false);
        setProbeError(false);
      } else if (result.kind === 'auth') {
        // 401 only: move to the reauth gate, preserving child state in RAM.
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
    if (dirty.dirty) {
      setConfirmSignOut(true);
      return;
    }
    void doSignOut();
    // eslint-disable-next-line @typescript-eslint/no-use-before-define
  }, [dirty.dirty]);

  const doSignOut = useCallback(async () => {
    if (flags.current.pending) return;
    flags.current.pending = true;
    const myGen = ++generation.current;
    const result = await logout();
    flags.current.pending = false;
    if (myGen !== generation.current) return; // stale: a newer auth action won
    if (result.kind === 'confirmed') {
      setConfirmSignOut(false);
      setSignOutUncertain(false);
      setDirty({ dirty: false });
      setState(null);
      setRetained(false);
      setAuth('signedOut');
    } else {
      // Network failure is NOT a confirmed revocation: stay signed in, keep
      // the child state, and surface a DISTINCT "not confirmed" message (not
      // a status-refresh error). No auto retry of the protected action.
      setConfirmSignOut(false);
      setSignOutUncertain(true);
    }
  }, []);

  const retrySignOut = useCallback(() => {
    setSignOutUncertain(false);
    void doSignOut();
  }, [doSignOut]);

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
            <button
              type="button"
              className="button button--ghost"
              onClick={requestSignOut}
              ref={signOutInvokerRef}
            >
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
          <LoginForm onLoggedIn={onLoggedIn} headingRef={mainRef} reauth />
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
              <button
                type="button"
                className="button button--ghost"
                onClick={() => void refresh('signedIn')}
              >
                {COPY.retry}
              </button>
            </p>
          )}
          {signOutUncertain && (
            <p className="banner" role="alert" data-testid="signout-failed">
              {COPY.signOutFailed}{' '}
              <button type="button" className="button button--ghost" data-testid="signout-retry" onClick={retrySignOut}>
                {COPY.signOutRetry}
              </button>
            </p>
          )}
          <StatusPanel state={state} retained={retained} onRefresh={() => void refresh('signedIn')} />
        </main>
      )}

      {/* D5 test-only stateful child. Rendered at ONE stable tree position (a
          direct child of .app) for BOTH signedIn and reauth, so the consuming
          child keeps its identity and its own useState across the auth boundary —
          no remount, no RAM loss. `gated` flips it inert/hidden while access is
          unconfirmed. Compiled out of the production bundle entirely. */}
      {(auth === 'signedIn' || auth === 'reauth') && (
        <TestChildBoundary dirty={dirty} onDirty={setDirty} gated={auth === 'reauth'} />
      )}

      {confirmSignOut && (
        <DirtySignOutDialog
          onStay={() => {
            setConfirmSignOut(false);
            signOutInvokerRef.current?.focus();
          }}
          onDiscardSignOut={() => void doSignOut()}
        />
      )}
    </div>
  );
}

// DirtySignOutDialog is the reusable dirty sign-out boundary. It is reachable
// in production only when a real consuming child holds unsaved work; there is
// no fake editor. It uses the NATIVE <dialog> shown with showModal(): the
// browser makes the ENTIRE rest of the document inert and AX-excluded (not
// focusable, not clickable, hidden from the accessibility tree), so neither
// pointer nor a controlled DOM.focus can reach the background — the F7
// defect. Escape fires `cancel` (= Stay, preserving RAM and returning focus
// to the invoker); initial focus lands on the safe action (Stay); native
// focus trapping keeps Tab/Shift+Tab contained.
function DirtySignOutDialog(props: { onStay: () => void; onDiscardSignOut: () => void }) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const stayRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const dlg = dialogRef.current;
    if (!dlg) return;
    // showModal() puts the dialog in the top layer and makes everything else
    // inert — the genuine modal boundary, enforced by the browser.
    dlg.showModal();
    // Initial focus on the safe action (Stay).
    stayRef.current?.focus();

    // Escape → cancel == Stay: keep in-RAM work, return focus to the invoker.
    // This runs BEFORE the dialog closes, so the background is still inert.
    const onCancel = (e: Event) => {
      e.preventDefault();
      props.onStay();
    };
    dlg.addEventListener('cancel', onCancel);
    return () => dlg.removeEventListener('cancel', onCancel);
  }, [props]);

  return (
    <dialog
      className="dialog"
      role="dialog"
      aria-modal="true"
      aria-labelledby="signout-title"
      ref={dialogRef}
      onClick={(e) => {
        // A click on the dialog's own backdrop (outside the panel) is Stay.
        if (e.target === dialogRef.current) props.onStay();
      }}
    >
      <div className="dialog__body">
        <h2 className="dialog__title" id="signout-title">
          {COPY.unsavedChanges}
        </h2>
        <p className="panel__text">Leaving will discard unsaved work that exists only in this page.</p>
        <div className="dialog__actions">
          <button type="button" className="button" onClick={props.onStay} ref={stayRef}>
            {COPY.stay}
          </button>
          <button type="button" className="button button--danger" onClick={props.onDiscardSignOut}>
            {COPY.discardSignOut}
          </button>
        </div>
      </div>
    </dialog>
  );
}

function LoginForm(props: {
  onLoggedIn: () => void;
  headingRef: React.RefObject<HTMLHeadingElement | null>;
  reauth?: boolean;
}) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  // Client-side codepoint validation, computed from the live values so a
  // pasted/inserted value is validated without being mutated.
  const usernameLen = countCodepoints(username);
  const passwordLen = countCodepoints(password);
  const usernameInvalid = username.length > 0 && (usernameLen < 1 || usernameLen > USERNAME_MAX);
  const passwordInvalid = password.length > 0 && (passwordLen < 1 || passwordLen > PASSWORD_MAX);
  const [submitError, setSubmitError] = useState<string | null>(null);
  // Which control the current submit error is the recovery context for, so the
  // error can be programmatically ASSOCIATED with that control (not just
  // announced once): a screen-reader user lands on the focused field and hears
  // the error via aria-describedby (the F6 residual — the visible role=alert
  // summary existed but had no association with the focused recovery target).
  const [errorFocus, setErrorFocus] = useState<'username' | 'password' | 'error' | null>(null);
  const [busy, setBusy] = useState(false);
  const local = useRef<SessionFlags>({ pending: false });
  // Refs for stable focus management: keep focus on the form across pending
  // and failure instead of letting it fall to <body>.
  const usernameRef = useRef<HTMLInputElement>(null);
  const passwordRef = useRef<HTMLInputElement>(null);
  const submitRef = useRef<HTMLButtonElement>(null);
  const errorRef = useRef<HTMLParagraphElement>(null);

  const fail = useCallback((msg: string, focus: 'username' | 'password' | 'error') => {
    setSubmitError(msg);
    setErrorFocus(focus);
    // Move focus deliberately so a screen reader user lands on the correction.
    requestAnimationFrame(() => {
      if (focus === 'username') usernameRef.current?.focus();
      else if (focus === 'password') passwordRef.current?.focus();
      else errorRef.current?.focus();
    });
  }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    // One POST per deliberate submit: guard duplicate Enter/click while busy.
    if (busy || local.current.pending) return;
    // Explicit codepoint validation BEFORE any request; input is never
    // truncated or mutated, only accepted or rejected with guidance.
    if (usernameLen < 1 || usernameLen > USERNAME_MAX) {
      fail(COPY.usernameTooLong, 'username');
      return;
    }
    if (passwordLen < 1 || passwordLen > PASSWORD_MAX) {
      fail(COPY.passwordTooLong, 'password');
      return;
    }
    // The SEPARATE 4096-byte serialized-body bound, checked client-side with
    // exactly the same JSON encoding that is sent (single-source rule from
    // T008: one encoder for validation and transport). The API enforces the
    // same limit independently; the client check exists so an over-bound
    // credential never leaves the browser and the fields stay intact.
    if (serializedLoginBodyBytes(username, password) > LOGIN_BODY_MAX_BYTES) {
      fail(COPY.tooLarge, 'error');
      return;
    }
    setSubmitError(null);
    setBusy(true);
    local.current.pending = true;
    // Keep focus stable on the submit control while pending (it stays enabled
    // for focus but guarded against duplicate submission).
    submitRef.current?.focus();
    const result: LoginResult = await login(username, password);
    local.current.pending = false;
    setBusy(false);
    switch (result.kind) {
      case 'ok':
        setPassword(''); // 204 clears the password; state is re-read by parent.
        props.onLoggedIn();
        return;
      case 'invalid':
        fail(COPY.genericAuthError, 'username');
        return;
      case 'tooLarge':
        fail(COPY.tooLarge, 'error');
        return;
      case 'csrf':
        fail(COPY.rejected, 'error');
        return;
      case 'rateLimited':
        fail(
          result.retryAfter ? COPY.retryAfter(result.retryAfter) : COPY.rateLimited,
          'error',
        );
        return;
      default:
        fail(COPY.unknownError, 'error');
    }
  };

  const errorId = 'login-error';

  return (
    <section className="panel panel--auth" aria-labelledby="login-heading">
      <h1 className="main__heading" id="login-heading" tabIndex={-1} ref={props.headingRef}>
        {props.reauth ? COPY.reauthHeading : COPY.signInHeading}
      </h1>
      {props.reauth && <p className="panel__text">{COPY.reauthBody}</p>}
      <form className="form" onSubmit={(e) => void submit(e)} noValidate>
        <div className="field">
          <label className="field__label" htmlFor="username">
            {COPY.username}
          </label>
          {/* No maxLength: it counts UTF-16 units and would silently truncate
              valid astral input. Codepoint bounds are validated on submit. */}
          <input
            id="username"
            name="username"
            type="text"
            autoComplete="username"
            required
            aria-invalid={usernameInvalid || (submitError !== null && errorFocus === 'username') || undefined}
            aria-describedby={
              [usernameInvalid || errorFocus === 'username' ? errorId : '',]
                .filter(Boolean)
                .join(' ') || undefined
            }
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            // Inputs are NOT natively disabled while pending — that is what
            // threw focus to <body> (the F6 defect). The submit() guard
            // enforces one POST; fields stay focusable and retain values.
            ref={usernameRef}
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
            aria-invalid={passwordInvalid || (submitError !== null && errorFocus === 'password') || undefined}
            aria-describedby={
              [passwordInvalid || errorFocus === 'password' ? errorId : '']
                .filter(Boolean)
                .join(' ') || undefined
            }
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            ref={passwordRef}
          />
        </div>
        {(usernameInvalid || passwordInvalid || submitError) && (
          <p
            className="field__error"
            role="alert"
            id={errorId}
            tabIndex={-1}
            ref={errorRef}
          >
            {submitError ??
              (usernameInvalid ? COPY.usernameTooLong : COPY.passwordTooLong)}
          </p>
        )}
        <button
          type="submit"
          className="button button--primary"
          // aria-disabled, NOT the native disabled attribute: native disabling
          // throws focus to <body> mid-submit (the F6 defect). aria-disabled
          // announces the busy state while focus stays on the control, and the
          // submit() guard below enforces one POST per deliberate submit.
          aria-disabled={busy || undefined}
          aria-busy={busy || undefined}
          ref={submitRef}
        >
          {busy ? COPY.signingIn : COPY.signIn}
        </button>
      </form>
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
      <div className="status__head">
        <h2 className="panel__title" id="status-heading">
          {COPY.status}
        </h2>
        {props.onRefresh && (
          <button
            type="button"
            className="button button--ghost"
            onClick={props.onRefresh}
            data-testid="status-refresh"
          >
            {COPY.retry}
          </button>
        )}
      </div>
      <dl className="status">
        <div className="status__row">
          <dt>{COPY.savedDraft}</dt>
          {/* A missing optional ID is "Not reported" (unknown), never a
              factual "No saved draft". */}
          <dd data-testid="status-draft">{s?.draftRevisionId ?? COPY.notReported}</dd>
        </div>
        <div className="status__row">
          <dt>{COPY.activeConfig}</dt>
          <dd data-testid="status-active">{s?.activeRevisionId ?? COPY.notReported}</dd>
        </div>
        <div className="status__row">
          <dt>{COPY.activeGeneration}</dt>
          {/* activeGeneration is an INTEGER when supplied (0 is meaningful).
              The CURRENT runtime truthfully reports no generation field, so
              the honest row value here is "Not reported" — the numeric 0/42/
              MAX_SAFE_INTEGER presentation is covered by the isolated
              presentation fixtures, NOT by a fabricated real-server claim. */}
          <dd data-testid="status-generation">{typeof s?.activeGeneration === 'number' ? s.activeGeneration : COPY.notReported}</dd>
        </div>
        <div className="status__row">
          <dt>{COPY.validation}</dt>
          {/* This endpoint supplies NO validation report: status is honestly
              "Unavailable", never an assumed "has not run" history. */}
          <dd>{COPY.unavailable}</dd>
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

// TestChildBoundary is the D5 test-only stateful child, compiled ONLY into the
// isolated test build. With `gated` (during reauth) it renders inert + hidden
// so its in-RAM state is preserved without exposing privileged content. In
// the normal production bundle (VITE_TEST_CHILD unset) it is tree-shaken to
// nothing — production output has no fake editor, notes field or secret echo.
function TestChildBoundary(props: {
  dirty: DirtyState;
  onDirty: (d: DirtyState) => void;
  gated?: boolean;
}) {
  if (!import.meta.env.VITE_TEST_CHILD) return null;
  return <TestChild {...props} />;
}
