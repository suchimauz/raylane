// TestChild is the D5 test-only stateful child. It is imported ONLY by the
// `TestChildBoundary` in App.tsx, which returns null unless the build set
// `VITE_TEST_CHILD` — so the normal production bundle tree-shakes this entire
// module out and ships no fake editor, notes field or secret echo.
//
// It exists to PROVE the foundation D5 boundary with the real compiled shell
// and a real backend restart: a consuming child's nonsecret + secret in-RAM
// state survives an auth boundary (401/restart) without remount, is gated
// (inert/hidden) while access is unconfirmed, and is discarded only on an
// EXPLICIT user decision. Nothing here is persisted, autosaved or replayed.
import { useState } from 'react';

interface DirtyState {
  dirty: boolean;
}

export function TestChild(props: {
  dirty: DirtyState;
  onDirty: (d: DirtyState) => void;
  gated?: boolean;
}) {
  const [text, setText] = useState('');
  const [secret, setSecret] = useState('');
  const [expanded, setExpanded] = useState(true);

  // While reauthenticating the child stays MOUNTED (so its RAM state survives)
  // but is inert and hidden: privileged content is not shown until access is
  // reconfirmed. No hidden DOM copies of the secret — the real inputs keep
  // their values in React state without being rendered into the gated tree.
  if (props.gated) {
    return (
      <section
        className="canary canary--hidden"
        aria-label="Test child (gated)"
        data-testid="test-child-gated"
        inert
      >
        <p className="panel__text panel__text--muted">Sign in required</p>
      </section>
    );
  }

  return (
    <section className="panel" aria-labelledby="test-child-heading" data-testid="test-child">
      <div className="status__head">
        <h2 className="panel__title" id="test-child-heading">
          Test child (in-memory only)
        </h2>
        {props.dirty.dirty && (
          <span className="flag" role="status">
            Unsaved changes present
          </span>
        )}
        <button
          type="button"
          className="button button--ghost"
          onClick={() => setExpanded((v) => !v)}
          aria-expanded={expanded}
        >
          {expanded ? 'Close' : 'Open'}
        </button>
      </div>
      {expanded && (
        <>
          <label className="field__label" htmlFor="test-child-text">
            Test notes (in-memory only)
          </label>
          <textarea
            id="test-child-text"
            className="canary__area"
            value={text}
            onChange={(e) => {
              setText(e.target.value);
              props.onDirty({ dirty: true });
            }}
          />
          <label className="field__label" htmlFor="test-child-secret">
            Test secret (in-memory only)
          </label>
          <input
            id="test-child-secret"
            type="password"
            value={secret}
            onChange={(e) => {
              setSecret(e.target.value);
              props.onDirty({ dirty: true });
            }}
            autoComplete="off"
          />
          <p className="panel__text panel__text--muted">
            Kept only in this page’s memory. Leaving or refreshing discards it.
          </p>
          <button
            type="button"
            className="button button--ghost"
            onClick={() => {
              setText('');
              setSecret('');
              props.onDirty({ dirty: false });
            }}
            disabled={!props.dirty.dirty}
          >
            Discard
          </button>
        </>
      )}
    </section>
  );
}
