// Raylane Web UI — root component.
//
// T002 scope: an inert placeholder. It states what the build is and what is
// not implemented yet, and nothing more. No API client, no routing, no
// product state, no privileged defaults.
//
// Design notes (docs/discovery/UI_UX_GUIDELINES.md, Apple Design skill):
// - one clear heading, plain language, no decorative motion;
// - status is carried by text, not by colour alone;
// - reduced motion is respected globally in styles.css.
export function App() {
  return (
    <main className="page">
      <header className="page__header">
        <h1 className="page__title">Raylane</h1>
        <p className="page__subtitle">Network panel — build scaffold</p>
      </header>

      <section className="panel" aria-labelledby="scaffold-heading">
        <h2 className="panel__title" id="scaffold-heading">
          This interface is not implemented yet
        </h2>
        <p className="panel__text">
          The build scaffold proves that the pinned toolchain compiles the UI.
          It contains no screens, no settings and no control of the network.
        </p>
        <p className="panel__text panel__text--muted">
          Saved, active and applied states are separate concepts in Raylane.
          Nothing in this placeholder applies, saves or inspects anything.
        </p>
      </section>
    </main>
  );
}
