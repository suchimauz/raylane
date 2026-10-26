/// <reference types="vite/client" />

// Build-time flags. VITE_TEST_CHILD is set ONLY by the isolated D5 test build
// (`npm --prefix web run build:test`); the normal production build leaves it
// unset so the test-only child is tree-shaken out of the production bundle.
interface ImportMetaEnv {
  readonly VITE_TEST_CHILD?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
