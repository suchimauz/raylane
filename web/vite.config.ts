// Raylane Web UI — Vite build configuration.
//
// T002 scope: build scaffold only. The dev server binds to the loopback
// interface and the production build is a static bundle. No product
// behaviour, no API client, no privileged defaults.
//
// @vitejs/plugin-react is intentionally NOT used: its 6.x line requires
// optional peers (oxc-transform-react, @rolldown/plugin-babel,
// babel-plugin-react-compiler) whose compatibility with the pinned Vite 8.3.5
// is recorded as UNVERIFIED in packaging/versions.lock §3. Vite's built-in
// esbuild/rolldown JSX transform handles this scaffold without adding an
// unverified peer dependency.
import { defineConfig } from 'vite';

export default defineConfig({
  // Relative base so the built bundle can be served from any prefix.
  base: './',
  build: {
    // Deterministic, self-contained output; no external CDN references.
    outDir: 'dist',
    assetsDir: 'assets',
    sourcemap: false,
    target: 'es2022',
  },
  server: {
    // Loopback only: the dev server must never be reachable from the LAN.
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
  },
  preview: {
    host: '127.0.0.1',
    port: 4173,
    strictPort: true,
  },
});
