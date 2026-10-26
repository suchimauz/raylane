// Builds the raylane binary with the embedded frontend bundle for the E2E run.
// The browser suite drives the REAL compiled process over REAL HTTPS, so the
// binary must embed the just-built web/dist (the go:embed enforces this).
import { execFileSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const OUT = path.join(REPO, 'build');
mkdirSync(OUT, { recursive: true });
const bin = path.join(OUT, process.platform === 'win32' ? 'raylane-e2e.exe' : 'raylane-e2e');

try {
  execFileSync('go', ['build', '-o', bin, './cmd/raylane'], {
    cwd: REPO,
    stdio: 'inherit',
  });
  console.log('built', bin);
} catch (e) {
  console.error('go build failed — is the Go toolchain on PATH?');
  process.exit(1);
}
