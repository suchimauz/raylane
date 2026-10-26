// Builds BOTH raylane binaries for the E2E run, in an order that keeps each
// embed correct:
//   1. clean production dist -> production binary (embeds the clean bundle);
//   2. isolated test dist (VITE_TEST_CHILD=1) -> test binary (embeds it);
//   3. rebuild the clean production dist so the repo's web/dist always ends as
//      the production artifact (never the test bundle).
// The browser suite drives the REAL compiled processes over REAL HTTPS.
import { execFileSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const OUT = path.join(REPO, 'build');
mkdirSync(OUT, { recursive: true });
const prod = path.join(OUT, process.platform === 'win32' ? 'raylane-e2e.exe' : 'raylane-e2e');
const test = path.join(OUT, process.platform === 'win32' ? 'raylane-e2e-test.exe' : 'raylane-e2e-test');

function run(cmd, args) {
  execFileSync(cmd, args, { cwd: REPO, stdio: 'inherit' });
}

try {
  // 1. production dist + binary.
  run('npm', ['--prefix', 'web', 'run', 'build']);
  run('go', ['build', '-o', prod, './cmd/raylane']);
  console.log('built', prod);
  // 2. isolated test dist + binary.
  run('npm', ['--prefix', 'web', 'run', 'build:test']);
  run('go', ['build', '-o', test, './cmd/raylane']);
  console.log('built', test);
  // 3. restore the clean production dist as the repo's final artifact state.
  run('npm', ['--prefix', 'web', 'run', 'build']);
} catch {
  console.error('E2E binary build failed');
  process.exit(1);
}
