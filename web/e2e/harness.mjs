// Raylane Web UI — browser acceptance harness (T009).
//
// Drives the REAL compiled `raylane serve` process over REAL HTTPS on its own
// loopback port, with a REAL sandboxed Chrome (Playwright 1.64.1, Chrome for
// Testing 156) that trusts a per-run synthetic lab CA through a TASK-OWNED NSS
// database (scoped trust only — never the real ~/.pki, never system trust,
// never the shared browser profile, never --ignore-certificate-errors, never
// --no-sandbox, never ignoreHTTPSErrors).
//
// Boundary (per the isolated-trust research intake):
//   - fresh lab CA per run, under private scratch (dir 0700 / keys 0600);
//   - HOME is a task-owned dir; the CA is added to $HOME/.pki/nssdb (NSS sql:)
//     with certutil -A -t "C,," — the ONLY scoped mechanism Chrome honours;
//   - chromiumSandbox: true and ignoreHTTPSErrors: false are set EXPLICITLY
//     (Playwright otherwise injects --no-sandbox);
//   - the shared raylane-chrome service / real profile / system trust are
//     never touched; own processes/ports are stopped at the end.
import { execFileSync, spawn, execSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
// certutil (libnss3-tools) is NOT installed system-wide and we never install it
// with root. The harness obtains it WITHOUT root by `apt-get download
// libnss3-tools` + `dpkg-deb -x` on first use, caching it under the gitignored
// build/ dir (dir 0700). NSS is the only scoped-trust mechanism Chrome honours
// and certutil is the maintained tool (see the isolated-HTTPS-trust research).
const CERTUTIL_CACHE = path.join(REPO, 'build', 'e2e-tools', 'certutil');
function ensureCertutil() {
  if (existsSync(CERTUTIL_CACHE)) return CERTUTIL_CACHE;
  const dir = path.dirname(CERTUTIL_CACHE);
  mkdirSync(dir, { recursive: true });
  chmodSync(dir, 0o700);
  const tmp = mkdtempSync(path.join(tmpdir(), 'raylane-certutil-'));
  try {
    execSync('apt-get download libnss3-tools', { cwd: tmp, stdio: 'ignore' });
    const deb = execSync('ls ' + JSON.stringify(tmp) + '/*.deb', { encoding: 'utf8' }).trim().split('\n')[0];
    execSync('dpkg-deb -x ' + JSON.stringify(deb) + ' ' + JSON.stringify(path.join(tmp, 'x')), { stdio: 'ignore' });
    const bin = path.join(tmp, 'x', 'usr', 'bin', 'certutil');
    execSync('cp ' + JSON.stringify(bin) + ' ' + JSON.stringify(CERTUTIL_CACHE), { stdio: 'ignore' });
    chmodSync(CERTUTIL_CACHE, 0o700);
  } finally {
    try {
      rmSync(tmp, { recursive: true, force: true });
    } catch {}
  }
  if (!existsSync(CERTUTIL_CACHE)) {
    throw new Error('could not obtain certutil (libnss3-tools) without root');
  }
  return CERTUTIL_CACHE;
}
// Chrome for Testing 156 (Playwright chromium-1248) — the same build the
// sandbox research used. Override with RAYLANE_E2E_CHROME for other layouts.
const CHROME =
  process.env.RAYLANE_E2E_CHROME ||
  path.join(
    process.env.HOME || '/home/suchimauz',
    '.cache/ms-playwright/chromium-1248/chrome-linux64/chrome',
  );

export function sha256(s) {
  return createHash('sha256').update(s).digest('hex');
}

// freePort returns an own loopback port for this run.
export function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => {
      const p = s.address().port;
      s.close(() => resolve(p));
    });
    s.on('error', reject);
  });
}

function run(cmd, args, opts = {}) {
  return execFileSync(cmd, args, {
    encoding: 'utf8',
    stdio: [opts.input ? 'pipe' : 'ignore', 'pipe', 'pipe'],
    input: opts.input,
    ...opts,
  });
}

// makeLabMaterial creates a fresh per-run CA + a server certificate for
// 127.0.0.1/localhost, all under `dir` (0700, keys 0600). Nothing is promoted
// to any real trust store.
export function makeLabMaterial(dir) {
  mkdirSync(dir, { recursive: true });
  chmodSync(dir, 0o700);
  const caKey = path.join(dir, 'ca.key');
  const caPem = path.join(dir, 'ca.pem');
  const srvKey = path.join(dir, 'srv.key');
  const srvCsr = path.join(dir, 'srv.csr');
  const srvPem = path.join(dir, 'srv.pem');
  const srvExt = path.join(dir, 'srv.ext');
  for (const f of [caKey, srvKey]) writeFileSync(f, '', { mode: 0o600 });

  run('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', caKey, '-out', caPem,
    '-days', '1', '-subj', '/CN=raylane-e2e-lab-ca', '-addext', 'basicConstraints=critical,CA:TRUE',
    '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
  ]);
  chmodSync(caKey, 0o600);
  writeFileSync(
    srvExt,
    'subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n',
  );
  run('openssl', ['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', srvKey, '-out', srvCsr, '-subj', '/CN=localhost']);
  chmodSync(srvKey, 0o600);
  run('openssl', ['x509', '-req', '-in', srvCsr, '-CA', caPem, '-CAkey', caKey, '-CAcreateserial', '-out', srvPem, '-days', '1', '-extfile', srvExt]);
  return { caPem, caKey, srvPem, srvKey };
}

// nssTrustCa adds the lab CA as a trusted SSL CA into a task-owned NSS sql
// database at $HOME/.pki/nssdb for the given task HOME. Returns the env to use
// when launching the browser.
export function nssTrustCa(taskHome, caPem) {
  const certutil = ensureCertutil();
  const nssdb = path.join(taskHome, '.pki', 'nssdb');
  mkdirSync(nssdb, { recursive: true });
  // Create the DB if absent, then add the CA as a trusted CA for SSL ("C,,").
  try {
    run(certutil, ['-N', '--empty-password', '-d', `sql:${nssdb}`]);
  } catch {
    /* DB already initialised */
  }
  run(certutil, ['-A', '-t', 'C,,', '-n', 'raylane-e2e-lab-ca', '-d', `sql:${nssdb}`, '-i', caPem]);
  return { ...process.env, HOME: taskHome };
}

// ServerHarness starts the real raylane binary over HTTPS with the lab
// certificate, on an own loopback port, with its own state DB and socket dir.
export class ServerHarness {
  constructor() {
    this.proc = null;
  }
  static async start({ bin }) {
    const h = new ServerHarness();
    h.binPath = bin;
    const scratch = mkdtempSync(path.join(tmpdir(), 'raylane-e2e-'));
    chmodSync(scratch, 0o700);
    h.scratch = scratch;
    h.dir = path.join(scratch, 'srv');
    mkdirSync(h.dir, { recursive: true });
    const mat = makeLabMaterial(path.join(h.dir, 'tls'));
    h.mat = mat;
    h.port = await freePort();
    h.sockDir = path.join(h.dir, 'run');
    mkdirSync(h.sockDir, { recursive: true });
    h.dbPath = path.join(h.dir, 'state.db');
    h.cfgPath = path.join(h.dir, 'config.json');
    h.origin = `https://127.0.0.1:${h.port}`;
    writeFileSync(
      h.cfgPath,
      JSON.stringify({
        db: h.dbPath,
        listen: `127.0.0.1:${h.port}`,
        origin: h.origin,
        socketDir: h.sockDir,
        tlsCert: mat.srvPem,
        tlsKey: mat.srvKey,
      }),
    );
    h.proc = spawn(bin, ['serve', '--config', h.cfgPath], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env },
    });
    h.stdout = '';
    h.stderr = '';
    h.proc.stdout.on('data', (d) => (h.stdout += d));
    h.proc.stderr.on('data', (d) => (h.stderr += d));
    await h.waitReady();
    return h;
  }
  // bootstrapAdmin creates the admin identity for this server instance.
  bootstrapAdmin(username, password) {
    return this.bootstrap(JSON.stringify({ username, password }));
  }
  async waitReady() {
    const deadline = Date.now() + 20000;
    while (!this.stdout.includes('raylane: management')) {
      if (this.code !== undefined) throw new Error(`serve exited early code=${this.code}: ${this.stderr}`);
      if (Date.now() > deadline) throw new Error(`serve not ready: ${this.stdout} ${this.stderr}`);
      await new Promise((r) => setTimeout(r, 20));
    }
  }
  url(p) {
    return this.origin + p;
  }
  // bootstrap creates the admin identity over the local control socket with
  // credentials on stdin (never argv/env). Mirrors the Go harness.
  bootstrap(creds) {
    const out = run(this.binPath || this.bin, ['bootstrap', '--socket-dir', this.sockDir], {
      input: creds,
    });
    return out;
  }
  async stop() {
    if (this.proc && this.code === undefined) {
      try {
        this.proc.kill('SIGTERM');
      } catch {}
      const deadline = Date.now() + 8000;
      while (this.code === undefined && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 20));
      }
      if (this.code === undefined) {
        try {
          this.proc.kill('SIGKILL');
        } catch {}
      }
    }
  }
}

export function buildServer(harness) {
  harness.proc.on('exit', (c) => (harness.code = c));
  return harness;
}

// launchChrome starts the sandboxed, task-trusted Chrome and returns
// { browser, context } via a persistent context rooted in a task-owned profile.
export async function launchChrome({ taskHome, profileDir }) {
  const { chromium } = await import('playwright');
  mkdirSync(profileDir, { recursive: true });
  const context = await chromium.launchPersistentContext(profileDir, {
    headless: true,
    chromiumSandbox: true, // explicit — Playwright otherwise injects --no-sandbox
    ignoreHTTPSErrors: false, // explicit — never a certificate bypass
    executablePath: CHROME,
    env: { ...process.env, HOME: taskHome },
    args: ['--disable-dev-shm-usage'],
  });
  return context;
}

export function cleanup(paths) {
  for (const p of paths) {
    try {
      rmSync(p, { recursive: true, force: true });
    } catch {}
  }
}

export { CHROME, REPO };
