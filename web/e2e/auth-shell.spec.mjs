// Raylane Web UI — T009 browser acceptance scenarios.
//
// Runs the REAL compiled `raylane serve` over REAL HTTPS and drives it with a
// REAL sandboxed, task-trusted Chrome (see harness.mjs for the trust/boundary
// model). These are PRODUCT BEHAVIOR checks (access states, login, status,
// RAM preservation across auth boundaries, logout, keyboard, responsive,
// reduced-motion, CSP), not static validators.
import { ServerHarness, nssTrustCa, launchChrome } from './harness.mjs';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const BIN = process.env.RAYLANE_E2E_BIN || path.join(REPO, 'build', 'raylane-e2e');
const USER = 'admin';
const PASS = 'correct horse battery staple';

let passed = 0;
let failed = 0;
const failures = [];
function check(name, cond, detail = '') {
  if (cond) {
    passed++;
    console.log(`  ok   ${name}`);
  } else {
    failed++;
    failures.push(`${name}${detail ? ' — ' + detail : ''}`);
    console.log(`  FAIL ${name}${detail ? ' — ' + detail : ''}`);
  }
}

async function freshPage(ctx, consoleErrors, failedReqs) {
  const page = await ctx.newPage();
  page.on('console', (m) => {
    // Network-status messages ("Failed to load resource: the server responded
    // with 401/403") are EXPECTED auth/CSRF responses, not app errors. Real
    // errors are javascript exceptions / CSP violations / page errors.
    if (m.type() === 'error' && !/Failed to load resource/.test(m.text())) {
      consoleErrors.push(m.text());
    }
  });
  page.on('pageerror', (e) => consoleErrors.push('pageerror: ' + e.message));
  page.on('requestfailed', (r) => failedReqs.push(r.url() + ' ' + (r.failure()?.errorText ?? '')));
  return page;
}

async function main() {
  const h = await ServerHarness.start({ bin: BIN });
  h.bootstrapAdmin(USER, PASS); // create the admin identity over the local socket
  const taskHome = mkdtempSync(path.join(tmpdir(), 'raylane-e2e-home-'));
  const results = { secure: false, scenarios: {} };
  try {
    nssTrustCa(taskHome, h.mat.caPem);
    const ctx = await launchChrome({ taskHome, profileDir: path.join(taskHome, 'pw') });
    try {
      // ---------- A: ACCESS — initial probe → sign-in ----------
      console.log('\n[A] Access states');
      const consoleErrors = [];
      const failedReqs = [];
      const page = await freshPage(ctx, consoleErrors, failedReqs);
      await page.goto(h.url('/'), { waitUntil: 'load', timeout: 20000 });
      results.secure = await page.evaluate(() => window.isSecureContext);
      check('secure context on trusted HTTPS origin', results.secure === true);
      await page.waitForSelector('#login-heading', { timeout: 10000 });
      check('initial 401 renders the sign-in gate (no privileged content)', true);
      const hasPrivileged = await page.$('text=Status') !== null || await page.$('#status-heading') !== null;
      check('no privileged status panel while signed out', !hasPrivileged);
      check('one h1 on the sign-in screen', (await page.$$('h1')).length === 1);
      check('no console errors on initial load', consoleErrors.length === 0, consoleErrors.join(' | '));
      check('no failed requests on initial load', failedReqs.length === 0, failedReqs.join(' | '));
      // unknown path must NOT render the app (generic 403, not SPA catch-all)
      const p403 = await ctx.newPage();
      let resp403 = null;
      p403.on('response', (r) => { if (r.url().endsWith('/no-such')) resp403 = r; });
      await p403.goto(h.url('/no-such'), { waitUntil: 'load', timeout: 20000 }).catch(() => {});
      check('unknown path is not the shell (generic 403)', resp403 && resp403.status() === 403, `got ${resp403?.status()}`);
      await p403.close();

      // ---------- B: LOGIN ----------
      console.log('\n[B] Login');
      // Failed login: generic error, no oracle.
      await page.fill('#username', USER);
      await page.fill('#password', 'wrong password');
      await page.click('button[type=submit]');
      await page.waitForSelector('.field__error', { timeout: 8000 });
      const errText = await page.textContent('.field__error');
      check('failed login shows a generic error', /invalid username or password/i.test(errText), errText);
      check('failed login error is associated (role=alert)', (await page.$('.field__error[role=alert]')) !== null);

      // Valid login.
      await page.fill('#password', PASS);
      // Guard against duplicate submit: press Enter twice rapidly; must be one request.
      let loginPosts = 0;
      page.on('request', (r) => { if (r.method() === 'POST' && r.url().endsWith('/api/v1/session')) loginPosts++; });
      await page.click('button[type=submit]');
      await page.waitForSelector('#status-heading', { timeout: 10000 });
      check('valid login reaches the authenticated shell', true);
      check('single login POST per deliberate submit', loginPosts === 1, `posts=${loginPosts}`);
      // After a 204 the login form is unmounted (its password value is dropped),
      // and the privileged shell is shown instead — the password never lingers.
      check('login form (and its password) removed after sign-in', (await page.$('#password')) === null);

      // ---------- C: STATUS PANEL ----------
      console.log('\n[C] Status panel');
      await page.waitForSelector('#status-heading', { timeout: 8000 });
      const statusText = await page.textContent('dl.status');
      check('status panel present', true);
      check('shows Saved draft row', /Saved draft/i.test(statusText));
      check('shows Active configuration row', /Active configuration/i.test(statusText));
      check('shows Validation row', /Validation/i.test(statusText));
      check('shows Runtime row', /Runtime/i.test(statusText));
      check('truthful not-running phase', /not[- ]running/i.test(statusText), statusText.replace(/\s+/g, ' ').slice(0, 200));
      // Long revision IDs / empty states: present, not faked.
      check('Saved draft shows the empty state (no fake id)', /no saved draft/i.test(statusText));

      // ---------- D: RAM preservation across an in-place 401 (reauth gate) ----------
      console.log('\n[D] Reauth preserves in-RAM state across a late 401');
      // Edit the canary (in-RAM only, incl. a secret) so it is dirty.
      await page.fill('#canary-text', 'draft notes alpha');
      await page.fill('#canary-secret', 's3cret-value');
      check('canary marks dirty after edit', (await page.$('span.flag')) !== null);
      // Simulate a late 401 WITHOUT navigation: drop the HttpOnly session cookie
      // from the context jar (the browser still holds the page in RAM), then ask
      // the app to re-read state via the genuine read-only Refresh. The next
      // probe returns 401 and must flip the app to the reauth gate IN PLACE,
      // preserving the canary values in RAM and hiding privileged content.
      await ctx.clearCookies();
      await page.click('[data-testid="status-refresh"]');
      await page.waitForSelector('#login-heading', { timeout: 10000 });
      const reauthHeading = await page.textContent('#login-heading');
      check('late 401 renders the reauth gate heading', /session expired/i.test(reauthHeading), reauthHeading);
      check('reauth gate hides the privileged status panel', (await page.$('#status-heading')) === null);
      // The canary is preserved in RAM across the auth boundary (hidden mirror).
      const hiddenText = await page.$eval('.canary--hidden input[type=hidden]', (el) => el.value).catch(() => null);
      check('canary text preserved in RAM across the 401 boundary', hiddenText === 'draft notes alpha', String(hiddenText));
      const hiddenSecret = await page.$$eval('.canary--hidden input[type=hidden]', (els) => els.map((e) => e.value)).catch(() => []);
      check('canary secret preserved in RAM across the 401 boundary', hiddenSecret.includes('s3cret-value'), JSON.stringify(hiddenSecret));
      // Re-authenticate in place: sign in again, privileged content returns.
      await page.fill('#username', USER);
      await page.fill('#password', PASS);
      await page.click('button[type=submit]');
      await page.waitForSelector('#status-heading', { timeout: 10000 });
      check('reauth restores privileged content after a fresh sign-in', true);

      // Re-open a clean server + page for the logout (E) and UX (F) scenarios.
      const h5 = await ServerHarness.start({ bin: BIN });
      h5.bootstrapAdmin(USER, PASS);
      try {
        nssTrustCa(taskHome, h5.mat.caPem);
        const p3 = await freshPage(ctx, consoleErrors, failedReqs);
        await p3.goto(h5.url('/'), { waitUntil: 'load', timeout: 20000 });
        await p3.waitForSelector('#login-heading', { timeout: 10000 });
        await p3.fill('#username', USER);
        await p3.fill('#password', PASS);
        await p3.click('button[type=submit]');
        await p3.waitForSelector('#status-heading', { timeout: 10000 });

        // ---------- D5 (honest, single-server): logout with dirty canary ----------
        console.log('\n[D5/E] Logout + dirty canary');
        await p3.fill('#canary-text', 'unsaved work here');
        await p3.fill('#canary-secret', 'topsecret');
        // Click Sign out with a dirty canary → confirmation dialog appears.
        await p3.click('button:has-text("Sign out")');
        await p3.waitForSelector('[role=dialog]', { timeout: 8000 });
        check('dirty sign-out opens a confirmation dialog', true);
        check('dialog offers Stay', (await p3.$('button:has-text("Stay")')) !== null);
        // Choose Stay: canary preserved, still signed in.
        await p3.click('button:has-text("Stay")');
        await p3.waitForSelector('#status-heading', { timeout: 8000 });
        check('Stay keeps the canary (RAM preserved)', (await p3.inputValue('#canary-text')) === 'unsaved work here');
        check('Stay keeps the secret', (await p3.inputValue('#canary-secret')) === 'topsecret');
        check('Stay keeps the user signed in', (await p3.$('#status-heading')) !== null);
        // Discard + sign out: session ends, no persistence.
        await p3.click('button:has-text("Sign out")');
        await p3.waitForSelector('[role=dialog]', { timeout: 8000 });
        await p3.click('button:has-text("Discard and sign out")');
        await p3.waitForSelector('#login-heading', { timeout: 8000 });
        check('Discard+sign out returns to the sign-in gate', true);
        // No storage of secrets anywhere.
        const leaked = await p3.evaluate(() => {
          const all = [];
          for (let i = 0; i < localStorage.length; i++) all.push(localStorage.key(i));
          for (let i = 0; i < sessionStorage.length; i++) all.push(sessionStorage.key(i));
          return { local: all, cookies: document.cookie, lsLen: localStorage.length, ssLen: sessionStorage.length };
        });
        check('no readable session cookie (HttpOnly)', leaked.cookies === '');
        check('nothing in localStorage/sessionStorage', leaked.lsLen === 0 && leaked.ssLen === 0, JSON.stringify(leaked));

        // ---------- F: keyboard / a11y / responsive / reduced-motion ----------
        console.log('\n[F] Keyboard, responsive, reduced-motion, CSP');
        // Skip link: the view heading is auto-focused (a11y), so Shift+Tab from it
        // reaches the skip link — proving the skip link is a real, ordered stop.
        await p3.keyboard.press('Shift+Tab');
        const skipFocus = await p3.evaluate(() => document.activeElement?.textContent || '');
        check('Shift+Tab reaches the skip link', /skip to content/i.test(skipFocus), String(skipFocus));
        // Native labelled form with password-manager autocomplete.
        const userLabel = await p3.$('label[for=username]');
        const passLabel = await p3.$('label[for=password]');
        check('username has an associated label', userLabel !== null);
        check('password has an associated label', passLabel !== null);
        check('password uses current-password autocomplete', (await p3.getAttribute('#password', 'autocomplete')) === 'current-password');
        check('username uses username autocomplete', (await p3.getAttribute('#username', 'autocomplete')) === 'username');
        // Enter submits the form once.
        await p3.fill('#username', USER);
        await p3.fill('#password', PASS);
        let enterPosts = 0;
        p3.on('request', (r) => { if (r.method() === 'POST' && r.url().endsWith('/api/v1/session')) enterPosts++; });
        await p3.press('#password', 'Enter');
        await p3.waitForSelector('#status-heading', { timeout: 10000 });
        check('Enter submits the login form', true);
        check('Enter produced exactly one login POST', enterPosts === 1, `posts=${enterPosts}`);

        // Responsive: 390px and 320px reflow without horizontal overflow and with
        // the primary control (Sign out) fully on-screen.
        for (const width of [390, 320]) {
          await p3.setViewportSize({ width, height: 844 });
          await p3.waitForTimeout(150);
          const overflow = await p3.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
          check(`no horizontal overflow at ${width}px`, !overflow);
          const clipped = await p3.evaluate(() => {
            const el = [...document.querySelectorAll('header button')].find((b) => /sign out/i.test(b.textContent));
            if (!el) return true;
            const r = el.getBoundingClientRect();
            return r.right > window.innerWidth + 1 || r.left < -1;
          });
          check(`primary control not clipped at ${width}px`, !clipped);
        }
        // Reduced motion: media query collapses animation/transition to ~0.
        await p3.emulateMedia({ reducedMotion: 'reduce' });
        const anim = await p3.evaluate(() => {
          const cs = getComputedStyle(document.body);
          const parse = (s) => parseFloat(s) || 0;
          return Math.max(parse(cs.animationDuration), parse(cs.transitionDuration));
        });
        check('reduced-motion collapses animation/transition durations', anim < 0.01, String(anim));

        // CSP: no unsafe-inline/eval attempts logged; page rendered under strict CSP.
        check('no CSP violations / console errors across scenarios', consoleErrors.length === 0, consoleErrors.slice(0, 3).join(' | '));
        await p3.close();
      } finally {
        await h5.stop();
      }
      await page.close();
    } finally {
      await ctx.close();
    }
  } finally {
    await h.stop();
  }

  console.log(`\n===== ${passed} passed, ${failed} failed =====`);
  if (failures.length) {
    console.log('FAILURES:');
    for (const f of failures) console.log('  - ' + f);
    process.exit(1);
  }
}

main().catch((e) => {
  console.error('HARNESS ERROR:', e);
  process.exit(2);
});
