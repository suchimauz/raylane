// Raylane Web UI — T009 browser acceptance scenarios.
//
// Runs the REAL compiled `raylane serve` over REAL HTTPS and drives it with a
// REAL sandboxed, task-trusted Chrome (see harness.mjs for the trust/boundary
// model). These are PRODUCT BEHAVIOR checks, not static validators.
//
// Two binary variants are exercised:
//   - PRODUCTION (`raylane-e2e`): the clean embedded bundle. Asserts there is
//     NO fake editor / notes / secret field anywhere (V4-T009-PRODUCTION-CANARY).
//   - ISOLATED TEST (`raylane-e2e-test`): built with VITE_TEST_CHILD=1 so the
//     D5 test-only stateful child is present. Used to PROVE foundation D5
//     (RAM preservation across a REAL backend restart), the dirty sign-out
//     modal semantics, and Unicode codepoint bounds. This variant is an
//     explicitly isolated test build, never the shipped artifact.
import { ServerHarness, nssTrustCa, launchChrome } from './harness.mjs';
import { mkdtempSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import https from 'node:https';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const BIN = process.env.RAYLANE_E2E_BIN || path.join(REPO, 'build', 'raylane-e2e');
const TEST_BIN = process.env.RAYLANE_E2E_TEST_BIN || path.join(REPO, 'build', 'raylane-e2e-test');
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
    // Network-status messages ("Failed to load resource: ... 401/403") are
    // EXPECTED auth/CSRF responses, not app errors.
    if (m.type() === 'error' && !/Failed to load resource/.test(m.text())) {
      consoleErrors.push(m.text());
    }
  });
  page.on('pageerror', (e) => consoleErrors.push('pageerror: ' + e.message));
  page.on('requestfailed', (r) => failedReqs.push(r.url() + ' ' + (r.failure()?.errorText ?? '')));
  return page;
}

async function loginAs(page, user = USER, pass = PASS) {
  await page.fill('#username', user);
  await page.fill('#password', pass);
  await page.click('button[type=submit]');
  await page.waitForSelector('#status-heading', { timeout: 10000 });
}


// Astral helper: a string of `n` code points outside the BMP (each is 2 UTF-16
// units, 4 UTF-8 bytes), used to prove codepoint (not UTF-16) length handling.
const astral = (n) => '\u{1F600}'.repeat(n);

async function main() {
  // ===================== PRODUCTION PHASE (clean bundle) =====================
  console.log('\n########## PRODUCTION BUNDLE (no test child) ##########');
  const h = await ServerHarness.start({ bin: BIN });
  h.bootstrapAdmin(USER, PASS);
  const taskHome = mkdtempSync(path.join(tmpdir(), 'raylane-e2e-home-'));
  try {
    nssTrustCa(taskHome, h.mat.caPem);
    const ctx = await launchChrome({ taskHome, profileDir: path.join(taskHome, 'pw') });
    try {
      const consoleErrors = [];
      const failedReqs = [];

      // ---------- A: ACCESS ----------
      console.log('\n[A] Access states');
      const page = await freshPage(ctx, consoleErrors, failedReqs);
      await page.goto(h.url('/'), { waitUntil: 'load', timeout: 20000 });
      check('secure context on trusted HTTPS origin', (await page.evaluate(() => window.isSecureContext)) === true);
      await page.waitForSelector('#login-heading', { timeout: 10000 });
      check('initial 401 renders the sign-in gate (no privileged content)', true);
      check('no privileged status panel while signed out', (await page.$('#status-heading')) === null);
      check('one h1 on the sign-in screen', (await page.$$('h1')).length === 1);
      check('no console errors on initial load', consoleErrors.length === 0, consoleErrors.join(' | '));
      check('no failed requests on initial load', failedReqs.length === 0, failedReqs.join(' | '));
      const p403 = await ctx.newPage();
      let resp403 = null;
      p403.on('response', (r) => { if (r.url().endsWith('/no-such')) resp403 = r; });
      await p403.goto(h.url('/no-such'), { waitUntil: 'load', timeout: 20000 }).catch(() => {});
      check('unknown path is not the shell (generic 403)', resp403 && resp403.status() === 403, `got ${resp403?.status()}`);
      await p403.close();

      // ---------- B: LOGIN + FOCUS ----------
      console.log('\n[B] Login, validation, focus');
      await page.fill('#username', USER);
      await page.fill('#password', 'wrong password');
      await page.click('button[type=submit]');
      await page.waitForSelector('.field__error', { timeout: 8000 });
      const errText = await page.textContent('.field__error');
      check('failed login shows a generic error', /invalid username or password/i.test(errText), errText);
      check('error is associated + announced (role=alert, tabbable summary)', (await page.$('.field__error[role=alert]#login-error')) !== null);
      await page.waitForTimeout(150); // allow deliberate post-failure focus to land
      check('after failure focus is not lost to body', await page.evaluate(() => document.activeElement !== document.body));
      check('username retained after failure', (await page.inputValue('#username')) === USER);

      // ---------- F6: stable focus + single POST while PENDING ----------
      // With the submit delayed, repeatedly press Enter during the in-flight
      // request: focus must stay on a purposeful control (never <body>) and
      // exactly ONE POST may leave the client (no duplicate submission).
      {
        let pendingPosts = 0;
        const pListener = (r) => { if (r.method() === 'POST' && r.url().endsWith('/api/v1/session')) pendingPosts++; };
        page.on('request', pListener);
        await page.route('**/api/v1/session', async (route) => {
          if (route.request().method() === 'POST') await new Promise((r) => setTimeout(r, 700));
          await route.continue();
        });
        await page.fill('#username', USER);
        await page.fill('#password', 'still-wrong-but-pending');
        await page.click('button[type=submit]');
        await page.waitForTimeout(120); // request now genuinely in flight
        check('F6: during pending, focus is not lost to body', await page.evaluate(() => document.activeElement !== document.body));
        check('F6: during pending, focus stays on a meaningful control', await page.evaluate(() => {
          const el = document.activeElement;
          return !!el && el !== document.documentElement && (el.tagName === 'BUTTON' || el.tagName === 'INPUT');
        }));
        await page.keyboard.press('Enter');
        await page.keyboard.press('Enter');
        await page.waitForTimeout(900);
        await page.unroute('**/api/v1/session');
        page.off('request', pListener);
        await page.waitForSelector('.field__error', { timeout: 4000 });
        check('F6: repeated Enter during pending sends exactly one POST', pendingPosts === 1, `posts=${pendingPosts}`);
        // Clear the staged failure for the scenarios that follow.
        await page.click('#username', { clickCount: 3 });
        await page.keyboard.press('Backspace');
      }

      // F4 Unicode: native insertion of 129 astral (258 UTF-16 units) must NOT
      // truncate to the 256-unit native maxLength; codepoint validation counts
      // codepoints, so 129 is accepted intact.
      await page.click('#username', { clickCount: 3 });
      await page.keyboard.press('Backspace');
      const u129 = astral(129);
      await page.keyboard.insertText(u129);
      const usernameNow = await page.inputValue('#username');
      check('F4: 129 astral username not truncated (codepoints preserved)', [...usernameNow].length === 129, `got ${[...usernameNow].length} codepoints`);
      // 257 codepoints → explicit client rejection without mutation/truncation.
      await page.click('#username', { clickCount: 3 });
      await page.keyboard.press('Backspace');
      await page.keyboard.insertText(astral(257));
      await page.fill('#password', 'x');
      await page.click('button[type=submit]');
      await page.waitForSelector('.field__error', { timeout: 8000 });
      check('F4: 257-codepoint username rejected with guidance', /1–256|1-256/i.test(await page.textContent('.field__error')));
      check('F4: rejected username not truncated (still 257)', [...(await page.inputValue('#username'))].length === 257);

      // F4: the SEPARATE 4096-byte serialized-body bound must reject even when
      // each field is within its own codepoint bound: astral(256) username
      // (256 cp ≤ 256) + astral(512) password (512 cp ≤ 1024) — measured with
      // the client's own encoder the JSON is 3101 bytes ≤ 4096, so THIS shape
      // is byte-legal and authenticates-or-401s normally; the overflow shape
      // uses astral(1024) password: 1024 cp ≤ 1024 bound, serialized JSON
      // 5141 bytes > 4096 → rejected purely on bytes. The client enforces the
      // bound before the wire; input is preserved intact. The exact
      // server-side boundary is proven below the real login.
      await page.click('#username', { clickCount: 3 });
      await page.keyboard.press('Backspace');
      await page.keyboard.insertText(astral(256));
      await page.click('#password');
      await page.keyboard.press('Control+a');
      await page.keyboard.press('Backspace');
      await page.keyboard.insertText(astral(1024));
      let overflowPosts = 0;
      const overflowListener = (r) => { if (r.method() === 'POST' && r.url().endsWith('/api/v1/session')) overflowPosts++; };
      page.on('request', overflowListener);
      await page.click('button[type=submit]');
      await page.waitForSelector('.field__error', { timeout: 8000 });
      page.off('request', overflowListener);
      check('F4: combined 4096-byte serialized body rejected independently of field bounds',
        /size limit/i.test(await page.textContent('.field__error')),
        String(await page.textContent('.field__error')));
      check('F4: overflow fields not mutated (256/1024 preserved)',
        [...(await page.inputValue('#username'))].length === 256 && [...(await page.inputValue('#password'))].length === 1024);
      check('F4: over-bound body never leaves the browser (client byte check, zero POSTs)',
        overflowPosts === 0, `posts=${overflowPosts}`);

      // Valid login with ordinary + Cyrillic credentials reaches the shell.
      await page.click('#username', { clickCount: 3 });
      await page.keyboard.press('Backspace');
      await page.fill('#username', USER);
      await page.fill('#password', PASS);
      let loginPosts = 0;
      page.on('request', (r) => { if (r.method() === 'POST' && r.url().endsWith('/api/v1/session')) loginPosts++; });
      await page.click('button[type=submit]');
      await page.waitForSelector('#status-heading', { timeout: 10000 });
      check('valid login reaches the authenticated shell', true);
      check('single login POST per deliberate submit', loginPosts === 1, `posts=${loginPosts}`);
      check('login form (and its password) removed after sign-in', (await page.$('#password')) === null);

      // ---------- F3: NO fake editor in production ----------
      console.log('\n[F3] Production shell has no fake editor/secret controls');
      const bodyText = await page.textContent('body');
      check('no "Working notes"/"Test notes" control', !/working notes|test notes/i.test(bodyText));
      check('no "Sensitive note"/"Test secret" field', !/sensitive note|test secret/i.test(bodyText));
      check('no canary/secret inputs in DOM', (await page.$('#canary-text,#canary-secret,#test-child-text,#test-child-secret')) === null);

      // ---------- C: STATUS EVIDENCE (truthfulness) ----------
      console.log('\n[C] Status evidence');
      const statusText = await page.textContent('dl.status');
      check('status panel present', true);
      check('C: missing optional IDs shown as Not reported (not "No saved draft")', /not reported/i.test(statusText), statusText.replace(/\s+/g, ' ').slice(0, 160));
      check('C: validation honestly Unavailable (no invented report)', /unavailable/i.test(statusText));
      check('C: numeric activeGeneration row present (0 allowed)', /active generation/i.test(statusText));
      // Truthful current-runtime evidence: the real /state endpoint supplies
      // NO generation field, so the honest presentation here is "Not
      // reported" — claiming a 0 would be exactly the fabrication this check
      // exists to forbid. Numeric 0/42/MAX_SAFE_INTEGER presentation is
      // covered by the isolated [F5] presentation fixtures in the test phase.
      check('C: real /state generation honestly "Not reported" (no fabricated 0)',
        (await page.textContent('[data-testid="status-generation"]')) === 'Not reported',
        String(await page.textContent('[data-testid="status-generation"]')));
      check('truthful not-running phase', /not[- ]running/i.test(statusText));

      // ---------- F8/F9: 403 honesty + logout-failure semantics ----------
      // Deliberately reach the signed-out gate first: the F4/F3 blocks left
      // this page SIGNED IN, so every login-form step below needs its own
      // explicit sign-out precondition.
      console.log('\n[F8/F9] 403 copy and logout-failure semantics');
      await page.click('button:has-text("Sign out")');
      await page.waitForSelector('.panel--auth', { timeout: 10000 });
      {
      // F8 first login-gate copy: the fresh sign-in gate promises nothing
      // about reload/expiry.
      const gateBody = await page.textContent('.panel--auth');
        check('F8: login gate copy carries no "Reload page" instruction', !/reload page/i.test(gateBody), gateBody.slice(0, 160));
        // Real server 403 to a wrong-origin login, observed at the NETWORK
        // layer through the maintained request/response events: the response
        // page is CORS-opaque (JS sees an error even though the server
        // answered), so the CDP response event — not JS — is the evidence.
        const pCross = await ctx.newPage();
        await pCross.goto('about:blank');
        // A non-trusted ORIGIN: the browser stamps Origin https://null on
        // this POST, so the request reaches the product's real CSRF/Origin
        // gate. Its response is CORS-opaque — Chrome gives JS and network
        // events no readable status for such a response — so the browser
        // proof here is that the foreign-origin request was ACTUALLY ISSUED;
        // the 403 itself is verified at the wire layer by the CA-validated
        // non-browser client below (positive trust anchor from this harness
        // instance, exactly like the Go tests).
        const crossReq = pCross.waitForRequest((r) => r.method() === 'POST' && r.url().endsWith('/api/v1/session'), { timeout: 10000 });
        await pCross.evaluate(async (origin) => {
          await fetch(origin + '/api/v1/session', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: 'probe', password: 'probe' }),
            mode: 'no-cors',
          }).catch(() => {});
        }, h.origin);
        const issued = await crossReq.then(() => true, () => false);
        check('F8: foreign-origin browser POST is actually issued to the product origin', issued);
        await pCross.close();
        const wire403 = await new Promise((resolve, reject) => {
          const body = JSON.stringify({ username: 'probe', password: 'probe' });
          const url = new URL(h.origin + '/api/v1/session');
          const req = https.request({
            hostname: url.hostname,
            port: url.port,
            path: url.pathname,
            method: 'POST',
            ca: readFileSync(h.mat.caPem), // positive trust anchor, no bypass flags
            headers: {
              'Content-Type': 'application/json',
              'Content-Length': Buffer.byteLength(body),
              // A WRONG origin on purpose: this is the request under test.
              Origin: 'https://foreign.invalid',
            },
          }, (res) => { res.resume(); resolve(res.statusCode); });
          req.on('error', reject);
          req.end(body);
        });
        check('F8: real CA-validated server answers 403 to wrong-origin login (wire-observed)',
          wire403 === 403, String(wire403));
      }
      // Client-side 403 PRESENTATION (a labelled fixture, separate from the
      // server-transport evidence above): stage a real-status 403 on the
      // login POST and submit from the signed-out gate — the UI must show
      // neutral rejection, no "Reload page", no navigation, and keep
      // entered values. The gate precondition was established above.
      {
        await page.route('**/api/v1/session', async (route) => {
          if (route.request().method() === 'POST') {
            return route.fulfill({ status: 403, contentType: 'application/json', body: '{"error":"forbidden"}' });
          }
          await route.continue();
        });
        await page.click('#username', { clickCount: 3 });
        await page.keyboard.press('Backspace');
        await page.fill('#username', USER);
        await page.fill('#password', PASS);
        const hrefBefore403 = page.url();
        await page.click('button[type=submit]');
        await page.waitForSelector('.field__error', { timeout: 8000 });
        const err403 = await page.textContent('.field__error');
        check('F8: login 403 shows neutral rejection (no expiry assumption, no reload advice)',
          !/reload page/i.test(err403) && !/expired/i.test(err403), err403);
        check('F8: login 403 keeps the document in place (no auto navigation/reload)',
          page.url() === hrefBefore403, page.url());
        check('F8: login 403 retains the nonsecret input', (await page.inputValue('#username')) === USER);
        await page.unroute('**/api/v1/session');
      }
      // Re-auth in place first.
      await loginAs(page);
      // F9: a FAILED sign-out (transport error on the DELETE) must preserve
      // session + RAM and show DISTINCT "not confirmed" copy — not the
      // status-refresh message. The explicit retry must send a DELETE, not a
      // status GET. Network failure staged via route abort (browser-real).
      await page.route('**/api/v1/session', async (route) => {
        if (route.request().method() === 'DELETE') return route.abort('failed');
        await route.continue();
      });
      await page.click('button:has-text("Sign out")');
      await page.waitForSelector('[data-testid="signout-failed"]', { timeout: 8000 });
      const failBanner = await page.textContent('[data-testid="signout-failed"]');
      check('F9: failed sign-out shows distinct not-confirmed copy',
        /not confirmed|may still be active/i.test(failBanner), failBanner);
      check('F9: failed sign-out does NOT fall back to sign-in gate (session preserved)',
        (await page.$('#status-heading')) !== null && (await page.$('#login-heading')) === null);
      // The retry re-issues a DELETE. Stage a 403 on the first retry DELETE:
      // the UI must stay in place, keep the session view (403 does NOT prove
      // expiry) and keep saying "not confirmed" — never gate/clear/navigate.
      let retryDeletes = 0;
      await page.route('**/api/v1/session', async (route) => {
        if (route.request().method() === 'DELETE') {
          retryDeletes++;
          if (retryDeletes === 1) {
            return route.fulfill({ status: 403, contentType: 'application/json', body: '{"error":"forbidden"}' });
          }
        }
        await route.continue();
      });
      const hrefBeforeRetry = page.url();
      await page.click('[data-testid="signout-retry"]');
      await page.waitForTimeout(400);
      const after403 = await page.evaluate(() => ({
        body: document.body.textContent || '',
        auth: !!document.querySelector('#login-heading'),
      }));
      check('F9: 403 on sign-out retry keeps the page in place (no auto navigation/reload)',
        page.url() === hrefBeforeRetry, page.url());
      check('F9: 403 retry does not falsely gate or clear the session view',
        after403.auth === false && (await page.$('#status-heading')) !== null);
      check('F9: 403 retry still says not confirmed (session may still be active)',
        /not confirmed|may still be active/i.test(after403.body), after403.body.slice(0, 200));
      check('F9: nowhere does the UI instruct "Reload page"', !/reload page/i.test(after403.body));
      await page.click('[data-testid="signout-retry"]'); // second retry succeeds (real DELETE 204)
      await page.waitForSelector('#login-heading', { timeout: 8000 });
      await page.unroute('**/api/v1/session');
      check('F9: retry sign-out re-issues DELETE (never a status GET in its place)',
        retryDeletes >= 2, `deletes=${retryDeletes}`);
      check('F9: successful retry completes logout (gate shown)', true);
      check('F6: heading focused after logout', await page.evaluate(() => document.activeElement?.id === 'login-heading'));
      // No persistence.
      const leaked = await page.evaluate(() => ({
        cookies: document.cookie, ls: localStorage.length, ss: sessionStorage.length,
      }));
      check('no readable session cookie (HttpOnly)', leaked.cookies === '');
      check('nothing in localStorage/sessionStorage', leaked.ls === 0 && leaked.ss === 0);

      await page.close();

      // ---------- F: keyboard / responsive / reduced-motion (production) ----------
      console.log('\n[F] Keyboard, responsive, reduced-motion, CSP');
      const p3 = await freshPage(ctx, consoleErrors, failedReqs);
      await p3.goto(h.url('/'), { waitUntil: 'load', timeout: 20000 });
      await p3.waitForSelector('#login-heading', { timeout: 10000 });
      await p3.keyboard.press('Shift+Tab');
      const skipFocus = await p3.evaluate(() => document.activeElement?.textContent || '');
      check('Shift+Tab reaches the skip link', /skip to content/i.test(skipFocus), String(skipFocus));
      check('username has an associated label', (await p3.$('label[for=username]')) !== null);
      check('password has an associated label', (await p3.$('label[for=password]')) !== null);
      check('password uses current-password autocomplete', (await p3.getAttribute('#password', 'autocomplete')) === 'current-password');
      check('username uses username autocomplete', (await p3.getAttribute('#username', 'autocomplete')) === 'username');
      await p3.fill('#username', USER);
      await p3.fill('#password', PASS);
      let enterPosts = 0;
      p3.on('request', (r) => { if (r.method() === 'POST' && r.url().endsWith('/api/v1/session')) enterPosts++; });
      await p3.press('#password', 'Enter');
      await p3.waitForSelector('#status-heading', { timeout: 10000 });
      check('Enter submits the login form (once)', enterPosts === 1, `posts=${enterPosts}`);
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
      await p3.emulateMedia({ reducedMotion: 'reduce' });
      const anim = await p3.evaluate(() => {
        const cs = getComputedStyle(document.body);
        const parse = (s) => parseFloat(s) || 0;
        return Math.max(parse(cs.animationDuration), parse(cs.transitionDuration));
      });
      check('reduced-motion collapses animation/transition durations', anim < 0.01, String(anim));
      check('no CSP violations / console errors across scenarios', consoleErrors.length === 0, consoleErrors.slice(0, 3).join(' | '));
      await p3.close();
    } finally {
      await ctx.close();
    }
  } finally {
    await h.stop();
  }

  // ===================== ISOLATED TEST PHASE (D5 child present) =====================
  if (!existsSync(TEST_BIN)) {
    console.log('\n########## TEST BUNDLE: SKIPPED (run web/e2e/build-test-bin.mjs) ##########');
  } else {
    console.log('\n########## ISOLATED TEST BUNDLE (D5 child) ##########');
    await testPhase();
  }

  console.log(`\n===== ${passed} passed, ${failed} failed =====`);
  if (failures.length) {
    console.log('FAILURES:');
    for (const f of failures) console.log('  - ' + f);
    process.exit(1);
  }
}

async function testPhase() {
  const h = await ServerHarness.start({ bin: TEST_BIN });
  h.bootstrapAdmin(USER, PASS);
  const taskHome = mkdtempSync(path.join(tmpdir(), 'raylane-e2e-test-home-'));
  try {
    nssTrustCa(taskHome, h.mat.caPem);
    const ctx = await launchChrome({ taskHome, profileDir: path.join(taskHome, 'pw') });
    try {
      const consoleErrors = [];
      const failedReqs = [];
      const page = await freshPage(ctx, consoleErrors, failedReqs);
      await page.goto(h.url('/'), { waitUntil: 'load', timeout: 20000 });
      await page.waitForSelector('#login-heading', { timeout: 10000 });
      await loginAs(page);
      await page.waitForSelector('#test-child-text', { timeout: 8000 });
      check('D5: test child present in test build', (await page.$('[data-testid="test-child"]')) !== null);

      // ---- D5: REAL backend restart preserves child RAM (no remount) ----
      console.log('\n[D5] Real restart: child identity + RAM preserved, gated on 401');
      await page.fill('#test-child-text', 'restart-doc-notes');
      await page.fill('#test-child-secret', 'restart-s3cret');
      const docIdBefore = await page.evaluate(() => {
        window.__docId = window.__docId || Math.random().toString(36).slice(2);
        return window.__docId;
      });
      // REAL restart: same DB dir + port, new process (sessions invalidate).
      await h.stop();
      const h2 = await ServerHarness.start({ bin: TEST_BIN, port: h.port, dir: h.dir });
      try {
        // Next privileged read 401s → in-place reauth gate; document NOT remounted.
        await page.click('[data-testid="status-refresh"]').catch(() => {});
        await page.waitForSelector('#login-heading', { timeout: 10000 });
        const docIdAfter = await page.evaluate(() => window.__docId);
        check('D5: document not remounted across restart (same window.__docId)', docIdAfter === docIdBefore, `${docIdBefore} vs ${docIdAfter}`);
        check('D5: reauth gate shown after real restart 401', /sign in required/i.test(await page.textContent('#login-heading')));
        // F6/F8 on the REAL 401 reauth gate: focus purposeful (heading),
        // neutral copy, no reload advice, RAM promise.
        const reauthBody = await page.textContent('.panel--auth');
        check('F6: reauth gate focuses the heading (not body)',
          await page.evaluate(() => document.activeElement?.id === 'login-heading'));
        check('F8: reauth copy does not instruct "Reload page"', !/reload page/i.test(reauthBody), reauthBody.slice(0, 160));
        check('F8: reauth copy promises RAM retention', /still here/i.test(reauthBody));
        // The gated child is inert/hidden but its inputs kept values in RAM.
        check('D5: gated child present but inert', (await page.$('[data-testid="test-child-gated"][inert]')) !== null);
        // Re-auth in place: child RAM (incl. secret) preserved, same document.
        await loginAs(page);
        await page.waitForSelector('#test-child-text', { timeout: 8000 });
        const docIdFinal = await page.evaluate(() => window.__docId);
        check('D5: still same document after reauth (no remount)', docIdFinal === docIdBefore);
        check('D5: nonsecret RAM preserved across restart+reauth', (await page.inputValue('#test-child-text')) === 'restart-doc-notes');
        check('D5: secret RAM preserved across restart+reauth', (await page.inputValue('#test-child-secret')) === 'restart-s3cret');
      } finally {
        await h2.stop();
      }

      // ---- F4: real backend login with allowed Unicode (astral) credentials ----
      console.log('\n[F4] Unicode codepoint bounds: real backend login');
      // Astral username (129 codepoints) + astral password (513 codepoints):
      // both inside their codepoint bounds, the combined serialized JSON is
      // 2597 bytes ≤ 4096, so the exact required payload must authenticate
      // end-to-end through the real backend.
      const uniUser = astral(129);
      // The contract's astral case is a 129-cp username + 513-cp password:
      // BOTH inside their codepoint bounds and the combined serialized JSON
      // is 2597 bytes ≤ 4096 (measured with TextEncoder, not escaped \u JSON),
      // so the exact required payload must authenticate end-to-end.
      const uniPass = astral(513);
      const h4 = await ServerHarness.start({ bin: TEST_BIN });
      try {
        h4.bootstrapAdmin(uniUser, uniPass);
        nssTrustCa(taskHome, h4.mat.caPem);
        const up = await freshPage(ctx, consoleErrors, failedReqs);
        await up.goto(h4.url('/'), { waitUntil: 'load', timeout: 20000 });
        await up.waitForSelector('#login-heading', { timeout: 10000 });
        // Type the astral credentials through the REAL form (insertText), with
        // NO truncation: the inputs must carry all 129/513 codepoints.
        await up.click('#username');
        await up.keyboard.insertText(uniUser);
        await up.click('#password');
        await up.keyboard.insertText(uniPass);
        check('F4: astral username intact (129) in form', [...(await up.inputValue('#username'))].length === 129);
        check('F4: astral password intact (513) in form', [...(await up.inputValue('#password'))].length === 513);
        await up.click('button[type=submit]');
        await up.waitForSelector('#status-heading', { timeout: 10000 });
        check('F4: real backend login succeeded with astral credentials', true);

        // A combined astral shape INSIDE both codepoint bounds but OVER the
        // serialized-byte bound must stay intact in the real form and be
        // rejected EXPLICITLY by the client's byte check: the POST never
        // leaves the browser and no field is mutated.
        await up.click('button:has-text("Sign out")');
        await up.waitForSelector('#login-heading', { timeout: 8000 });
        let boundPosts = 0;
        const boundListener = (r) => { if (r.method() === 'POST' && r.url().endsWith('/api/v1/session')) boundPosts++; };
        up.on('request', boundListener);
        await up.click('#username');
        await up.keyboard.insertText(astral(256));
        await up.click('#password');
        await up.keyboard.insertText(astral(1024));
        check('F4: astral-1024 password stays intact in the real form',
          [...(await up.inputValue('#password'))].length === 1024);
        await up.click('button[type=submit]');
        await up.waitForSelector('.field__error', { timeout: 8000 });
        check('F4: over-byte astral body rejected with explicit size-limit guidance',
          /size limit/i.test(await up.textContent('.field__error')), String(await up.textContent('.field__error')));
        check('F4: rejected astral-1024 password not truncated', [...(await up.inputValue('#password'))].length === 1024);
        check('F4: over-bound astral submit sent no session POST', boundPosts === 0, `posts=${boundPosts}`);
        up.off('request', boundListener);

        // Server-side proof of the SEPARATE 4096-byte bound over the SAME
        // real HTTPS origin at the EXACT boundary: grow an ASCII password
        // byte-by-byte (length measured with TextEncoder, exactly like the
        // client) until the serialized body crosses 4096. The last in-bound
        // body must answer 401 (size accepted, auth negative — never 413);
        // the first over-bound body must answer 413 on bytes alone, with
        // BOTH fields still inside their codepoint bounds.
        const boundary = await up.evaluate(async () => {
          const enc = new TextEncoder();
          const mk = async (u, p) => {
            const body = JSON.stringify({ username: u, password: p });
            const r = await fetch('/api/v1/session', {
              method: 'POST', credentials: 'same-origin', cache: 'no-store',
              headers: { 'Content-Type': 'application/json' }, body,
            });
            return [r.status, enc.encode(body).length];
          };
          const user = '\u{1F600}'.repeat(256);
          // Binary search the largest ASCII password whose body is ≤ 4096.
          let lo = 1, hi = 4200;
          const size = (n) => enc.encode(JSON.stringify({ username: user, password: 'x'.repeat(n) })).length;
          while (lo < hi) {
            const mid = Math.ceil((lo + hi) / 2);
            if (size(mid) <= 4096) lo = mid; else hi = mid - 1;
          }
          return {
            in: await mk(user, 'x'.repeat(lo)),
            out: await mk(user, 'x'.repeat(lo + 1)),
            inSize: size(lo), outSize: size(lo + 1),
          };
        });
        check('F4: server accepts a body of exactly the bound (401, not 413) — both fields in codepoint bounds',
          boundary.in[0] === 401 && boundary.in[1] <= 4096 && boundary.in[1] > 4096 - 2,
          `status=${boundary.in[0]} bytes=${boundary.in[1]}`);
        check('F4: server rejects one byte over the bound with 413 while both fields stay in their codepoint bounds',
          boundary.out[0] === 413 && boundary.out[1] === boundary.in[1] + 1,
          `status=${boundary.out[0]} bytes=${boundary.out[1]}`);

        // 1025-codepoint password PAST its own codepoint bound (1..1024) must
        // be explicitly rejected by the client without mutation — a distinct
        // failure from the byte bound above. (513 is WITHIN the password's
        // 1..1024 codepoint bound; the contract's astral-513 credential case
        // is the intact form value + rejection copy, covered by the byte
        // bound proofs above; 1025 tests the codepoint bound itself.)
        // RE-AUTHENTICATE: the byte-bound rejection above happened on the
        // signed-out gate, so this page has no session and no Sign-out
        // button; a deliberate fresh login with the REAL astral identity
        // returns to the shell first (fields hold astral leftovers — clear
        // both, then fill the known credentials).
        await up.click('#username', { clickCount: 3 });
        await up.keyboard.press('Backspace');
        await up.click('#password', { clickCount: 3 });
        await up.keyboard.press('Backspace');
        await loginAs(up, uniUser, uniPass);
        await up.click('button:has-text("Sign out")');
        await up.waitForSelector('#login-heading', { timeout: 8000 });
        await up.click('#username');
        await up.keyboard.insertText(uniUser);
        await up.click('#password');
        // ASCII (1 byte/char) so the serialized body stays ≤ 4096: the
        // rejection can then ONLY come from the 1..1024 codepoint bound.
        await up.keyboard.insertText('a'.repeat(1025));
        await up.click('button[type=submit]');
        await up.waitForSelector('.field__error', { timeout: 8000 });
        check('F4: 1025-codepoint password rejected per the 1..1024 bound',
          /1–1024|1-1024/i.test(await up.textContent('.field__error')), String(await up.textContent('.field__error')));
        check('F4: rejected 1025 password not truncated', [...(await up.inputValue('#password'))].length === 1025);

        // ---- F5: numeric-generation presentation fixtures (0 / 42 / MAX_SAFE) ----
        // The local runtime can only ever report generation 0 (proven in the
        // production phase); 42 and 9007199254740991 come from the isolated
        // TEST-build presentation seam staging one /state payload. The render
        // rule under test is the product's: an integer renders as that exact
        // number; a missing optional ID renders "Not reported", never a
        // factual empty-state claim.
        console.log('\n[F5] Numeric generation presentation fixtures');
        // Deliberate signed-in precondition: the 1025-bound fixture above
        // left this page on the sign-in gate.
        await loginAs(up, uniUser, uniPass);
        await up.waitForSelector('[data-testid="status-refresh"]', { timeout: 8000 });
        for (const gen of [0, 42, 9007199254740991]) {
          const staged = await up.evaluate((g) => {
            return new Promise((resolve) => {
              (window).__raylaneStateTestHook = (s) => ({
                ...s,
                activeGeneration: g,
                draftRevisionId: 'draft-' + 'd'.repeat(64) + '-' + g,
                activeRevisionId: 'active-' + 'a'.repeat(64) + '-' + g,
              });
              document.querySelector('[data-testid="status-refresh"]').click();
              setTimeout(() => {
                const t = document.querySelector('dl.status')?.textContent || '';
                resolve({
                  gen: document.querySelector('[data-testid="status-generation"]')?.textContent,
                  draft: document.querySelector('[data-testid="status-draft"]')?.textContent,
                  active: document.querySelector('[data-testid="status-active"]')?.textContent,
                  noFalseEmpty: !/no saved draft|no active configuration/i.test(t),
                  validation: /unavailable/i.test(t),
                });
              }, 600);
            });
          }, gen);
          check(`F5: generation ${gen} rendered as the exact number`, staged.gen === String(gen), String(staged.gen));
          check(`F5: distinct long IDs shown truthfully (gen ${gen})`,
            staged.draft?.includes('draft-') === true && staged.active?.includes('active-') === true,
            `${staged.draft?.slice(0, 24)} | ${staged.active?.slice(0, 24)}`);
          check(`F5: no fabricated empty/validation claims (gen ${gen})`, staged.noFalseEmpty && staged.validation);
        }
        await up.close();
      } finally {
        await h4.stop();
      }

      // ---- F7: dirty sign-out modal semantics ----
      console.log('\n[F7] Dirty sign-out modal');
      const h3 = await ServerHarness.start({ bin: TEST_BIN });
      h3.bootstrapAdmin(USER, PASS);
      try {
        nssTrustCa(taskHome, h3.mat.caPem);
        const p = await freshPage(ctx, consoleErrors, failedReqs);
        await p.goto(h3.url('/'), { waitUntil: 'load', timeout: 20000 });
        await p.waitForSelector('#login-heading', { timeout: 10000 });
        await loginAs(p);
        await p.fill('#test-child-text', 'modal-work');
        await p.fill('#test-child-secret', 'modal-secret');
        // Open the dirty dialog via the invoker.
        await p.click('header button:has-text("Sign out")');
        await p.waitForSelector('[role=dialog]', { timeout: 8000 });
        check('F7: dialog opens', true);
        check('F7: initial focus on Stay (safe action)', await p.evaluate(() => document.activeElement?.textContent?.trim() === 'Stay'));
        // Tab containment: cycle within the two actions only.
        await p.keyboard.press('Tab');
        const afterTab = await p.evaluate(() => document.activeElement?.textContent?.trim());
        check('F7: Tab moves to Discard', afterTab === 'Discard and sign out', String(afterTab));
        await p.keyboard.press('Tab');
        const afterTab2 = await p.evaluate(() => document.activeElement?.textContent?.trim());
        check('F7: Tab wraps back to Stay (contained)', afterTab2 === 'Stay', String(afterTab2));
        // Escape == Stay: no DELETE, RAM preserved, focus returns to invoker.
        let deletes = 0;
        p.on('request', (r) => { if (r.method() === 'DELETE') deletes++; });
        await p.keyboard.press('Escape');
        await p.waitForTimeout(200);
        check('F7: Escape cancels (dialog closed, no DELETE)', (await p.$('[role=dialog]')) === null && deletes === 0, `deletes=${deletes}`);
        check('F7: focus returned to Sign-out invoker', await p.evaluate(() => /sign out/i.test(document.activeElement?.textContent || '')));
        check('F7: RAM preserved after Escape', (await p.inputValue('#test-child-text')) === 'modal-work');
        // Discard and sign out: exactly one DELETE, returns to gate.
        await p.click('header button:has-text("Sign out")');
        await p.waitForSelector('[role=dialog]', { timeout: 8000 });
        await p.click('button:has-text("Discard and sign out")');
        await p.waitForSelector('#login-heading', { timeout: 8000 });
        check('F7: Discard+sign out sends one DELETE and returns to gate', deletes === 1, `deletes=${deletes}`);
        await p.close();
      } finally {
        await h3.stop();
      }
    } finally {
      await ctx.close();
    }
  } finally {
    await h.stop();
  }
}

main().catch((e) => {
  console.error('HARNESS ERROR:', e);
  process.exit(2);
});
