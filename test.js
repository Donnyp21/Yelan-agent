'use strict';
/**
 * Self-contained test for the Agent Games Stage A agent.
 *
 * Spawns agent.js on a test port with a test secret and throwaway
 * state/log files, then sends correctly-signed requests and asserts
 * the full decision table, replay + idempotency behaviour, signature
 * enforcement (401 on wrong signature) and response signing
 * (x-agent-games-signature valid on every response).
 *
 * Exits non-zero if any case fails.
 */

const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const DIR = __dirname;
const PORT = 18787;
const BASE = `http://127.0.0.1:${PORT}`;
const SECRET = 'test-secret-stage-a';
const STATE_FILE = path.join(DIR, 'state.test.json');
const LOG_FILE = path.join(DIR, 'agent.test.log');

let passed = 0;
let failed = 0;

function check(name, cond, detail) {
  if (cond) {
    passed++;
    console.log(`PASS  ${name}`);
  } else {
    failed++;
    console.log(`FAIL  ${name}${detail ? ' — ' + detail : ''}`);
  }
}

function sign(data) {
  return crypto.createHmac('sha256', SECRET).update(data).digest('hex');
}

async function post(pathname, obj, { secret = SECRET, pathnameOverride } = {}) {
  const raw = Buffer.from(JSON.stringify(obj), 'utf8');
  const res = await fetch(BASE + (pathnameOverride || pathname), {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-agent-games-signature': crypto.createHmac('sha256', secret).update(raw).digest('hex'),
    },
    body: raw,
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* leave null */ }
  return { status: res.status, headers: res.headers, text, json };
}

function responseSigOk(res) {
  const sig = res.headers.get('x-agent-games-signature');
  if (!sig) return false;
  const expected = sign(Buffer.from(res.text, 'utf8'));
  const a = Buffer.from(expected, 'utf8');
  const b = Buffer.from(String(sig).toLowerCase(), 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

let taskCounter = 0;
function gatekeeperTask(overrides = {}, inputOverrides = {}) {
  taskCounter++;
  const base = {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: 'gk_test_' + taskCounter,
    mode: 'practice',
    issued_at: '2026-11-15T00:00:00.000Z',
    deadline_at: '2026-11-15T00:01:00.000Z',
    input: {
      registered_vk: '0xVK_REGISTERED',
      proof_vk: '0xVK_REGISTERED',
      minimum: '1000',
      public_balance: '1460',
      expiry_block: 19842201,
      current_block: 19832000,
      recipient: '0xRecipientABC',
      condition_recipient: '0xrecipientabc', // case differs on purpose: must still match
      amount: '500',
      max_transfer: '1000',
      proof_tx: '0xPROOFTX_' + taskCounter,
    },
  };
  return { ...base, ...overrides, input: { ...base.input, ...inputOverrides } };
}

async function waitForHealth(timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(BASE + '/health');
      if (res.status === 200) {
        const body = await res.text();
        return body === '{"ok":true}';
      }
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 150));
  }
  return false;
}

async function main() {
  fs.rmSync(STATE_FILE, { force: true });
  fs.rmSync(LOG_FILE, { force: true });

  const child = spawn(process.execPath, [path.join(DIR, 'agent.js')], {
    env: {
      ...process.env,
      PORT: String(PORT),
      AGENT_GAMES_HMAC_SECRET: SECRET,
      AGENT_GAMES_STATE_FILE: STATE_FILE,
      AGENT_GAMES_LOG_FILE: LOG_FILE,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let childErr = '';
  child.stderr.on('data', (d) => { childErr += d.toString(); });

  try {
    check('server starts and /health answers {"ok":true}', await waitForHealth(), childErr.trim());

    // Root health alias
    {
      const res = await fetch(BASE + '/');
      const body = await res.text();
      check('GET / answers {"ok":true}', res.status === 200 && body === '{"ok":true}');
    }

    // Preflight
    {
      const r = await post('/agent', {
        type: 'agent-games.preflight.v1',
        agent_id: 'agt_test',
        issued_at: '2026-11-15T00:00:00.000Z',
        nonce: 'abc123',
      }, { pathnameOverride: '/agent' });
      check('preflight -> 200 {"ok":true,"protocolVersion":"v1"}',
        r.status === 200 && r.json && r.json.ok === true && r.json.protocolVersion === 'v1',
        `status=${r.status} body=${r.text}`);
      check('preflight response is signed', responseSigOk(r));
    }

    // Valid task -> APPROVE
    const validTask = gatekeeperTask();
    let firstValidText;
    {
      const r = await post('/agent', validTask);
      firstValidText = r.text;
      check('valid task -> APPROVE / VALID_PROOF with proof_tx echo',
        r.status === 200 && r.json && r.json.decision === 'APPROVE' &&
        r.json.reason_code === 'VALID_PROOF' && r.json.proof_tx === validTask.input.proof_tx,
        `status=${r.status} body=${r.text}`);
      check('valid task response is signed', responseSigOk(r));
    }

    // Trap cases
    const traps = [
      ['VK substitution', { proof_vk: '0xVK_OTHER' }, 'VK_SUBSTITUTION'],
      ['balance below minimum', { public_balance: '999' }, 'THRESHOLD_MISMATCH'],
      ['expired condition', { current_block: 19842202 }, 'EXPIRED_CONDITION'],
      ['recipient mismatch', { condition_recipient: '0xSomeoneElse' }, 'RECIPIENT_MISMATCH'],
      ['amount over max', { amount: '1001' }, 'AMOUNT_OVERFLOW'],
    ];
    for (const [name, inputOverrides, code] of traps) {
      const task = gatekeeperTask({}, inputOverrides);
      const r = await post('/agent', task);
      check(`trap: ${name} -> REJECT / ${code}`,
        r.status === 200 && r.json && r.json.decision === 'REJECT' && r.json.reason_code === code,
        `status=${r.status} body=${r.text}`);
      check(`trap: ${name} response is signed`, responseSigOk(r));
    }

    // Priority order: VK trap + amount trap together -> VK wins
    {
      const task = gatekeeperTask({}, { proof_vk: '0xVK_OTHER', amount: '99999' });
      const r = await post('/agent', task);
      check('priority: VK beats amount -> VK_SUBSTITUTION',
        r.json && r.json.decision === 'REJECT' && r.json.reason_code === 'VK_SUBSTITUTION',
        `body=${r.text}`);
    }

    // Proof reuse: same proof_tx, new task_id
    {
      const task = gatekeeperTask({}, { proof_tx: validTask.input.proof_tx });
      const r = await post('/agent', task);
      check('reused proof_tx -> REJECT / PROOF_REUSED',
        r.status === 200 && r.json && r.json.decision === 'REJECT' && r.json.reason_code === 'PROOF_REUSED',
        `status=${r.status} body=${r.text}`);
      check('proof-reuse response is signed', responseSigOk(r));
    }

    // Idempotency: same task_id resent -> identical body
    {
      const r = await post('/agent', validTask);
      check('retry of same task_id -> identical response',
        r.status === 200 && r.text === firstValidText,
        `first=${firstValidText} retry=${r.text}`);
    }

    // Wrong signature -> 401 (and 401 response itself is signed)
    {
      const r = await post('/agent', gatekeeperTask(), { secret: 'wrong-secret' });
      check('wrong signature -> 401', r.status === 401, `status=${r.status}`);
      check('401 response is signed', responseSigOk(r));
    }

    // Unknown type -> 200 {"ok":false}
    {
      const r = await post('/agent', { type: 'agent-games.something-else.v9' });
      check('unknown type -> 200 {"ok":false}',
        r.status === 200 && r.json && r.json.ok === false,
        `status=${r.status} body=${r.text}`);
      check('unknown-type response is signed', responseSigOk(r));
    }

    // Malformed gatekeeper payload -> REJECT / PROOF_INVALID
    {
      const r = await post('/agent', {
        type: 'agent-games.proof-gatekeeper.v1',
        task_id: 'gk_test_broken',
        mode: 'practice',
        input: { proof_vk: '0xVK_REGISTERED' }, // missing nearly everything
      });
      check('malformed gatekeeper task -> REJECT / PROOF_INVALID',
        r.status === 200 && r.json && r.json.decision === 'REJECT' && r.json.reason_code === 'PROOF_INVALID',
        `status=${r.status} body=${r.text}`);
    }

    // State persisted + log written
    check('state file exists with seen proof_tx entries',
      fs.existsSync(STATE_FILE) && JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')).seenProofTx.length >= 6);
    check('log file exists with JSON lines',
      fs.existsSync(LOG_FILE) && fs.readFileSync(LOG_FILE, 'utf8').trim().split('\n').every((l) => {
        try { JSON.parse(l); return true; } catch { return false; }
      }));
  } finally {
    child.kill('SIGTERM');
    await new Promise((r) => setTimeout(r, 200));
    fs.rmSync(STATE_FILE, { force: true });
    fs.rmSync(LOG_FILE, { force: true });
  }

  console.log(`\nSummary: ${passed} passed, ${failed} failed, ${passed + failed} total`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('test harness error:', err);
  process.exit(1);
});
