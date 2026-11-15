'use strict';
/**
 * Agent Games (zkVerify) — Stage A competitor agent.
 *
 * Pure Node builtins only (node:http, node:crypto, node:fs).
 *
 * Protocol:
 *  - Inbound POSTs are authenticated: header `x-agent-games-signature`
 *    must equal HMAC-SHA256 hex of the RAW request body, keyed by
 *    AGENT_GAMES_HMAC_SECRET. Verified before parsing; mismatch -> 401.
 *  - Every response carries `x-agent-games-signature` = HMAC-SHA256 hex
 *    of the raw response body, same secret.
 *  - Preflight: {"type":"agent-games.preflight.v1", ...} ->
 *    200 {"ok":true,"protocolVersion":"v1"}
 *  - Gatekeeper tasks: proof checks in a fixed priority order
 *    (see decide()); REJECT reason codes per spec.
 *  - Fail closed: unknown type -> 200 {"ok":false}; a gatekeeper task
 *    that fails parsing -> REJECT / PROOF_INVALID. Never hangs.
 *
 * State (seen proof_tx set + per-task_id decisions) lives in a JSON
 * file so it survives restarts. Env: PORT (default 8787),
 * AGENT_GAMES_HMAC_SECRET (required), AGENT_GAMES_STATE_FILE,
 * AGENT_GAMES_LOG_FILE.
 */

const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const PORT = Number(process.env.PORT || 8787);
const HOST = '0.0.0.0';
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const DIR = __dirname;
const STATE_FILE = process.env.AGENT_GAMES_STATE_FILE || path.join(DIR, 'state.json');
const LOG_FILE = process.env.AGENT_GAMES_LOG_FILE || path.join(DIR, 'agent.log');
const MAX_BODY_BYTES = 1024 * 1024; // 1 MiB guard; tasks are tiny

if (!SECRET) {
  console.error('FATAL: AGENT_GAMES_HMAC_SECRET is not set.');
  process.exit(1);
}

// ---------------------------------------------------------------- state

function loadState() {
  try {
    const parsed = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
    const seen = new Set(Array.isArray(parsed.seenProofTx) ? parsed.seenProofTx : []);
    const decisions = parsed.decisions && typeof parsed.decisions === 'object' ? parsed.decisions : {};
    return { seen, decisions };
  } catch {
    return { seen: new Set(), decisions: {} };
  }
}

const state = loadState();

function persistState() {
  const payload = JSON.stringify(
    { seenProofTx: [...state.seen], decisions: state.decisions },
    null,
    2
  );
  const tmp = STATE_FILE + '.tmp';
  fs.writeFileSync(tmp, payload);
  fs.renameSync(tmp, STATE_FILE); // atomic-ish replace
}

// ---------------------------------------------------------------- logging

function logLine(entry) {
  try {
    fs.appendFileSync(LOG_FILE, JSON.stringify(entry) + '\n');
  } catch (err) {
    console.error('log write failed:', err.message);
  }
}

// ---------------------------------------------------------------- crypto helpers

function hmacHex(data) {
  return crypto.createHmac('sha256', SECRET).update(data).digest('hex');
}

function signatureOk(rawBody, headerValue) {
  if (typeof headerValue !== 'string' || headerValue.length === 0) return false;
  const expected = Buffer.from(hmacHex(rawBody), 'utf8');
  const given = Buffer.from(headerValue.trim().toLowerCase(), 'utf8');
  if (expected.length !== given.length) return false;
  return crypto.timingSafeEqual(expected, given);
}

// ---------------------------------------------------------------- responses

function sendJson(res, startedAt, meta, status, obj) {
  const body = Buffer.from(JSON.stringify(obj), 'utf8');
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': body.length,
    'x-agent-games-signature': hmacHex(body),
  });
  res.end(body);
  logLine({
    ts: new Date().toISOString(),
    ...meta,
    status,
    latency_ms: Date.now() - startedAt,
  });
}

function sendHealth(res, startedAt, meta) {
  const body = Buffer.from('{"ok":true}', 'utf8');
  res.writeHead(200, {
    'content-type': 'application/json',
    'content-length': body.length,
    'x-agent-games-signature': hmacHex(body),
  });
  res.end(body);
  logLine({ ts: new Date().toISOString(), ...meta, status: 200, latency_ms: Date.now() - startedAt });
}

// ---------------------------------------------------------------- gatekeeper decision

function reject(reason_code, proof_tx) {
  const out = { decision: 'REJECT', reason_code };
  if (typeof proof_tx === 'string') out.proof_tx = proof_tx;
  return out;
}

function parseBigIntField(input, key) {
  const v = input[key];
  if (typeof v === 'string' && v.trim() !== '') return BigInt(v);
  if (typeof v === 'number' && Number.isSafeInteger(v)) return BigInt(v);
  if (typeof v === 'bigint') return v;
  throw new Error('field not a valid integer: ' + key);
}

function decide(task) {
  const input = task && typeof task === 'object' ? task.input : null;
  if (!input || typeof input !== 'object') {
    return reject('PROOF_INVALID', input && typeof input.proof_tx === 'string' ? input.proof_tx : undefined);
  }
  const proof_tx = typeof input.proof_tx === 'string' ? input.proof_tx : undefined;
  try {
    // 1. VK substitution
    if (typeof input.proof_vk !== 'string' || typeof input.registered_vk !== 'string') {
      return reject('PROOF_INVALID', proof_tx);
    }
    if (input.proof_vk !== input.registered_vk) return reject('VK_SUBSTITUTION', proof_tx);

    // 2. Balance below minimum
    const publicBalance = parseBigIntField(input, 'public_balance');
    const minimum = parseBigIntField(input, 'minimum');
    if (publicBalance < minimum) return reject('THRESHOLD_MISMATCH', proof_tx);

    // 3. Condition expired
    const currentBlock = parseBigIntField(input, 'current_block');
    const expiryBlock = parseBigIntField(input, 'expiry_block');
    if (currentBlock > expiryBlock) return reject('EXPIRED_CONDITION', proof_tx);

    // 4. Recipient mismatch (case-insensitive)
    if (typeof input.recipient !== 'string' || typeof input.condition_recipient !== 'string') {
      return reject('PROOF_INVALID', proof_tx);
    }
    if (input.recipient.toLowerCase() !== input.condition_recipient.toLowerCase()) {
      return reject('RECIPIENT_MISMATCH', proof_tx);
    }

    // 5. Amount over max transfer
    const amount = parseBigIntField(input, 'amount');
    const maxTransfer = parseBigIntField(input, 'max_transfer');
    if (amount > maxTransfer) return reject('AMOUNT_OVERFLOW', proof_tx);

    // 6. Proof replay
    if (proof_tx === undefined) return reject('PROOF_INVALID', proof_tx);
    if (state.seen.has(proof_tx)) return reject('PROOF_REUSED', proof_tx);

    // 7. All checks passed
    return { decision: 'APPROVE', reason_code: 'VALID_PROOF', proof_tx };
  } catch {
    return reject('PROOF_INVALID', proof_tx);
  }
}

// ---------------------------------------------------------------- request handling

function readBody(req) {
  return new Promise((resolve, rejectPromise) => {
    const chunks = [];
    let total = 0;
    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        rejectPromise(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', rejectPromise);
  });
}

async function handlePost(req, res, startedAt) {
  const raw = await readBody(req);

  if (!signatureOk(raw, req.headers['x-agent-games-signature'])) {
    return sendJson(res, startedAt, { type: null, error: 'bad_signature' }, 401, { ok: false, error: 'invalid_signature' });
  }

  let msg;
  try {
    msg = JSON.parse(raw.toString('utf8'));
  } catch {
    return sendJson(res, startedAt, { type: null, error: 'malformed_json' }, 200, { ok: false });
  }

  const type = msg && typeof msg === 'object' ? msg.type : undefined;

  if (type === 'agent-games.preflight.v1') {
    return sendJson(res, startedAt, { type }, 200, { ok: true, protocolVersion: 'v1' });
  }

  if (type === 'agent-games.proof-gatekeeper.v1') {
    const taskId = typeof msg.task_id === 'string' ? msg.task_id : null;
    const mode = typeof msg.mode === 'string' ? msg.mode : null;
    const input = msg.input && typeof msg.input === 'object' ? msg.input : null;
    const proofTx = input && typeof input.proof_tx === 'string' ? input.proof_tx : null;

    // Idempotency: a retried task_id returns the stored decision verbatim.
    if (taskId && Object.prototype.hasOwnProperty.call(state.decisions, taskId)) {
      const stored = state.decisions[taskId];
      return sendJson(
        res,
        startedAt,
        { type, task_id: taskId, mode, decision: stored.decision, reason_code: stored.reason_code, idempotent_replay: true },
        200,
        stored
      );
    }

    const response = decide(msg);
    if (taskId) state.decisions[taskId] = response;
    if (proofTx) state.seen.add(proofTx);
    try { persistState(); } catch (err) { console.error('state persist failed:', err.message); }

    return sendJson(
      res,
      startedAt,
      { type, task_id: taskId, mode, decision: response.decision, reason_code: response.reason_code },
      200,
      response
    );
  }

  // Unknown type: fail closed but always answer.
  return sendJson(res, startedAt, { type: typeof type === 'string' ? type : null, error: 'unknown_type' }, 200, { ok: false });
}

const server = http.createServer((req, res) => {
  const startedAt = Date.now();
  const url = (req.url || '/').split('?')[0];
  const meta = { method: req.method, path: url };

  if (req.method === 'GET' && (url === '/health' || url === '/')) {
    return sendHealth(res, startedAt, meta);
  }

  if (req.method === 'POST') {
    handlePost(req, res, startedAt).catch((err) => {
      try {
        sendJson(res, startedAt, { ...meta, error: String(err && err.message) }, 200, { ok: false });
      } catch { /* socket already gone */ }
    });
    return;
  }

  sendJson(res, startedAt, meta, 404, { ok: false, error: 'not_found' });
});

server.listen(PORT, HOST, () => {
  console.log(`agent-games agent listening on http://${HOST}:${PORT}`);
  console.log(`state file: ${STATE_FILE}`);
  console.log(`log file:   ${LOG_FILE}`);
});
