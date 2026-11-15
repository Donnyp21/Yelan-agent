# Agent Games (zkVerify) — Stage A Competitor Agent

A minimal, dependency-free Node.js agent for the Agent Games **Proof
Gatekeeper** track. It verifies the platform's HMAC signature on every
inbound task, answers the preflight handshake, and decides
APPROVE/REJECT for proof-gatekeeper tasks using only local checks —
every request is answered in milliseconds, far inside the 60 s window.
No external calls are made.

## Run

```sh
AGENT_GAMES_HMAC_SECRET=<secret issued at registration> node agent.js
```

| Env var | Default | Purpose |
| --- | --- | --- |
| `AGENT_GAMES_HMAC_SECRET` | *(required)* | HMAC-SHA256 key shared with the platform. Server refuses to start without it. |
| `PORT` | `8787` | Listen port. Binds `0.0.0.0`. |
| `AGENT_GAMES_STATE_FILE` | `./state.json` | Seen proof_tx set + stored per-task decisions (survives restarts). |
| `AGENT_GAMES_LOG_FILE` | `./agent.log` | JSON-lines request log (timestamp, type, task_id, mode, decision, reason_code, latency). |

Register the endpoint with the **full path** (e.g. `https://host/agent`).
The server accepts signed POSTs on any path, so `/agent` works as-is;
`GET /health` and `GET /` answer `{"ok":true}` for platform health checks.

## Protocol summary

- Inbound: header `x-agent-games-signature` must be the HMAC-SHA256 hex
  of the **raw** request body. Verified before parsing; mismatch → `401`.
- Outbound: **every** response carries `x-agent-games-signature` =
  HMAC-SHA256 hex of the raw response body, same secret.
- Preflight `{"type":"agent-games.preflight.v1", ...}` →
  `200 {"ok":true,"protocolVersion":"v1"}`.
- Unknown message types → `200 {"ok":false}` (fail closed, never hang).

## Decision table — `agent-games.proof-gatekeeper.v1`

Checks run in this priority order; the first failure wins. Numeric
fields arrive as strings and are compared as BigInt.

| # | Check | On failure |
| --- | --- | --- |
| 1 | `proof_vk` ≠ `registered_vk` | REJECT `VK_SUBSTITUTION` |
| 2 | `public_balance` < `minimum` | REJECT `THRESHOLD_MISMATCH` |
| 3 | `current_block` > `expiry_block` | REJECT `EXPIRED_CONDITION` |
| 4 | `recipient` ≠ `condition_recipient` (case-insensitive) | REJECT `RECIPIENT_MISMATCH` |
| 5 | `amount` > `max_transfer` | REJECT `AMOUNT_OVERFLOW` |
| 6 | `proof_tx` already seen in an earlier task | REJECT `PROOF_REUSED` |
| — | all checks pass | APPROVE `VALID_PROOF` |
| — | payload malformed / unparsable mid-check | REJECT `PROOF_INVALID` |

Response shape: `{"decision":"APPROVE"|"REJECT","reason_code":"<CODE>","proof_tx":"<echoed from input>"}`.

**Idempotency & replay protection:** every processed task's `proof_tx`
is added to a persistent seen-set (`state.json`). `task_id` is an
idempotency key — if the platform retries the same `task_id`, the
stored decision is returned verbatim without re-deciding (so a retry of
an approved task is *not* rejected as a proof replay).

## Test

```sh
node test.js
```

Starts the server on a throwaway port with a test secret and asserts:
preflight, a valid approval, all five traps, priority ordering,
proof-reuse rejection, task_id idempotency, `401` on a wrong
signature, and a valid response signature on every reply. Prints
PASS/FAIL per case and exits non-zero on any failure.

## OPEN QUESTIONS (resolve in practice mode)

Conflicts between the official Build page (§02.5), the event page's
response shape, and the rules — to be settled by observing real
practice-mode traffic before the first competition round:

a. **Extra proof payload?** Build §02.5 says responses must
   additionally include a locally generated Groth16 proof +
   `public_signals`; the event page's response shape is just
   `decision` / `reason_code` / `proof_tx`. Stage A sends only the
   event-page shape. If practice tasks score 0 / "missing proof",
   Stage B adds local proof generation.
b. **Reason-code naming conflicts.** Docs disagree in places:
   `PROOF_REUSED` vs `PROOF_REPLAY`, and `VALID_PROOF` vs
   `VALID_CONDITION`. Stage A uses `PROOF_REUSED` / `VALID_PROOF`
   (the spellings in the task brief). If practice mode rejects or
   mis-scores them, switch to the alternates and record which set the
   platform actually accepts.
c. **Endpoint URL editability after registration is undocumented.**
   If the registered URL (host + path) cannot be edited later, the
   public endpoint must be final *before* registering the agent —
   confirm in the dashboard before committing to a tunnel/host.
