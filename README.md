# BTC Lottery — Multithreaded Address Scanner

Educational JavaScript / Node.js implementation of the classic "Bitcoin lottery": generate random Bitcoin keypairs, derive their addresses, and check whether any of them happen to hold a balance via public block explorer APIs.

> **Disclaimer (please read).** Finding a funded address by random brute-force has a probability of roughly **1 in 2¹⁶⁰**. Even if this script ran on every computer on Earth for billions of years, the chance of a single hit would still be effectively zero. This project is interesting as a study in cryptography, parallel I/O, and Node.js worker threads — **it is not a financial strategy**. Do not run it expecting any return.

---

## Features

- **Multi-threaded** — uses Node.js `worker_threads` to generate keypairs in parallel.
- **Multiple address types** — P2PKH (compressed/uncompressed), P2WPKH (SegWit bech32), P2SH-P2WPKH (nested SegWit), and 2-of-3 multisig (optional).
- **Multiple endpoints with failover** — `blockchain.info`, `blockstream.info`, `mempool.space`, with three strategies: `failover`, `round-robin`, `random`.
- **Batched lookups** — when supported by the endpoint (e.g. `blockchain.info`), all addresses for one keypair are checked in a single HTTP request.
- **Resilient HTTP** — request timeouts, one automatic retry on transient/`5xx`/`429` errors, longer back-off when rate-limited.
- **Auto-restart of crashed workers** — if a worker dies, it is respawned without losing the run.
- **Cooldown cycle** — work N minutes, rest M minutes, repeat. Keeps the device cool when running for long sessions.
- **Persistent state** — cumulative counters and per-endpoint statistics are written atomically to `state.json`, with a periodic backup to `state.json.backup`.
- **JSON Lines hits** — every hit is appended as a single JSON object per line for easy parsing by other tools.
- **In-worker LRU cache** — duplicate addresses (extremely rare but free) are served from memory.
- **Connection keep-alive** — uses `undici` with long keep-alive timeouts to skip TLS handshakes on most requests.
- **Environment-variable overrides** — every setting in `config.json` can be overridden at runtime via env vars.

---

## Installation

```bash
npm install
```

Requires Node.js ≥ 20.

## Run

```bash
npm start
# or
node index.js
```

To stop: `Ctrl+C`. The script catches `SIGINT` / `SIGTERM`, terminates all workers cleanly, and writes the final state.

---

## Configuration (`config.json`)

| Field | Type | Default | Description |
|---|---|---|---|
| `workerCount` | number | `3` | Parallel worker threads. Each = roughly 1 CPU core. |
| `addressesPerRound` | number | `60` | Addresses per worker before a round pause. |
| `perAddressDelayMs` | number | `1500` | Delay between iterations inside a worker. |
| `jitterMs` | number | `400` | Random ± jitter added to the delay above. |
| `roundPauseMs` | number | `30000` | Pause after each round (in ms). |
| `errorBackoffMs` | number | `15000` | Sleep duration after a worker-level error. |
| `requestTimeoutMs` | number | `10000` | Per-request HTTP timeout. |
| `workIntervalMinutes` | number | `30` | Cooldown cycle: minutes of work before resting. `0` to disable. |
| `restPauseMinutes` | number | `2` | Cooldown cycle: minutes of rest. `0` to disable. |
| `endpoints` | array | (3 public APIs) | List of `{ type, url }` endpoints to query. |
| `endpointStrategy` | string | `failover` | `failover` (try in order), `round-robin`, or `random`. |
| `addressTypes` | object | (multiple) | Toggle which address types to derive & check. |
| `outputFile` | string | `Lottery_BTC.jsonl` | File to which hits are appended (JSON Lines). |
| `verbose` | boolean | `true` | Print every checked address. Disable for quiet runs. |
| `statsIntervalMs` | number | `60000` | Periodic stats line interval. |
| `pauseOnHit` | boolean | `true` | Stop everything immediately when a balance is found. |
| `stateFile` | string | `state.json` | Persistent state file path. |
| `backupIntervalMs` | number | `3600000` | Interval for writing `state.json.backup` (default 1 h). |

---

## Environment variable overrides

Any setting can be overridden at runtime without touching `config.json`. Useful for deployment.

| Env var | Maps to |
|---|---|
| `WORKER_COUNT` | `workerCount` |
| `PER_ADDRESS_DELAY_MS` | `perAddressDelayMs` |
| `JITTER_MS` | `jitterMs` |
| `ROUND_PAUSE_MS` | `roundPauseMs` |
| `ADDRESSES_PER_ROUND` | `addressesPerRound` |
| `ERROR_BACKOFF_MS` | `errorBackoffMs` |
| `REQUEST_TIMEOUT_MS` | `requestTimeoutMs` |
| `WORK_INTERVAL_MINUTES` | `workIntervalMinutes` |
| `REST_PAUSE_MINUTES` | `restPauseMinutes` |
| `STATS_INTERVAL_MS` | `statsIntervalMs` |
| `BACKUP_INTERVAL_MS` | `backupIntervalMs` |
| `ENDPOINT_STRATEGY` | `endpointStrategy` |
| `OUTPUT_FILE` | `outputFile` |
| `STATE_FILE` | `stateFile` |
| `VERBOSE` | `verbose` (`"true"` / `"false"`) |
| `PAUSE_ON_HIT` | `pauseOnHit` (`"true"` / `"false"`) |

Example:

```bash
WORKER_COUNT=2 PER_ADDRESS_DELAY_MS=2000 VERBOSE=false node index.js
```

---

## Output

### `Lottery_BTC.jsonl`

Each hit becomes a single JSON object on its own line. Example:

```json
{"ts":"2026-04-23T19:30:00.000Z","type":"compressed","address":"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa","balance":5000,"wif":"K..."}
```

This makes downstream parsing trivial — e.g. `cat Lottery_BTC.jsonl | jq .`.

### `state.json` and `state.json.backup`

Atomically-written cumulative counters plus per-endpoint reliability stats:

```json
{
  "totalCount": 1024,
  "totalHits": 0,
  "totalErrors": 12,
  "totalUptimeMs": 1800000,
  "runs": 4,
  "endpointStats": {
    "blockchain":  { "ok": 1010, "err": 4 },
    "blockstream": { "ok":   12, "err": 6 },
    "mempool":     { "ok":    2, "err": 2 }
  }
}
```

The backup file is written periodically (default: every hour). If `state.json` is ever corrupted, you can restore it by copying the backup over.

---

## Cooldown cycle

To keep the host cool during long runs, the script alternates between **work** and **rest**:

```
[ work for `workIntervalMinutes` ]  →  [ pause for `restPauseMinutes` ]  →  repeat
```

During the rest window, all worker threads pause cleanly — they are not killed, so no progress or warmup time is lost. Banner messages mark the transitions in the console.

Set both fields to `0` to disable.

---

## Heat-friendly profile

For laptops, mobile devices, or cramped enclosures, the defaults are conservative. If the host still runs hot, try:

```json
"workerCount": 2,
"perAddressDelayMs": 2500,
"workIntervalMinutes": 20,
"restPauseMinutes": 5
```

For maximum throughput on a powerful machine:

```json
"workerCount": 6,
"perAddressDelayMs": 500,
"workIntervalMinutes": 0,
"restPauseMinutes": 0
```

---

## Architecture

```
 ┌────────────────────────────────────────────────────────────┐
 │                      Main process                          │
 │  - reads config + env overrides                            │
 │  - spawns workers (auto-restart on crash)                  │
 │  - aggregates stats, writes state.json + backup            │
 │  - cooldown cycle (pause / resume)                         │
 │  - handles hits → appends JSON line, optional stop         │
 └────────────────────────────────────────────────────────────┘
              │ messages          ▲
              ▼                   │
    ┌──────────────┐   ┌──────────────┐    ...   ┌──────────────┐
    │  Worker 1    │   │  Worker 2    │          │  Worker N    │
    │              │   │              │          │              │
    │ generate kp  │   │ generate kp  │          │ generate kp  │
    │ batch lookup │   │ batch lookup │          │ batch lookup │
    │ LRU cache    │   │ LRU cache    │          │ LRU cache    │
    └──────────────┘   └──────────────┘          └──────────────┘
              │
              ▼
    HTTP (undici keep-alive) → blockchain.info / blockstream / mempool
```

---

## License & Use

Educational use only. You are responsible for complying with the terms of service of any block-explorer API you query (rate limits, attribution, etc.). Do not point this script at private/paid APIs without permission.
