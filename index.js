/*
 * btc-balance.js
 *
 * Multithreaded JavaScript port of the original Python "BTC lottery" script.
 * Uses Node.js worker_threads to generate Bitcoin keypairs and check their
 * balances in parallel. All settings come from config.json — no CLI flags.
 *
 * Run:
 *   node btc-balance.js
 *
 * Educational use only. The probability of brute-forcing a funded address
 * is effectively zero (~1 in 2^160).
 */

import { appendFileSync, readFileSync, writeFileSync, existsSync, renameSync } from "node:fs";
import { setTimeout as sleep } from "node:timers/promises";
import { Worker, isMainThread, parentPort, workerData } from "node:worker_threads";
import { fileURLToPath } from "node:url";
import * as bitcoin from "bitcoinjs-lib";
import * as ecc from "tiny-secp256k1";
import { ECPairFactory } from "ecpair";
// Note: Node 20's built-in fetch already uses a keep-alive pool by default.
// We previously installed a custom undici Agent here for longer keep-alive
// timeouts, but it caused fetch to hang inside worker threads on this Node
// version. Default dispatcher is fine for our request rate.

bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);
const NETWORK = bitcoin.networks.bitcoin;
const SELF = fileURLToPath(import.meta.url);

function loadConfig() {
  const raw = readFileSync(new URL("./config.json", import.meta.url), "utf8");
  return JSON.parse(raw);
}

/* ----------------------------- Bitcoin helpers ---------------------------- */

function makeKeyPair() {
  const compressedKey = ECPair.makeRandom({ network: NETWORK, compressed: true });
  const uncompressedKey = ECPair.fromPrivateKey(compressedKey.privateKey, {
    network: NETWORK,
    compressed: false,
  });

  const { address: compressedAddress } = bitcoin.payments.p2pkh({
    pubkey: compressedKey.publicKey,
    network: NETWORK,
  });
  const { address: uncompressedAddress } = bitcoin.payments.p2pkh({
    pubkey: uncompressedKey.publicKey,
    network: NETWORK,
  });
  const { address: segwitAddress } = bitcoin.payments.p2wpkh({
    pubkey: compressedKey.publicKey,
    network: NETWORK,
  });
  const { address: nestedSegwitAddress } = bitcoin.payments.p2sh({
    redeem: bitcoin.payments.p2wpkh({ pubkey: compressedKey.publicKey, network: NETWORK }),
    network: NETWORK,
  });

  return {
    privateKeyHex: Buffer.from(compressedKey.privateKey).toString("hex"),
    wifCompressed: compressedKey.toWIF(),
    wifUncompressed: uncompressedKey.toWIF(),
    compressedAddress,
    uncompressedAddress,
    segwitAddress,
    nestedSegwitAddress,
  };
}

function makeMultisigAddress() {
  const keys = [0, 1, 2].map(() =>
    ECPair.makeRandom({ network: NETWORK, compressed: true }),
  );
  const redeem = bitcoin.payments.p2ms({
    m: 2,
    pubkeys: keys.map((k) => k.publicKey),
    network: NETWORK,
  });
  const { address } = bitcoin.payments.p2sh({ redeem, network: NETWORK });
  return { address, privateKeysWif: keys.map((k) => k.toWIF()) };
}

const ENDPOINT_PARSERS = {
  blockchain: async (res, addresses) => {
    const data = await res.json();
    const out = {};
    for (const a of addresses) {
      out[a] = Number(data[a]?.final_balance ?? 0);
    }
    return out;
  },
  blockstream: async (res, addresses) => {
    const data = await res.json();
    const c = data.chain_stats ?? { funded_txo_sum: 0, spent_txo_sum: 0 };
    const m = data.mempool_stats ?? { funded_txo_sum: 0, spent_txo_sum: 0 };
    return {
      [addresses[0]]:
        (c.funded_txo_sum - c.spent_txo_sum) +
        (m.funded_txo_sum - m.spent_txo_sum),
    };
  },
};
ENDPOINT_PARSERS.mempool = ENDPOINT_PARSERS.blockstream;

const ENDPOINT_BATCH = {
  blockchain: true,
  blockstream: false,
  mempool: false,
};

function buildEndpointUrl(endpoint, addresses) {
  if (endpoint.type === "blockchain") return `${endpoint.url}${addresses.join("|")}`;
  if (endpoint.type === "blockstream") return `${endpoint.url}${addresses[0]}`;
  if (endpoint.type === "mempool") return `${endpoint.url}${addresses[0]}`;
  throw new Error(`Unknown endpoint type: ${endpoint.type}`);
}

let rrCursor = 0;
function orderEndpoints(endpoints, strategy) {
  if (strategy === "round-robin" && endpoints.length > 1) {
    const start = rrCursor++ % endpoints.length;
    return endpoints.slice(start).concat(endpoints.slice(0, start));
  }
  if (strategy === "random" && endpoints.length > 1) {
    const start = Math.floor(Math.random() * endpoints.length);
    return endpoints.slice(start).concat(endpoints.slice(0, start));
  }
  return endpoints;
}

// Filter endpoints that are currently in 429 cooldown. If every endpoint is
// cooling down we still return the full list (least-cooled first) so we keep
// trying instead of stalling forever.
function filterCooling(endpoints, cooldownUntil) {
  const now = Date.now();
  const live = endpoints.filter((e) => !cooldownUntil[e.type] || cooldownUntil[e.type] <= now);
  if (live.length > 0) return live;
  return [...endpoints].sort(
    (a, b) => (cooldownUntil[a.type] ?? 0) - (cooldownUntil[b.type] ?? 0),
  );
}

async function fetchOnce(url, timeoutMs) {
  const res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) });
  if (!res.ok) {
    const err = new Error(`HTTP ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return res;
}

/**
 * Fetch balances for one or more addresses through the configured endpoints.
 * - Tries endpoints in order (round-robin / random / failover).
 * - Batches addresses into a single request when the endpoint supports it.
 * - One automatic retry on transient network/5xx errors before failing over.
 * - Honors HTTP 429 with a longer backoff.
 */
async function getBalances(addresses, endpoints, strategy, epStats, opts, cooldownUntil, batchChunkSize) {
  const timeoutMs = opts.requestTimeoutMs;
  const errorBackoffMs = opts.errorBackoffMs;
  const rateLimitBackoffMs = opts.rateLimitBackoffMs ?? 5000;
  const rateLimitCooldownMs = opts.rateLimitCooldownMs ?? 60000;
  const chunkSize = Math.max(1, batchChunkSize ?? 50);
  let lastErr;

  const ordered = orderEndpoints(filterCooling(endpoints, cooldownUntil), strategy);
  for (const endpoint of ordered) {
    const slot = epStats[endpoint.type] ?? (epStats[endpoint.type] = { ok: 0, err: 0 });
    const parser = ENDPOINT_PARSERS[endpoint.type];
    const supportsBatch = ENDPOINT_BATCH[endpoint.type];
    let groups;
    if (supportsBatch) {
      groups = [];
      for (let i = 0; i < addresses.length; i += chunkSize) {
        groups.push(addresses.slice(i, i + chunkSize));
      }
    } else {
      groups = addresses.map((a) => [a]);
    }

    try {
      const merged = {};
      for (const group of groups) {
        const url = buildEndpointUrl(endpoint, group);
        let res;
        try {
          res = await fetchOnce(url, timeoutMs);
        } catch (err) {
          if (err.status === 429) {
            cooldownUntil[endpoint.type] = Date.now() + rateLimitCooldownMs;
            throw err; // immediately fail over to next endpoint
          }
          // 1 retry for transient failures (timeout, network, 5xx). Skip retry on other 4xx.
          const transient =
            !err.status || err.status >= 500 || err.name === "TimeoutError" || err.name === "AbortError";
          if (!transient) throw err;
          await sleep(Math.min(errorBackoffMs, 3000));
          res = await fetchOnce(url, timeoutMs);
        }
        const part = await parser(res, group);
        Object.assign(merged, part);
      }
      slot.ok += 1;
      return merged;
    } catch (err) {
      slot.err += 1;
      lastErr = err;
    }
  }
  throw new Error(`all endpoints failed: ${lastErr?.message}`);
}

/* -------------------------------- Worker -------------------------------- */

async function runWorker() {
  const cfg = workerData.config;
  const id = workerData.id;
  const enabled = cfg.addressTypes;
  const epStats = {};
  let paused = false;
  parentPort.on("message", (m) => {
    if (m?.type === "pause") paused = true;
    else if (m?.type === "resume") paused = false;
  });
  const flushEp = () => {
    const snap = {};
    for (const k of Object.keys(epStats)) {
      snap[k] = { ok: epStats[k].ok, err: epStats[k].err };
      epStats[k].ok = 0;
      epStats[k].err = 0;
    }
    if (Object.keys(snap).length) {
      parentPort.postMessage({ type: "endpointStats", workerId: id, snap });
    }
  };

  const opts = {
    requestTimeoutMs: cfg.requestTimeoutMs ?? 10000,
    errorBackoffMs: cfg.errorBackoffMs ?? 15000,
    rateLimitBackoffMs: cfg.rateLimitBackoffMs ?? 5000,
    rateLimitCooldownMs: cfg.rateLimitCooldownMs ?? 60000,
  };

  // Per-endpoint cooldown timestamps (ms epoch). When an endpoint returns 429
  // we mark it cooling, and getBalances/orderEndpoints will skip it until the
  // cooldown expires. State is local to the worker — the rate limit is
  // server-side anyway, so each worker discovers it independently.
  const cooldownUntil = {};
  const batchKeypairs = Math.max(1, cfg.batchKeypairs ?? 1);
  const batchChunkSize = Math.max(1, cfg.batchChunkSize ?? 50);

  // Tiny LRU cache: address -> balance. Catches the (vanishingly rare) case
  // of duplicate addresses without an extra HTTP round-trip.
  const CACHE_MAX = 1000;
  const cache = new Map();
  const cacheGet = (k) => {
    if (!cache.has(k)) return undefined;
    const v = cache.get(k);
    cache.delete(k); cache.set(k, v);
    return v;
  };
  const cacheSet = (k, v) => {
    if (cache.has(k)) cache.delete(k);
    cache.set(k, v);
    if (cache.size > CACHE_MAX) cache.delete(cache.keys().next().value);
  };

  while (true) {
    if (paused) {
      while (paused) await sleep(1000);
    }
    try {
      // Generate a batch of keypairs and build the combined task list so we
      // can resolve all of their balances in one (or few) HTTP request(s).
      const items = [];
      const allAddrs = [];
      for (let i = 0; i < batchKeypairs; i++) {
        const kp = makeKeyPair();
        const multi = enabled.multisig ? makeMultisigAddress() : null;
        const tasks = [];
        if (enabled.uncompressed) tasks.push(["uncompressed", kp.uncompressedAddress]);
        if (enabled.compressed)   tasks.push(["compressed",   kp.compressedAddress]);
        if (enabled.segwit)       tasks.push(["segwit",       kp.segwitAddress]);
        if (enabled.nestedSegwit) tasks.push(["nestedSegwit", kp.nestedSegwitAddress]);
        if (multi)                tasks.push(["multi",        multi.address]);
        items.push({ kp, multi, tasks });
        for (const [, a] of tasks) allAddrs.push(a);
      }

      const cachedHits = {};
      const toFetch = [];
      const seen = new Set();
      for (const a of allAddrs) {
        const c = cacheGet(a);
        if (c !== undefined) {
          cachedHits[a] = c;
        } else if (!seen.has(a)) {
          seen.add(a);
          toFetch.push(a);
        }
      }
      let balMap = { ...cachedHits };
      if (toFetch.length > 0) {
        const fetched = await getBalances(
          toFetch, cfg.endpoints, cfg.endpointStrategy, epStats, opts,
          cooldownUntil, batchChunkSize,
        );
        for (const a of toFetch) cacheSet(a, Number(fetched[a] ?? 0));
        balMap = { ...balMap, ...fetched };
      }

      for (const { kp, multi, tasks } of items) {
        const balances = {
          uncompressed: 0, compressed: 0, segwit: 0, nestedSegwit: 0, multi: 0,
        };
        tasks.forEach(([key, addr]) => { balances[key] = Number(balMap[addr] ?? 0); });
        parentPort.postMessage({ type: "result", workerId: id, kp, multi, balances });
      }
      flushEp();
    } catch (err) {
      parentPort.postMessage({ type: "error", workerId: id, message: err.message });
      flushEp();
      await sleep(cfg.errorBackoffMs);
    }
    // perAddressDelayMs is per *keypair*; scale by batch size so request
    // pacing stays roughly the same regardless of batch size.
    const jitter = cfg.jitterMs ?? 0;
    const base = cfg.perAddressDelayMs * batchKeypairs;
    const wait = jitter > 0
      ? base + Math.floor((Math.random() * 2 - 1) * jitter)
      : base;
    await sleep(Math.max(0, wait));
  }
}

/* --------------------------------- Main --------------------------------- */

const C = {
  reset: "\x1b[0m",
  dim: "\x1b[2m",
  bold: "\x1b[1m",
  cyan: "\x1b[36m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  gray: "\x1b[90m",
};

function pad(s, n) {
  s = String(s);
  return s.length >= n ? s : s + " ".repeat(n - s.length);
}

function padLeft(s, n) {
  s = String(s);
  return s.length >= n ? s : " ".repeat(n - s.length) + s;
}

function printRow(count, workerId, kp, multi, balances, enabled) {
  const rows = [];
  if (enabled.uncompressed) rows.push({ type: "uncompressed", addr: kp.uncompressedAddress, bal: balances.uncompressed });
  if (enabled.compressed)   rows.push({ type: "compressed",   addr: kp.compressedAddress,   bal: balances.compressed   });
  if (enabled.segwit)       rows.push({ type: "segwit",       addr: kp.segwitAddress,       bal: balances.segwit       });
  if (enabled.nestedSegwit) rows.push({ type: "p2sh-segwit",  addr: kp.nestedSegwitAddress, bal: balances.nestedSegwit });
  if (multi)                rows.push({ type: "multisig",     addr: multi.address,           bal: balances.multi        });
  if (rows.length === 0) return;

  const header = `${C.gray}┌─ ${C.bold}#${padLeft(count, 6)}${C.reset}${C.gray} ─ worker ${workerId} ${"─".repeat(58)}${C.reset}`;
  console.log(header);
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];
    const branch = i === rows.length - 1 ? "└" : "├";
    const balColor = r.bal > 0 ? C.green + C.bold : C.dim;
    console.log(
      `${C.gray}${branch}─${C.reset} ${C.cyan}${pad(r.type, 12)}${C.reset} ${pad(r.addr, 44)} ${balColor}${padLeft(r.bal, 10)}${C.reset} sat`,
    );
  }
}

function appendHitLine(file, obj) {
  appendFileSync(file, JSON.stringify(obj) + "\n");
}

function handleHit(cfg, kp, multi, balances) {
  const ts = new Date().toISOString();
  const hits = [];
  if (balances.uncompressed > 0) {
    hits.push({ ts, type: "uncompressed", address: kp.uncompressedAddress, balance: balances.uncompressed, wif: kp.wifUncompressed, privateKeyHex: kp.privateKeyHex });
  }
  if (balances.compressed > 0) {
    hits.push({ ts, type: "compressed", address: kp.compressedAddress, balance: balances.compressed, wif: kp.wifCompressed, privateKeyHex: kp.privateKeyHex });
  }
  if (balances.segwit > 0) {
    hits.push({ ts, type: "segwit", address: kp.segwitAddress, balance: balances.segwit, wif: kp.wifCompressed, privateKeyHex: kp.privateKeyHex });
  }
  if (balances.nestedSegwit > 0) {
    hits.push({ ts, type: "p2sh-segwit", address: kp.nestedSegwitAddress, balance: balances.nestedSegwit, wif: kp.wifCompressed, privateKeyHex: kp.privateKeyHex });
  }
  if (multi && balances.multi > 0) {
    hits.push({ ts, type: "multisig", address: multi.address, balance: balances.multi, privateKeysWif: multi.privateKeysWif });
  }
  if (hits.length === 0) return false;
  for (const h of hits) appendHitLine(cfg.outputFile, h);
  console.log("\n!!! You have just rung the bell of BTC Lottery !!!");
  return true;
}

function defaultState() {
  return { totalCount: 0, totalHits: 0, totalErrors: 0, totalUptimeMs: 0, runs: 0, endpointStats: {} };
}

function loadState(file) {
  if (!file || !existsSync(file)) return defaultState();
  try {
    const s = JSON.parse(readFileSync(file, "utf8"));
    return { ...defaultState(), ...s, endpointStats: s.endpointStats ?? {} };
  } catch {
    return defaultState();
  }
}

function saveState(file, state) {
  if (!file) return;
  try {
    const tmp = `${file}.tmp`;
    writeFileSync(tmp, JSON.stringify(state, null, 2));
    renameSync(tmp, file);
  } catch (err) {
    console.log(`\t[state] save failed: ${err.message}`);
  }
}

function normalizeEndpoints(cfg) {
  if (Array.isArray(cfg.endpoints) && cfg.endpoints.length > 0) return cfg.endpoints;
  if (cfg.balanceApiUrl) {
    return [{ type: "blockchain", url: cfg.balanceApiUrl }];
  }
  return [
    { type: "blockchain", url: "https://blockchain.info/balance?active=" },
    { type: "blockstream", url: "https://blockstream.info/api/address/" },
  ];
}

function applyEnvOverrides(cfg) {
  const env = process.env;
  const num = (k, target) => { if (env[k] !== undefined && env[k] !== "") cfg[target] = Number(env[k]); };
  const bool = (k, target) => { if (env[k] !== undefined) cfg[target] = env[k] === "true" || env[k] === "1"; };
  const str = (k, target) => { if (env[k] !== undefined && env[k] !== "") cfg[target] = env[k]; };
  num("WORKER_COUNT", "workerCount");
  num("PER_ADDRESS_DELAY_MS", "perAddressDelayMs");
  num("JITTER_MS", "jitterMs");
  num("ROUND_PAUSE_MS", "roundPauseMs");
  num("ADDRESSES_PER_ROUND", "addressesPerRound");
  num("ERROR_BACKOFF_MS", "errorBackoffMs");
  num("REQUEST_TIMEOUT_MS", "requestTimeoutMs");
  num("WORK_INTERVAL_MINUTES", "workIntervalMinutes");
  num("REST_PAUSE_MINUTES", "restPauseMinutes");
  num("STATS_INTERVAL_MS", "statsIntervalMs");
  num("BACKUP_INTERVAL_MS", "backupIntervalMs");
  num("BATCH_KEYPAIRS", "batchKeypairs");
  num("BATCH_CHUNK_SIZE", "batchChunkSize");
  num("RATE_LIMIT_COOLDOWN_MS", "rateLimitCooldownMs");
  str("ENDPOINT_STRATEGY", "endpointStrategy");
  str("OUTPUT_FILE", "outputFile");
  str("STATE_FILE", "stateFile");
  bool("VERBOSE", "verbose");
  bool("PAUSE_ON_HIT", "pauseOnHit");
  return cfg;
}

function normalizeAddressTypes(cfg) {
  const def = { uncompressed: true, compressed: true, segwit: true, nestedSegwit: true, multisig: true };
  if (cfg.addressTypes && typeof cfg.addressTypes === "object") {
    return { ...def, ...cfg.addressTypes };
  }
  if (cfg.checkMultisig === false) def.multisig = false;
  return def;
}

async function runMain() {
  const cfg = applyEnvOverrides(loadConfig());
  cfg.endpoints = normalizeEndpoints(cfg);
  cfg.addressTypes = normalizeAddressTypes(cfg);
  cfg.requestTimeoutMs = cfg.requestTimeoutMs ?? 10000;
  cfg.backupIntervalMs = cfg.backupIntervalMs ?? 3600000;
  cfg.batchKeypairs = Math.max(1, cfg.batchKeypairs ?? 1);
  cfg.batchChunkSize = Math.max(1, cfg.batchChunkSize ?? 50);
  cfg.rateLimitCooldownMs = cfg.rateLimitCooldownMs ?? 60000;
  if (!Object.values(cfg.addressTypes).some(Boolean)) {
    console.error("Configuration error: at least one address type must be enabled in config.json -> addressTypes.");
    process.exit(1);
  }
  const stateFile = cfg.stateFile ?? "state.json";
  const persisted = loadState(stateFile);
  persisted.runs = (persisted.runs ?? 0) + 1;

  const dline = "═".repeat(78);
  const sline = "─".repeat(78);
  const row = (label, value) =>
    `${C.gray}│${C.reset} ${C.cyan}${pad(label, 18)}${C.reset} ${value}`;
  console.log("");
  console.log(`${C.yellow}${dline}${C.reset}`);
  console.log(`${C.bold}            BTC LOTTERY — multithreaded address scanner${C.reset}`);
  console.log(`${C.yellow}${dline}${C.reset}`);
  console.log(row("Workers",         cfg.workerCount));
  console.log(row("Delay / address", `${cfg.perAddressDelayMs} ms${(cfg.jitterMs ?? 0) > 0 ? ` ± ${cfg.jitterMs} ms jitter` : ""}`));
  console.log(row("Round pause",     `${cfg.roundPauseMs} ms (every ${cfg.addressesPerRound * cfg.workerCount} addresses)`));
  console.log(row("Stats interval",  `${cfg.statsIntervalMs ?? 60000} ms`));
  const enabledTypes = Object.entries(cfg.addressTypes)
    .filter(([, v]) => v).map(([k]) => k).join(", ") || "(none)";
  console.log(row("Address types",   enabledTypes));
  console.log(row("Pause on hit",    cfg.pauseOnHit ? `${C.green}ON${C.reset}` : `${C.dim}off${C.reset}`));
  if ((cfg.workIntervalMinutes ?? 0) > 0 && (cfg.restPauseMinutes ?? 0) > 0) {
    console.log(row("Cooldown cycle", `${cfg.workIntervalMinutes} min on / ${cfg.restPauseMinutes} min off`));
  }
  console.log(row("Output file",     cfg.outputFile));
  console.log(row("State file",      stateFile));
  console.log(row("Endpoints",       cfg.endpoints.map((e) => e.type).join(cfg.endpointStrategy === "round-robin" ? " ⇄ " : cfg.endpointStrategy === "random" ? " ? " : " → ")));
  console.log(row("Endpoint strategy", cfg.endpointStrategy ?? "failover"));
  console.log(row("Batch keypairs",  `${cfg.batchKeypairs} per request (chunk ≤ ${cfg.batchChunkSize} addrs)`));
  console.log(row("Rate-limit cool", `${cfg.rateLimitCooldownMs / 1000}s on HTTP 429`));
  console.log(row("Run",             `#${persisted.runs}`));
  console.log(row("Cumulative",
    `total=${persisted.totalCount} hits=${persisted.totalHits} errors=${persisted.totalErrors} uptime=${(persisted.totalUptimeMs / 60000).toFixed(1)}min`));
  console.log(`${C.yellow}${dline}${C.reset}`);
  console.log(`${C.gray}${sline}${C.reset}\n`);

  const stats = {
    count: 0,
    errors: 0,
    hits: 0,
    lastSnapshotCount: 0,
    lastSnapshotAt: Date.now(),
    endpoints: {},
  };
  function bumpEndpoint(snap) {
    for (const [name, val] of Object.entries(snap)) {
      const slot = stats.endpoints[name] ?? (stats.endpoints[name] = { ok: 0, err: 0 });
      slot.ok += val.ok;
      slot.err += val.err;
    }
  }
  const startedAt = Date.now();

  function snapshotPersisted() {
    const mergedEp = {};
    for (const k of new Set([...Object.keys(persisted.endpointStats ?? {}), ...Object.keys(stats.endpoints)])) {
      const p = persisted.endpointStats?.[k] ?? { ok: 0, err: 0 };
      const s = stats.endpoints[k] ?? { ok: 0, err: 0 };
      mergedEp[k] = { ok: p.ok + s.ok, err: p.err + s.err };
    }
    return {
      totalCount: persisted.totalCount + stats.count,
      totalHits: persisted.totalHits + stats.hits,
      totalErrors: persisted.totalErrors + stats.errors,
      totalUptimeMs: persisted.totalUptimeMs + (Date.now() - startedAt),
      runs: persisted.runs,
      endpointStats: mergedEp,
    };
  }

  setInterval(() => saveState(stateFile, snapshotPersisted()), 30000).unref();
  setInterval(() => {
    saveState(`${stateFile}.backup`, snapshotPersisted());
  }, cfg.backupIntervalMs).unref();
  const pauseEvery = cfg.addressesPerRound * cfg.workerCount;
  const statsIntervalMs = (cfg.statsIntervalMs ?? 60000);

  if (statsIntervalMs > 0) {
    setInterval(() => {
      const now = Date.now();
      const totalElapsedMin = (now - startedAt) / 60000;
      const windowMin = (now - stats.lastSnapshotAt) / 60000;
      const windowDelta = stats.count - stats.lastSnapshotCount;
      const windowRate = windowMin > 0 ? (windowDelta / windowMin).toFixed(1) : "0.0";
      const overallRate = totalElapsedMin > 0 ? (stats.count / totalElapsedMin).toFixed(1) : "0.0";
      const line = "─".repeat(78);
      const epParts = Object.entries(stats.endpoints).map(([name, s]) => {
        const total = s.ok + s.err;
        const errRate = total > 0 ? ((s.err / total) * 100).toFixed(0) : "0";
        const errCol = s.err === 0 ? C.green : (s.err / Math.max(1, total) > 0.2 ? "\x1b[31m" : C.yellow);
        return `${C.cyan}${name}${C.reset} ${s.ok}ok/${errCol}${s.err}err${C.reset} (${errRate}%)`;
      }).join("  ");
      console.log(
        `\n${C.yellow}${line}${C.reset}\n` +
          `${C.bold} STATS${C.reset}  ` +
          `${C.cyan}total${C.reset} ${stats.count}  ` +
          `${C.cyan}hits${C.reset} ${stats.hits}  ` +
          `${C.cyan}errors${C.reset} ${stats.errors}  ` +
          `${C.cyan}rate${C.reset} ${windowRate}/min (avg ${overallRate}/min)  ` +
          `${C.cyan}uptime${C.reset} ${totalElapsedMin.toFixed(1)}min` +
          (epParts ? `\n ENDPOINTS  ${epParts}` : "") +
          `\n${C.yellow}${line}${C.reset}\n`,
      );
      stats.lastSnapshotCount = stats.count;
      stats.lastSnapshotAt = now;
    }, statsIntervalMs).unref();
  }

  const workers = [];
  let stopping = false;

  function printFinalStats(reason) {
    const totalElapsedMin = (Date.now() - startedAt) / 60000;
    const overallRate = totalElapsedMin > 0 ? (stats.count / totalElapsedMin).toFixed(1) : "0.0";
    const snap = snapshotPersisted();
    console.log(
      `\n\t==== FINAL STATS (${reason}) ==== this run: total=${stats.count} hits=${stats.hits} errors=${stats.errors} | rate=${overallRate}/min | uptime=${totalElapsedMin.toFixed(1)}min\n` +
        `\t==== CUMULATIVE (${snap.runs} runs) ==== total=${snap.totalCount} hits=${snap.totalHits} errors=${snap.totalErrors} uptime=${(snap.totalUptimeMs / 60000).toFixed(1)}min\n`,
    );
  }

  async function stopAll(reason) {
    if (stopping) return;
    stopping = true;
    console.log(`\n\t!!! ${reason} — stopping all workers ...\n`);
    await Promise.all(workers.map((w) => w.terminate().catch(() => {})));
    saveState(stateFile, snapshotPersisted());
    printFinalStats(reason);
    console.log("\t All workers stopped. State saved. Check the output file for details.");
    process.exit(0);
  }

  for (const sig of ["SIGINT", "SIGTERM"]) {
    process.on(sig, () => {
      stopAll(sig).catch(() => process.exit(1));
    });
  }

  // pausedByCycle tracks the last pause/resume command sent to workers,
  // so re-spawned workers can be brought back to the same paused state.
  let pausedByCycle = false;

  function spawnWorker(id) {
    const worker = new Worker(SELF, { workerData: { config: cfg, id } });
    if (pausedByCycle) {
      // Newly spawned workers default to running; immediately pause if cycle is in rest mode.
      worker.postMessage({ type: "pause" });
    }

    worker.on("message", async (msg) => {
      if (stopping) return;
      if (msg.type === "endpointStats") {
        bumpEndpoint(msg.snap);
        return;
      }
      if (msg.type === "error") {
        stats.errors += 1;
        console.log(`\t[worker ${msg.workerId}] error: ${msg.message}`);
        return;
      }
      stats.count += 1;
      const count = stats.count;
      const hit = handleHit(cfg, msg.kp, msg.multi, msg.balances);
      if (hit) {
        stats.hits += 1;
        saveState(stateFile, snapshotPersisted());
        if (cfg.pauseOnHit) {
          await stopAll("HIT FOUND");
          return;
        }
      }
      if (!hit && cfg.verbose) {
        printRow(count, msg.workerId, msg.kp, msg.multi, msg.balances, cfg.addressTypes);
      }

      if (cfg.roundPauseMs > 0 && count % pauseEvery === 0) {
        const elapsed = ((Date.now() - startedAt) / 1000).toFixed(1);
        console.log(
          `\n\t${count} addresses checked in ${elapsed}s — pausing ${cfg.roundPauseMs / 1000}s ...\n`,
        );
        await sleep(cfg.roundPauseMs);
        console.log("\t Resuming ...\n");
      }
    });

    worker.on("error", (err) => console.error(`Worker ${id} fatal:`, err));
    worker.on("exit", (code) => {
      if (stopping) return;
      console.log(`\t[supervisor] worker ${id} exited with code ${code} — respawning in 2s ...`);
      const idx = workers.indexOf(worker);
      setTimeout(() => {
        if (stopping) return;
        const fresh = spawnWorker(id);
        if (idx >= 0) workers[idx] = fresh;
        else workers.push(fresh);
      }, 2000);
    });

    return worker;
  }

  const stagger = Math.floor(cfg.perAddressDelayMs / Math.max(1, cfg.workerCount));
  for (let i = 0; i < cfg.workerCount; i++) {
    if (i > 0) await sleep(stagger);
    if (stopping) break;
    workers.push(spawnWorker(i + 1));
  }

  // Cooldown cycle: run for workIntervalMinutes, then pause all workers for restPauseMinutes.
  const workIntervalMs = (cfg.workIntervalMinutes ?? 0) * 60000;
  const restPauseMs = (cfg.restPauseMinutes ?? 0) * 60000;
  if (workIntervalMs > 0 && restPauseMs > 0) {
    (async () => {
      while (!stopping) {
        await sleep(workIntervalMs);
        if (stopping) return;
        const line = "─".repeat(78);
        console.log(
          `\n${C.yellow}${line}${C.reset}\n` +
          `${C.bold} COOLDOWN${C.reset}  pausing all workers for ${restPauseMs / 60000} min ` +
          `(work cycle = ${workIntervalMs / 60000} min)\n${C.yellow}${line}${C.reset}\n`,
        );
        pausedByCycle = true;
        for (const w of workers) w.postMessage({ type: "pause" });
        await sleep(restPauseMs);
        if (stopping) return;
        console.log(
          `\n${C.yellow}${line}${C.reset}\n` +
          `${C.bold} RESUMING${C.reset}  workers continuing for next ${workIntervalMs / 60000} min\n` +
          `${C.yellow}${line}${C.reset}\n`,
        );
        pausedByCycle = false;
        for (const w of workers) w.postMessage({ type: "resume" });
      }
    })().catch((e) => console.error("cycle error:", e));
  }
}

if (isMainThread) {
  runMain().catch((err) => {
    console.error("Fatal:", err);
    process.exit(1);
  });
} else {
  runWorker();
}
