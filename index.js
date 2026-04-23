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
async function getBalances(addresses, endpoints, strategy, epStats, opts) {
  const timeoutMs = opts.requestTimeoutMs;
  const errorBackoffMs = opts.errorBackoffMs;
  let lastErr;

  for (const endpoint of orderEndpoints(endpoints, strategy)) {
    const slot = epStats[endpoint.type] ?? (epStats[endpoint.type] = { ok: 0, err: 0 });
    const parser = ENDPOINT_PARSERS[endpoint.type];
    const supportsBatch = ENDPOINT_BATCH[endpoint.type];
    const groups = supportsBatch ? [addresses] : addresses.map((a) => [a]);

    try {
      const merged = {};
      for (const group of groups) {
        const url = buildEndpointUrl(endpoint, group);
        let res;
        try {
          res = await fetchOnce(url, timeoutMs);
        } catch (err) {
          // 1 retry for transient failures (timeout, network, 5xx). Skip retry on 4xx (except 429).
          const transient =
            !err.status || err.status >= 500 || err.status === 429 || err.name === "TimeoutError" || err.name === "AbortError";
          if (!transient) throw err;
          const wait = err.status === 429 ? errorBackoffMs : Math.min(errorBackoffMs, 3000);
          await sleep(wait);
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
  };

  while (true) {
    if (paused) {
      while (paused) await sleep(1000);
    }
    try {
      const kp = makeKeyPair();
      const multi = enabled.multisig ? makeMultisigAddress() : null;

      const tasks = [];
      const balances = {
        uncompressed: 0, compressed: 0, segwit: 0, nestedSegwit: 0, multi: 0,
      };
      if (enabled.uncompressed) tasks.push(["uncompressed", kp.uncompressedAddress]);
      if (enabled.compressed)   tasks.push(["compressed",   kp.compressedAddress]);
      if (enabled.segwit)       tasks.push(["segwit",       kp.segwitAddress]);
      if (enabled.nestedSegwit) tasks.push(["nestedSegwit", kp.nestedSegwitAddress]);
      if (multi)                tasks.push(["multi",        multi.address]);

      const addrs = tasks.map(([, addr]) => addr);
      const balMap = await getBalances(addrs, cfg.endpoints, cfg.endpointStrategy, epStats, opts);
      tasks.forEach(([key, addr]) => { balances[key] = Number(balMap[addr] ?? 0); });

      parentPort.postMessage({ type: "result", workerId: id, kp, multi, balances });
      flushEp();
    } catch (err) {
      parentPort.postMessage({ type: "error", workerId: id, message: err.message });
      flushEp();
      await sleep(cfg.errorBackoffMs);
    }
    const jitter = cfg.jitterMs ?? 0;
    const wait = jitter > 0
      ? cfg.perAddressDelayMs + Math.floor((Math.random() * 2 - 1) * jitter)
      : cfg.perAddressDelayMs;
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

function appendHit(file, text) {
  appendFileSync(file, text);
}

function handleHit(cfg, kp, multi, balances) {
  const hits = [];
  if (balances.uncompressed > 0) {
    hits.push(
      `Uncompressed Private Key (WIF)\t: ${kp.wifUncompressed}\n` +
        ` Uncompressed Address\t: ${kp.uncompressedAddress}\n` +
        ` Balance: ${balances.uncompressed}\n\n`,
    );
  }
  if (balances.compressed > 0) {
    hits.push(
      `Compressed Private Key (WIF)\t: ${kp.wifCompressed}\n` +
        ` Compressed Address\t: ${kp.compressedAddress}\n` +
        ` Balance: ${balances.compressed}\n\n`,
    );
  }
  if (balances.segwit > 0) {
    hits.push(
      `Compressed Private Key (WIF)\t: ${kp.wifCompressed}\n` +
        ` SegWit (bech32) Address\t: ${kp.segwitAddress}\n` +
        ` Balance: ${balances.segwit}\n\n`,
    );
  }
  if (balances.nestedSegwit > 0) {
    hits.push(
      `Compressed Private Key (WIF)\t: ${kp.wifCompressed}\n` +
        ` P2SH-SegWit Address\t: ${kp.nestedSegwitAddress}\n` +
        ` Balance: ${balances.nestedSegwit}\n\n`,
    );
  }
  if (multi && balances.multi > 0) {
    hits.push(
      `Multisig Address\t: ${multi.address}\n` +
        ` Multisig Private Keys (WIF)\t: ${multi.privateKeysWif.join(", ")}\n` +
        ` Balance: ${balances.multi}\n\n`,
    );
  }
  if (hits.length === 0) return false;
  for (const h of hits) appendHit(cfg.outputFile, h);
  console.log("\n!!! You have just rung the bell of BTC Lottery !!!");
  return true;
}

function loadState(file) {
  if (!file || !existsSync(file)) {
    return { totalCount: 0, totalHits: 0, totalErrors: 0, totalUptimeMs: 0, runs: 0 };
  }
  try {
    return JSON.parse(readFileSync(file, "utf8"));
  } catch {
    return { totalCount: 0, totalHits: 0, totalErrors: 0, totalUptimeMs: 0, runs: 0 };
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

function normalizeAddressTypes(cfg) {
  const def = { uncompressed: true, compressed: true, segwit: true, nestedSegwit: true, multisig: true };
  if (cfg.addressTypes && typeof cfg.addressTypes === "object") {
    return { ...def, ...cfg.addressTypes };
  }
  if (cfg.checkMultisig === false) def.multisig = false;
  return def;
}

async function runMain() {
  const cfg = loadConfig();
  cfg.endpoints = normalizeEndpoints(cfg);
  cfg.addressTypes = normalizeAddressTypes(cfg);
  cfg.requestTimeoutMs = cfg.requestTimeoutMs ?? 10000;
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
    return {
      totalCount: persisted.totalCount + stats.count,
      totalHits: persisted.totalHits + stats.hits,
      totalErrors: persisted.totalErrors + stats.errors,
      totalUptimeMs: persisted.totalUptimeMs + (Date.now() - startedAt),
      runs: persisted.runs,
    };
  }

  setInterval(() => saveState(stateFile, snapshotPersisted()), 30000).unref();
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

  const stagger = Math.floor(cfg.perAddressDelayMs / Math.max(1, cfg.workerCount));
  for (let i = 0; i < cfg.workerCount; i++) {
    if (i > 0) await sleep(stagger);
    if (stopping) break;
    const worker = new Worker(SELF, { workerData: { config: cfg, id: i + 1 } });
    workers.push(worker);

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

    worker.on("error", (err) => console.error(`Worker ${i + 1} fatal:`, err));
    worker.on("exit", (code) =>
      console.log(`Worker ${i + 1} exited with code ${code}`),
    );
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
        for (const w of workers) w.postMessage({ type: "pause" });
        await sleep(restPauseMs);
        if (stopping) return;
        console.log(
          `\n${C.yellow}${line}${C.reset}\n` +
          `${C.bold} RESUMING${C.reset}  workers continuing for next ${workIntervalMs / 60000} min\n` +
          `${C.yellow}${line}${C.reset}\n`,
        );
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
