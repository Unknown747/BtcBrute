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
import * as readline from "node:readline/promises";
import * as bitcoin from "bitcoinjs-lib";
import * as ecc from "tiny-secp256k1";
import { ECPairFactory } from "ecpair";
import * as bip39 from "bip39";
import { BIP32Factory } from "bip32";
// Note: Node 20's built-in fetch already uses a keep-alive pool by default.
// We previously installed a custom undici Agent here for longer keep-alive
// timeouts, but it caused fetch to hang inside worker threads on this Node
// version. Default dispatcher is fine for our request rate.

bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);
const bip32 = BIP32Factory(ecc);
const NETWORK = bitcoin.networks.bitcoin;
const SELF = fileURLToPath(import.meta.url);

// BIP path -> (pubkey -> address) mapping. BIP44 = legacy P2PKH,
// BIP49 = nested SegWit (P2SH-P2WPKH), BIP84 = native SegWit (P2WPKH).
const BIP_PATHS = {
  bip44: { coin: "44'/0'/0'/0", type: "bip44-p2pkh", toAddress: (pub) =>
    bitcoin.payments.p2pkh({ pubkey: pub, network: NETWORK }).address },
  bip49: { coin: "49'/0'/0'/0", type: "bip49-p2sh-p2wpkh", toAddress: (pub) =>
    bitcoin.payments.p2sh({
      redeem: bitcoin.payments.p2wpkh({ pubkey: pub, network: NETWORK }),
      network: NETWORK,
    }).address },
  bip84: { coin: "84'/0'/0'/0", type: "bip84-p2wpkh", toAddress: (pub) =>
    bitcoin.payments.p2wpkh({ pubkey: pub, network: NETWORK }).address },
};

function makeMnemonicSet(opts) {
  // Returns { mnemonic, derivations: [{type, path, address, wif}, ...] }.
  // Generates one fresh mnemonic and walks the requested BIP paths +
  // address indices, producing N×paths.length addresses to check.
  const strength = opts.strength === 256 ? 256 : 128; // 128=12 words, 256=24
  const mnemonic = bip39.generateMnemonic(strength);
  const seed = bip39.mnemonicToSeedSync(mnemonic);
  const root = bip32.fromSeed(seed, NETWORK);
  const paths = Array.isArray(opts.paths) && opts.paths.length > 0
    ? opts.paths.filter((p) => BIP_PATHS[p])
    : ["bip44", "bip49", "bip84"];
  const count = Math.max(1, opts.addressesPerPath ?? 5);
  const derivations = [];
  for (const p of paths) {
    const def = BIP_PATHS[p];
    for (let i = 0; i < count; i++) {
      const path = `m/${def.coin}/${i}`;
      const node = root.derivePath(path);
      const wif = ECPair.fromPrivateKey(node.privateKey, { network: NETWORK, compressed: true }).toWIF();
      derivations.push({
        type: def.type,
        path,
        address: def.toAddress(node.publicKey),
        wif,
      });
    }
  }
  return { mnemonic, derivations };
}

function loadConfig() {
  const raw = readFileSync(new URL("./config.json", import.meta.url), "utf8");
  return JSON.parse(raw);
}

const SECP256K1_N = BigInt(
  "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
);

function bigIntToHex64(n) {
  return n.toString(16).padStart(64, "0");
}

function keyPairFromBigInt(n) {
  if (n <= 0n || n >= SECP256K1_N) {
    throw new Error(`private key out of range: 0x${bigIntToHex64(n)}`);
  }
  const buf = Buffer.from(bigIntToHex64(n), "hex");
  const compressedKey = ECPair.fromPrivateKey(buf, { network: NETWORK, compressed: true });
  const uncompressedKey = ECPair.fromPrivateKey(buf, { network: NETWORK, compressed: false });
  const { address: compressedAddress } = bitcoin.payments.p2pkh({
    pubkey: compressedKey.publicKey, network: NETWORK,
  });
  const { address: uncompressedAddress } = bitcoin.payments.p2pkh({
    pubkey: uncompressedKey.publicKey, network: NETWORK,
  });
  const { address: segwitAddress } = bitcoin.payments.p2wpkh({
    pubkey: compressedKey.publicKey, network: NETWORK,
  });
  const { address: nestedSegwitAddress } = bitcoin.payments.p2sh({
    redeem: bitcoin.payments.p2wpkh({ pubkey: compressedKey.publicKey, network: NETWORK }),
    network: NETWORK,
  });
  return {
    privateKeyHex: bigIntToHex64(n),
    wifCompressed: compressedKey.toWIF(),
    wifUncompressed: uncompressedKey.toWIF(),
    compressedAddress,
    uncompressedAddress,
    segwitAddress,
    nestedSegwitAddress,
  };
}

function loadRangeCursor(file, fallback) {
  try {
    if (!existsSync(file)) return fallback;
    const txt = readFileSync(file, "utf8").trim();
    if (/^[0-9a-fA-F]{1,64}$/.test(txt)) {
      const n = BigInt("0x" + txt);
      if (n > 0n && n < SECP256K1_N) return n;
    }
  } catch { /* ignore */ }
  return fallback;
}

function saveRangeCursor(file, n) {
  try { writeFileSync(file, bigIntToHex64(n) + "\n"); } catch { /* ignore */ }
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
function newSlot() {
  return { ok: 0, err: 0, rl429: 0, totalMs: 0, msCount: 0 };
}

async function getBalances(addresses, endpoints, strategy, epStats, opts, cooldownUntil, batchChunkSize) {
  const timeoutMs = opts.requestTimeoutMs;
  const errorBackoffMs = opts.errorBackoffMs;
  const rateLimitBackoffMs = opts.rateLimitBackoffMs ?? 5000;
  const rateLimitCooldownMs = opts.rateLimitCooldownMs ?? 60000;
  const chunkSize = Math.max(1, batchChunkSize ?? 50);
  let lastErr;

  const ordered = orderEndpoints(filterCooling(endpoints, cooldownUntil), strategy);
  for (const endpoint of ordered) {
    const slot = epStats[endpoint.type] ?? (epStats[endpoint.type] = newSlot());
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
        const t0 = Date.now();
        try {
          res = await fetchOnce(url, timeoutMs);
        } catch (err) {
          if (err.status === 429) {
            slot.rl429 += 1;
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
        slot.totalMs += Date.now() - t0;
        slot.msCount += 1;
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
  // currentDelay starts from config but can be retuned at runtime via
  // {type:"setDelay"} messages from the parent (auto-throttle).
  let currentDelay = cfg.perAddressDelayMs;
  let rangeResolver = null;
  parentPort.on("message", (m) => {
    if (m?.type === "pause") paused = true;
    else if (m?.type === "resume") paused = false;
    else if (m?.type === "setDelay" && Number.isFinite(m.value)) {
      currentDelay = Math.max(0, m.value);
    } else if (m?.type === "rangeChunk" && rangeResolver) {
      const r = rangeResolver; rangeResolver = null; r(m);
    }
  });
  function requestRangeChunk(count) {
    return new Promise((resolve) => {
      rangeResolver = resolve;
      parentPort.postMessage({ type: "requestRange", workerId: id, count });
    });
  }
  const flushEp = () => {
    const snap = {};
    for (const k of Object.keys(epStats)) {
      const s = epStats[k];
      snap[k] = { ok: s.ok, err: s.err, rl429: s.rl429, totalMs: s.totalMs, msCount: s.msCount };
      s.ok = 0; s.err = 0; s.rl429 = 0; s.totalMs = 0; s.msCount = 0;
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
  const batchKeypairs = Math.max(0, cfg.batchKeypairs ?? 1);
  const batchChunkSize = Math.max(1, cfg.batchChunkSize ?? 50);
  const bip39Cfg = cfg.bip39 ?? {};
  const bip39Enabled = enabled.bip39 === true && cfg.mode !== "range";
  const bip39PerBatch = Math.max(0, bip39Cfg.mnemonicsPerBatch ?? 1);
  const rangeMode = cfg.mode === "range";

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
      // Generate a batch of items and build the combined task list so we can
      // resolve all of their balances in one (or few) HTTP request(s).
      // Each item is either a random keypair (kind="kp") or an HD wallet
      // generated from a fresh BIP39 mnemonic (kind="mn") with multiple
      // derived addresses across BIP44/49/84 paths.
      const items = [];
      const allAddrs = [];
      if (rangeMode) {
        // Pull the next slice of sequential keys from the parent. The parent
        // owns the cursor and persists it to disk so we can resume later.
        const chunk = await requestRangeChunk(batchKeypairs);
        let n = BigInt("0x" + chunk.startHex);
        for (let i = 0; i < chunk.count; i++) {
          let kp;
          try { kp = keyPairFromBigInt(n); }
          catch { n += 1n; continue; }
          const tasks = [];
          if (enabled.uncompressed) tasks.push(["uncompressed", kp.uncompressedAddress]);
          if (enabled.compressed)   tasks.push(["compressed",   kp.compressedAddress]);
          if (enabled.segwit)       tasks.push(["segwit",       kp.segwitAddress]);
          if (enabled.nestedSegwit) tasks.push(["nestedSegwit", kp.nestedSegwitAddress]);
          items.push({ kind: "kp", kp, multi: null, tasks });
          for (const [, a] of tasks) allAddrs.push(a);
          n += 1n;
        }
      } else {
        for (let i = 0; i < batchKeypairs; i++) {
          const kp = makeKeyPair();
          const multi = enabled.multisig ? makeMultisigAddress() : null;
          const tasks = [];
          if (enabled.uncompressed) tasks.push(["uncompressed", kp.uncompressedAddress]);
          if (enabled.compressed)   tasks.push(["compressed",   kp.compressedAddress]);
          if (enabled.segwit)       tasks.push(["segwit",       kp.segwitAddress]);
          if (enabled.nestedSegwit) tasks.push(["nestedSegwit", kp.nestedSegwitAddress]);
          if (multi)                tasks.push(["multi",        multi.address]);
          items.push({ kind: "kp", kp, multi, tasks });
          for (const [, a] of tasks) allAddrs.push(a);
        }
        if (bip39Enabled && bip39PerBatch > 0) {
          for (let i = 0; i < bip39PerBatch; i++) {
            const set = makeMnemonicSet(bip39Cfg);
            items.push({ kind: "mn", mnemonic: set.mnemonic, derivations: set.derivations });
            for (const d of set.derivations) allAddrs.push(d.address);
          }
        }
      }
      if (items.length === 0) {
        // Nothing to do this round (e.g. mnemonic mode with batchKeypairs=0
        // and bip39 disabled); fall through to the per-iteration delay.
        await sleep(currentDelay);
        continue;
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

      for (const item of items) {
        if (item.kind === "kp") {
          const balances = {
            uncompressed: 0, compressed: 0, segwit: 0, nestedSegwit: 0, multi: 0,
          };
          item.tasks.forEach(([key, addr]) => { balances[key] = Number(balMap[addr] ?? 0); });
          parentPort.postMessage({
            type: "result", workerId: id, kp: item.kp, multi: item.multi, balances,
          });
        } else {
          // mnemonic item: attach balance to each derivation
          const derivations = item.derivations.map((d) => ({
            ...d, balance: Number(balMap[d.address] ?? 0),
          }));
          parentPort.postMessage({
            type: "mnemonicResult", workerId: id,
            mnemonic: item.mnemonic, derivations,
          });
        }
      }
      flushEp();
    } catch (err) {
      parentPort.postMessage({ type: "error", workerId: id, message: err.message });
      flushEp();
      await sleep(cfg.errorBackoffMs);
    }
    // perAddressDelayMs is per *keypair*; scale by batch size so request
    // pacing stays roughly the same regardless of batch size. Auto-throttle
    // mutates currentDelay at runtime based on observed error rate.
    const jitter = cfg.jitterMs ?? 0;
    const base = currentDelay * batchKeypairs;
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

function formatDuration(minutes) {
  // Human-readable duration from minutes; degrades gracefully for huge ETAs
  // (range scans can easily span centuries — show that honestly).
  if (!Number.isFinite(minutes) || minutes < 0) return "—";
  if (minutes < 1) return `${Math.max(1, Math.round(minutes * 60))}s`;
  const m = Math.floor(minutes);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ${m % 60}m`;
  const d = Math.floor(h / 24);
  if (d < 365) return `${d}d ${h % 24}h`;
  const y = d / 365;
  if (y < 1000) return `${y.toFixed(1)}y`;
  if (y < 1e6) return `${(y / 1000).toFixed(1)}Ky`;
  if (y < 1e9) return `${(y / 1e6).toFixed(1)}My`;
  return `${(y / 1e9).toExponential(1)}Gy`;
}

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

function printMnemonicRow(count, workerId, mnemonic, derivations) {
  // Compact mnemonic banner: show first 3 + last 2 words to save console
  // real estate while still letting you eyeball uniqueness in logs.
  const words = mnemonic.split(" ");
  const preview = words.length <= 6
    ? words.join(" ")
    : `${words.slice(0, 3).join(" ")} … ${words.slice(-2).join(" ")} (${words.length}w)`;
  const header = `${C.gray}┌─ ${C.bold}#${padLeft(count, 6)}${C.reset}${C.gray} ─ worker ${workerId} ─ ${C.cyan}mnemonic${C.gray} ${preview} ${"─".repeat(Math.max(0, 30 - preview.length))}${C.reset}`;
  console.log(header);
  for (let i = 0; i < derivations.length; i++) {
    const d = derivations[i];
    const branch = i === derivations.length - 1 ? "└" : "├";
    const balColor = d.balance > 0 ? C.green + C.bold : C.dim;
    console.log(
      `${C.gray}${branch}─${C.reset} ${C.cyan}${pad(d.type, 18)}${C.reset} ${pad(d.address, 44)} ${balColor}${padLeft(d.balance, 10)}${C.reset} sat`,
    );
  }
}

function handleMnemonicHit(cfg, mnemonic, derivations) {
  const ts = new Date().toISOString();
  const hits = derivations.filter((d) => d.balance > 0);
  if (hits.length === 0) return false;
  for (const h of hits) {
    appendHitLine(cfg.outputFile, {
      ts, source: "bip39", type: h.type, address: h.address, balance: h.balance,
      derivationPath: h.path, wif: h.wif, mnemonic,
    });
  }
  console.log("\n!!! You have just rung the bell of BTC Lottery !!! (BIP39)");
  return true;
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
  // Range overrides: accept hex with or without 0x prefix, normalise to lower
  // case so downstream regex / BigInt parsing works uniformly.
  const hex = (k, target) => {
    if (env[k] === undefined || env[k] === "") return;
    const v = env[k].trim().toLowerCase().replace(/^0x/, "");
    if (!/^[0-9a-f]{1,64}$/.test(v)) {
      console.error(`Configuration error: ${k} must be 1–64 hex chars (with optional 0x), got "${env[k]}"`);
      process.exit(1);
    }
    cfg.range = cfg.range ?? {};
    cfg.range[target] = v;
  };
  hex("RANGE_START", "start");
  hex("RANGE_END", "end");
  str("RANGE_FILE", "rangeFile");
  return cfg;
}

function normalizeAddressTypes(cfg) {
  const def = { uncompressed: true, compressed: true, segwit: true, nestedSegwit: true, multisig: true, bip39: false };
  if (cfg.addressTypes && typeof cfg.addressTypes === "object") {
    return { ...def, ...cfg.addressTypes };
  }
  if (cfg.checkMultisig === false) def.multisig = false;
  return def;
}

async function promptMode(cfg) {
  const map = {
    "1": "privkey", "privkey": "privkey", "p": "privkey",
    "2": "mnemonic", "mnemonic": "mnemonic", "m": "mnemonic",
    "3": "range", "range": "range", "r": "range",
  };
  const fromEnv = (process.env.MODE || "").toLowerCase().trim();
  if (map[fromEnv]) return map[fromEnv];
  if (cfg.mode && map[String(cfg.mode).toLowerCase()]) return map[String(cfg.mode).toLowerCase()];
  if (!process.stdin.isTTY) {
    // Non-interactive (no terminal attached) — default to privkey.
    return "privkey";
  }
  console.log("");
  console.log(`${C.yellow}Select scan mode:${C.reset}`);
  console.log("  1) Random PrivateKey   (fast brute-force)");
  console.log("  2) Random BIP39 Mnemonic   (12-word, derives BIP44/49/84)");
  console.log(`  3) Sequential Range   (resumes from ${C.cyan}${cfg.rangeFile ?? "Last_Scan.txt"}${C.reset})`);
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  let choice;
  try { choice = (await rl.question("Choice [1/2/3] (default 1): ")).trim().toLowerCase(); }
  finally { rl.close(); }
  return map[choice] || "privkey";
}

async function runMain() {
  const cfg = applyEnvOverrides(loadConfig());
  cfg.endpoints = normalizeEndpoints(cfg);
  cfg.addressTypes = normalizeAddressTypes(cfg);
  cfg.requestTimeoutMs = cfg.requestTimeoutMs ?? 10000;
  cfg.backupIntervalMs = cfg.backupIntervalMs ?? 3600000;
  cfg.batchKeypairs = Math.max(0, cfg.batchKeypairs ?? 1);
  cfg.batchChunkSize = Math.max(1, cfg.batchChunkSize ?? 50);
  cfg.rateLimitCooldownMs = cfg.rateLimitCooldownMs ?? 60000;
  cfg.bip39 = {
    strength: cfg.bip39?.strength ?? 128,
    paths: cfg.bip39?.paths ?? ["bip44", "bip49", "bip84"],
    addressesPerPath: Math.max(1, cfg.bip39?.addressesPerPath ?? 5),
    mnemonicsPerBatch: Math.max(0, cfg.bip39?.mnemonicsPerBatch ?? 1),
  };
  cfg.rangeFile = cfg.rangeFile ?? "Last_Scan.txt";
  cfg.range = {
    start: cfg.range?.start ?? "0000000000000000000000000000000000000000000000000000000000000001",
    end: cfg.range?.end ?? null,
  };

  // Interactive mode selection. ENV `MODE=privkey|mnemonic|range` skips the
  // prompt (handy for headless runs); otherwise we ask once on startup.
  const mode = await promptMode(cfg);
  cfg.mode = mode;
  if (mode === "privkey") {
    cfg.addressTypes.bip39 = false;
    if (cfg.batchKeypairs < 1) cfg.batchKeypairs = 1;
  } else if (mode === "mnemonic") {
    cfg.addressTypes.bip39 = true;
    cfg.batchKeypairs = 0;
    if (cfg.bip39.mnemonicsPerBatch < 1) cfg.bip39.mnemonicsPerBatch = 1;
  } else if (mode === "range") {
    cfg.addressTypes.bip39 = false;
    cfg.addressTypes.multisig = false;
    if (cfg.batchKeypairs < 1) cfg.batchKeypairs = 20;
  }

  // Range cursor: BigInt that names the next private key to scan. Loaded from
  // Last_Scan.txt if it exists so a previous run can be resumed exactly.
  let rangeCursor = mode === "range"
    ? loadRangeCursor(cfg.rangeFile, BigInt("0x" + cfg.range.start))
    : null;
  // Optional inclusive upper bound. When the cursor passes it the parent
  // stops handing out work and triggers a clean shutdown.
  // Snapshot of where this run started (used to compute "scanned this run"
  // for the progress line). Cursor advances as workers consume keys.
  const rangeStartAtRun = rangeCursor;
  let rangeEnd = null;
  if (mode === "range" && cfg.range.end) {
    if (!/^[0-9a-fA-F]{1,64}$/.test(cfg.range.end)) {
      console.error(`Configuration error: range.end must be 1–64 hex chars, got "${cfg.range.end}"`);
      process.exit(1);
    }
    rangeEnd = BigInt("0x" + cfg.range.end);
    if (rangeEnd >= SECP256K1_N) rangeEnd = SECP256K1_N - 1n;
    if (rangeEnd < rangeCursor) {
      console.error(`Configuration error: range.end (0x${bigIntToHex64(rangeEnd)}) is before current cursor (0x${bigIntToHex64(rangeCursor)}).`);
      console.error(`Reset by deleting ${cfg.rangeFile} or setting range.start past the end.`);
      process.exit(1);
    }
  }

  // Auto-throttle config (resolved here so it can be shown in the banner).
  const autoTune = cfg.autoTune ?? {};
  const tuneEnabled = autoTune.enabled !== false; // default on
  const minDelay = Math.max(0, autoTune.minDelayMs ?? 200);
  const maxDelay = Math.max(minDelay, autoTune.maxDelayMs ?? 10000);
  const upThreshold = autoTune.upErrorRate ?? 0.10;
  const downThreshold = autoTune.downErrorRate ?? 0.0;
  const upFactor = autoTune.upFactor ?? 1.5;
  const downFactor = autoTune.downFactor ?? 0.9;
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
  console.log(row("Auto-throttle",   tuneEnabled
    ? `${C.green}ON${C.reset} delay ${cfg.perAddressDelayMs}ms (range ${minDelay}–${maxDelay}ms)`
    : `${C.dim}off${C.reset}`));
  console.log(row("BIP39 mnemonic",  cfg.addressTypes.bip39
    ? `${C.green}ON${C.reset} ${cfg.bip39.mnemonicsPerBatch}/batch × ${cfg.bip39.paths.length} paths × ${cfg.bip39.addressesPerPath} addr (${cfg.bip39.strength === 256 ? 24 : 12} words)`
    : `${C.dim}off${C.reset}`));
  const modeLabel = mode === "privkey" ? "Random PrivateKey"
    : mode === "mnemonic" ? "Random BIP39 Mnemonic"
    : `Sequential Range`;
  console.log(row("Scan mode",       `${C.green}${modeLabel}${C.reset}`));
  if (mode === "range") {
    console.log(row("Range cursor",  `${C.cyan}0x${bigIntToHex64(rangeCursor)}${C.reset}  →  ${C.dim}${cfg.rangeFile}${C.reset}`));
    if (rangeEnd !== null) {
      const remaining = rangeEnd - rangeCursor + 1n;
      console.log(row("Range end",   `${C.cyan}0x${bigIntToHex64(rangeEnd)}${C.reset}  (${remaining.toString()} keys remaining)`));
    } else {
      console.log(row("Range end",   `${C.dim}none (scan until stopped)${C.reset}`));
    }
  }
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
    lastSnapshotErrors: 0,
    lastSnapshotAt: Date.now(),
    lastSnapshotCursor: rangeStartAtRun,
    endpoints: {},
    recentErrors: [],   // ring buffer of recent worker error messages
    errorCounts: {},    // tally of error messages for shutdown summary
  };
  const RECENT_ERR_MAX = 20;
  function recordError(message) {
    stats.recentErrors.push({ ts: Date.now(), message });
    if (stats.recentErrors.length > RECENT_ERR_MAX) stats.recentErrors.shift();
    stats.errorCounts[message] = (stats.errorCounts[message] ?? 0) + 1;
  }
  function bumpEndpoint(snap) {
    for (const [name, val] of Object.entries(snap)) {
      const slot = stats.endpoints[name] ?? (stats.endpoints[name] = {
        ok: 0, err: 0, rl429: 0, totalMs: 0, msCount: 0,
      });
      slot.ok += val.ok ?? 0;
      slot.err += val.err ?? 0;
      slot.rl429 += val.rl429 ?? 0;
      slot.totalMs += val.totalMs ?? 0;
      slot.msCount += val.msCount ?? 0;
    }
  }

  // currentDelay is what we last broadcast to workers (mutated by auto-tune).
  let currentDelay = cfg.perAddressDelayMs;
  const startedAt = Date.now();

  function snapshotPersisted() {
    const mergedEp = {};
    for (const k of new Set([...Object.keys(persisted.endpointStats ?? {}), ...Object.keys(stats.endpoints)])) {
      const p = persisted.endpointStats?.[k] ?? { ok: 0, err: 0, rl429: 0 };
      const s = stats.endpoints[k] ?? { ok: 0, err: 0, rl429: 0 };
      mergedEp[k] = {
        ok: (p.ok ?? 0) + (s.ok ?? 0),
        err: (p.err ?? 0) + (s.err ?? 0),
        rl429: (p.rl429 ?? 0) + (s.rl429 ?? 0),
      };
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

  function broadcastDelay(value) {
    for (const w of workers) {
      try { w.postMessage({ type: "setDelay", value }); } catch {}
    }
  }

  if (statsIntervalMs > 0) {
    setInterval(() => {
      const now = Date.now();
      const totalElapsedMin = (now - startedAt) / 60000;
      const windowMin = (now - stats.lastSnapshotAt) / 60000;
      const windowDelta = stats.count - stats.lastSnapshotCount;
      const windowErrDelta = stats.errors - stats.lastSnapshotErrors;
      const windowRate = windowMin > 0 ? (windowDelta / windowMin).toFixed(1) : "0.0";
      const overallRate = totalElapsedMin > 0 ? (stats.count / totalElapsedMin).toFixed(1) : "0.0";

      // Auto-tune: combine worker errors (window) + endpoint failovers (last
      // window we don't track separately, so approximate via overall rates).
      let tuneNote = "";
      if (tuneEnabled) {
        const windowAttempts = windowDelta + windowErrDelta;
        const errRate = windowAttempts > 0 ? windowErrDelta / windowAttempts : 0;
        const prev = currentDelay;
        if (errRate >= upThreshold) {
          currentDelay = Math.min(maxDelay, Math.round(currentDelay * upFactor));
        } else if (errRate <= downThreshold && currentDelay > minDelay) {
          currentDelay = Math.max(minDelay, Math.round(currentDelay * downFactor));
        }
        if (currentDelay !== prev) {
          broadcastDelay(currentDelay);
          tuneNote = `  ${C.yellow}delay ${prev}→${currentDelay}ms${C.reset}`;
        }
      }

      const line = "─".repeat(78);
      const epParts = Object.entries(stats.endpoints).map(([name, s]) => {
        const total = s.ok + s.err;
        const errRate = total > 0 ? ((s.err / total) * 100).toFixed(0) : "0";
        const errCol = s.err === 0 ? C.green : (s.err / Math.max(1, total) > 0.2 ? "\x1b[31m" : C.yellow);
        const avgMs = s.msCount > 0 ? Math.round(s.totalMs / s.msCount) : 0;
        const rl = s.rl429 > 0 ? ` ${C.yellow}429×${s.rl429}${C.reset}` : "";
        return `${C.cyan}${name}${C.reset} ${s.ok}ok/${errCol}${s.err}err${C.reset} (${errRate}%, ~${avgMs}ms)${rl}`;
      }).join("  ");
      // Range progress line: shows position in [start..end], % complete, and
      // ETA based on the *current window* key consumption rate.
      let progressLine = "";
      if (mode === "range" && rangeCursor !== null) {
        const scannedThisRun = rangeCursor - rangeStartAtRun;
        const windowKeys = rangeCursor - stats.lastSnapshotCursor;
        const keysPerMin = windowMin > 0 ? Number(windowKeys) / windowMin : 0;
        let pctStr = "";
        let etaStr = "";
        let totalStr = "";
        if (rangeEnd !== null) {
          const total = rangeEnd - BigInt("0x" + (cfg.range.start || "1")) + 1n;
          const remaining = rangeEnd - rangeCursor + 1n;
          // Compute percent with one decimal using BigInt math (×1000 trick).
          const pctTimes10 = total > 0n
            ? Number((rangeCursor - BigInt("0x" + (cfg.range.start || "1"))) * 1000n / total)
            : 0;
          pctStr = ` (${(pctTimes10 / 10).toFixed(1)}%)`;
          totalStr = ` of ${total.toString()}`;
          if (keysPerMin > 0 && remaining > 0n) {
            const minutesLeft = Number(remaining) / keysPerMin;
            etaStr = `  ${C.cyan}ETA${C.reset} ${formatDuration(minutesLeft)}`;
          } else if (remaining > 0n) {
            etaStr = `  ${C.cyan}ETA${C.reset} —`;
          }
        }
        progressLine = `\n RANGE      ${C.cyan}cursor${C.reset} 0x${bigIntToHex64(rangeCursor)}${pctStr}` +
          `  ${C.cyan}scanned${C.reset} ${scannedThisRun.toString()}${totalStr}` +
          `  ${C.cyan}rate${C.reset} ${keysPerMin.toFixed(1)} keys/min${etaStr}`;
      }
      console.log(
        `\n${C.yellow}${line}${C.reset}\n` +
          `${C.bold} STATS${C.reset}  ` +
          `${C.cyan}total${C.reset} ${stats.count}  ` +
          `${C.cyan}hits${C.reset} ${stats.hits}  ` +
          `${C.cyan}errors${C.reset} ${stats.errors}  ` +
          `${C.cyan}rate${C.reset} ${windowRate}/min (avg ${overallRate}/min)  ` +
          `${C.cyan}uptime${C.reset} ${totalElapsedMin.toFixed(1)}min${tuneNote}` +
          progressLine +
          (epParts ? `\n ENDPOINTS  ${epParts}` : "") +
          `\n${C.yellow}${line}${C.reset}\n`,
      );
      stats.lastSnapshotCount = stats.count;
      stats.lastSnapshotErrors = stats.errors;
      stats.lastSnapshotAt = now;
      stats.lastSnapshotCursor = rangeCursor;
    }, statsIntervalMs).unref();
  }

  const workers = [];
  let stopping = false;

  function printFinalStats(reason) {
    const totalElapsedMin = (Date.now() - startedAt) / 60000;
    const overallRate = totalElapsedMin > 0 ? (stats.count / totalElapsedMin).toFixed(1) : "0.0";
    const snap = snapshotPersisted();
    const dline = "═".repeat(78);
    const sline = "─".repeat(78);
    console.log(`\n${C.yellow}${dline}${C.reset}`);
    console.log(`${C.bold} FINAL STATS (${reason})${C.reset}`);
    console.log(`${C.yellow}${dline}${C.reset}`);
    console.log(` this run     total=${stats.count}  hits=${stats.hits}  errors=${stats.errors}  rate=${overallRate}/min  uptime=${totalElapsedMin.toFixed(1)}min  finalDelay=${currentDelay}ms`);
    console.log(` cumulative   runs=${snap.runs}  total=${snap.totalCount}  hits=${snap.totalHits}  errors=${snap.totalErrors}  uptime=${(snap.totalUptimeMs / 60000).toFixed(1)}min`);

    const epEntries = Object.entries(stats.endpoints);
    if (epEntries.length > 0) {
      console.log(`${C.gray}${sline}${C.reset}`);
      console.log(` ${C.bold}per-endpoint (this run)${C.reset}`);
      for (const [name, s] of epEntries) {
        const total = s.ok + s.err;
        const errPct = total > 0 ? ((s.err / total) * 100).toFixed(1) : "0.0";
        const avgMs = s.msCount > 0 ? Math.round(s.totalMs / s.msCount) : 0;
        console.log(
          `   ${C.cyan}${pad(name, 12)}${C.reset} ` +
          `ok=${pad(s.ok, 6)} err=${pad(s.err, 5)} (${pad(errPct + "%", 6)}) ` +
          `avg=${pad(avgMs + "ms", 7)} 429×${s.rl429}`,
        );
      }
    }

    const errEntries = Object.entries(stats.errorCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);
    if (errEntries.length > 0) {
      console.log(`${C.gray}${sline}${C.reset}`);
      console.log(` ${C.bold}top worker errors (this run)${C.reset}`);
      for (const [msg, n] of errEntries) {
        console.log(`   ${pad(`×${n}`, 6)} ${msg}`);
      }
    }
    console.log(`${C.yellow}${dline}${C.reset}\n`);
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
      if (msg.type === "requestRange") {
        // Hand out the next chunk of sequential keys and persist the cursor
        // so the next run picks up where we left off (Last_Scan.txt).
        if (rangeCursor === null) {
          worker.postMessage({ type: "rangeChunk", startHex: bigIntToHex64(1n), count: 0 });
          return;
        }
        // Stop assigning work once the cursor has passed the configured end.
        if (rangeEnd !== null && rangeCursor > rangeEnd) {
          worker.postMessage({ type: "rangeChunk", startHex: bigIntToHex64(rangeCursor), count: 0 });
          if (!stopping) {
            console.log(`\n${C.green}Range scan complete: cursor reached 0x${bigIntToHex64(rangeEnd)}.${C.reset}`);
            await stopAll("RANGE COMPLETE");
          }
          return;
        }
        let count = Math.max(1, Number(msg.count) || 1);
        // Clamp the chunk so we don't overshoot the configured end.
        if (rangeEnd !== null) {
          const remaining = rangeEnd - rangeCursor + 1n;
          if (BigInt(count) > remaining) count = Number(remaining);
        }
        const startHex = bigIntToHex64(rangeCursor);
        rangeCursor = rangeCursor + BigInt(count);
        if (rangeCursor >= SECP256K1_N) rangeCursor = SECP256K1_N - 1n;
        saveRangeCursor(cfg.rangeFile, rangeCursor);
        worker.postMessage({ type: "rangeChunk", startHex, count });
        return;
      }
      if (msg.type === "endpointStats") {
        bumpEndpoint(msg.snap);
        return;
      }
      if (msg.type === "error") {
        stats.errors += 1;
        recordError(msg.message);
        console.log(`\t[worker ${msg.workerId}] error: ${msg.message}`);
        return;
      }
      if (msg.type === "mnemonicResult") {
        stats.count += 1;
        stats.mnemonicCount = (stats.mnemonicCount ?? 0) + 1;
        const count = stats.count;
        const hit = handleMnemonicHit(cfg, msg.mnemonic, msg.derivations);
        if (hit) {
          stats.hits += 1;
          saveState(stateFile, snapshotPersisted());
          if (cfg.pauseOnHit) {
            await stopAll("HIT FOUND");
            return;
          }
        }
        if (!hit && cfg.verbose) {
          printMnemonicRow(count, msg.workerId, msg.mnemonic, msg.derivations);
        }
        if (cfg.roundPauseMs > 0 && count % pauseEvery === 0) {
          const elapsed = ((Date.now() - startedAt) / 1000).toFixed(1);
          console.log(`\n\t${count} addresses checked in ${elapsed}s — pausing ${cfg.roundPauseMs / 1000}s ...\n`);
          await sleep(cfg.roundPauseMs);
          console.log("\t Resuming ...\n");
        }
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
