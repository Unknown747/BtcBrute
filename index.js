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

import { appendFileSync, readFileSync, writeFileSync, existsSync } from "node:fs";
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
  blockchain: async (res, address) => {
    const data = await res.json();
    return Number(data[address].final_balance);
  },
  blockstream: async (res) => {
    const data = await res.json();
    const c = data.chain_stats ?? { funded_txo_sum: 0, spent_txo_sum: 0 };
    const m = data.mempool_stats ?? { funded_txo_sum: 0, spent_txo_sum: 0 };
    return (
      (c.funded_txo_sum - c.spent_txo_sum) +
      (m.funded_txo_sum - m.spent_txo_sum)
    );
  },
};

function buildEndpointUrl(endpoint, address) {
  if (endpoint.type === "blockchain") return `${endpoint.url}${address}`;
  if (endpoint.type === "blockstream") return `${endpoint.url}${address}`;
  throw new Error(`Unknown endpoint type: ${endpoint.type}`);
}

async function getFinalBalance(address, endpoints) {
  let lastErr;
  for (const endpoint of endpoints) {
    try {
      const res = await fetch(buildEndpointUrl(endpoint, address));
      if (!res.ok) {
        throw new Error(`${endpoint.type} responded ${res.status}`);
      }
      const parser = ENDPOINT_PARSERS[endpoint.type];
      return await parser(res, address);
    } catch (err) {
      lastErr = err;
    }
  }
  throw new Error(`all endpoints failed for ${address}: ${lastErr?.message}`);
}

/* -------------------------------- Worker -------------------------------- */

async function runWorker() {
  const cfg = workerData.config;
  const id = workerData.id;

  while (true) {
    try {
      const kp = makeKeyPair();
      const multi = cfg.checkMultisig ? makeMultisigAddress() : null;

      const lookups = [
        getFinalBalance(kp.uncompressedAddress, cfg.endpoints),
        getFinalBalance(kp.compressedAddress, cfg.endpoints),
        getFinalBalance(kp.segwitAddress, cfg.endpoints),
        getFinalBalance(kp.nestedSegwitAddress, cfg.endpoints),
      ];
      if (multi) lookups.push(getFinalBalance(multi.address, cfg.endpoints));

      const results = await Promise.all(lookups);
      const balances = {
        uncompressed: results[0],
        compressed: results[1],
        segwit: results[2],
        nestedSegwit: results[3],
        multi: multi ? results[4] : 0,
      };

      parentPort.postMessage({ type: "result", workerId: id, kp, multi, balances });
    } catch (err) {
      parentPort.postMessage({ type: "error", workerId: id, message: err.message });
      await sleep(cfg.errorBackoffMs);
    }
    await sleep(cfg.perAddressDelayMs);
  }
}

/* --------------------------------- Main --------------------------------- */

function pad(s, n) {
  s = String(s);
  return s.length >= n ? s : s + " ".repeat(n - s.length);
}

function printRow(count, workerId, kp, multi, balances) {
  const rows = [
    { addr: kp.uncompressedAddress, bal: balances.uncompressed, type: "uncompressed" },
    { addr: kp.compressedAddress, bal: balances.compressed, type: "compressed  " },
    { addr: kp.segwitAddress, bal: balances.segwit, type: "segwit      " },
    { addr: kp.nestedSegwitAddress, bal: balances.nestedSegwit, type: "p2sh-segwit " },
  ];
  if (multi) rows.push({ addr: multi.address, bal: balances.multi, type: "multisig    " });

  for (const r of rows) {
    console.log(
      `Count : ${pad(count, 6)} Addrs : ${pad(r.addr, 44)} Bal : ${r.bal}  [${r.type}|w${workerId}]`,
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
    writeFileSync(file, JSON.stringify(state, null, 2));
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

async function runMain() {
  const cfg = loadConfig();
  cfg.endpoints = normalizeEndpoints(cfg);
  const stateFile = cfg.stateFile ?? "state.json";
  const persisted = loadState(stateFile);
  persisted.runs = (persisted.runs ?? 0) + 1;

  const endpointList = cfg.endpoints.map((e, i) => `\t  ${i + 1}. ${e.type} — ${e.url}`).join("\n");
  console.log("\n" + "=".repeat(80));
  console.log("\t            BTC LOTTERY — multithreaded address scanner");
  console.log("=".repeat(80));
  console.log(`\t Workers           : ${cfg.workerCount}`);
  console.log(`\t Delay / address   : ${cfg.perAddressDelayMs} ms`);
  console.log(`\t Round pause       : ${cfg.roundPauseMs} ms (every ${cfg.addressesPerRound * cfg.workerCount} addresses)`);
  console.log(`\t Stats interval    : ${cfg.statsIntervalMs ?? 60000} ms`);
  console.log(`\t Multisig check    : ${cfg.checkMultisig ? "ON" : "off"}`);
  console.log(`\t Pause on hit      : ${cfg.pauseOnHit ? "ON" : "off"}`);
  console.log(`\t Output file       : ${cfg.outputFile}`);
  console.log(`\t State file        : ${stateFile}`);
  console.log(`\t Balance endpoints (failover order):`);
  console.log(endpointList);
  console.log(`\t Run               : #${persisted.runs}`);
  console.log(
    `\t Cumulative so far : total=${persisted.totalCount} hits=${persisted.totalHits} errors=${persisted.totalErrors} uptime=${(persisted.totalUptimeMs / 60000).toFixed(1)}min`,
  );
  console.log("=".repeat(80) + "\n");

  const stats = {
    count: 0,
    errors: 0,
    hits: 0,
    lastSnapshotCount: 0,
    lastSnapshotAt: Date.now(),
  };
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
      console.log(
        `\n\t==== STATS ==== total: ${stats.count} | hits: ${stats.hits} | errors: ${stats.errors} | last ${windowMin.toFixed(1)}min: ${windowRate}/min | overall: ${overallRate}/min | uptime: ${totalElapsedMin.toFixed(1)}min\n`,
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

  for (let i = 0; i < cfg.workerCount; i++) {
    const worker = new Worker(SELF, { workerData: { config: cfg, id: i + 1 } });
    workers.push(worker);

    worker.on("message", async (msg) => {
      if (stopping) return;
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
        if (cfg.pauseOnHit) {
          await stopAll("HIT FOUND");
          return;
        }
      }
      if (!hit && cfg.verbose) {
        printRow(count, msg.workerId, msg.kp, msg.multi, msg.balances);
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
}

if (isMainThread) {
  runMain().catch((err) => {
    console.error("Fatal:", err);
    process.exit(1);
  });
} else {
  runWorker();
}
