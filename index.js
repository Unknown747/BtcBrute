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

import { appendFileSync, readFileSync } from "node:fs";
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

  return {
    privateKeyHex: Buffer.from(compressedKey.privateKey).toString("hex"),
    wifCompressed: compressedKey.toWIF(),
    wifUncompressed: uncompressedKey.toWIF(),
    compressedAddress,
    uncompressedAddress,
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

async function getFinalBalance(address, apiUrl) {
  const res = await fetch(`${apiUrl}${address}`);
  if (!res.ok) {
    throw new Error(`API responded ${res.status} for ${address}`);
  }
  const data = await res.json();
  return Number(data[address].final_balance);
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
        getFinalBalance(kp.uncompressedAddress, cfg.balanceApiUrl),
        getFinalBalance(kp.compressedAddress, cfg.balanceApiUrl),
      ];
      if (multi) lookups.push(getFinalBalance(multi.address, cfg.balanceApiUrl));

      const results = await Promise.all(lookups);
      const balances = {
        uncompressed: results[0],
        compressed: results[1],
        multi: multi ? results[2] : 0,
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

function printRow(count, workerId, kp, multi, balances) {
  console.log(
    "\t-------------------------------------------------------------------------------------------------------",
  );
  console.log(
    `\t#${count} (worker ${workerId})\t Private Key (WIF-Uncompressed) : ${kp.wifUncompressed}`,
  );
  console.log(`\t\t Private Key (WIF-Compressed)   : ${kp.wifCompressed}`);
  console.log(`\t\t Uncompressed Address           : ${kp.uncompressedAddress}  [bal: ${balances.uncompressed}]`);
  console.log(`\t\t Compressed Address             : ${kp.compressedAddress}  [bal: ${balances.compressed}]`);
  console.log(`\t\t Private Key (hex)              : ${kp.privateKeyHex}`);
  if (multi) {
    console.log(`\t\t Multisig Address               : ${multi.address}  [bal: ${balances.multi}]`);
  }
  console.log("\t\t No luck yet!");
}

function appendHit(file, text) {
  appendFileSync(file, text);
}

function handleHit(cfg, kp, multi, balances) {
  if (balances.uncompressed > 0) {
    appendHit(
      cfg.outputFile,
      `Uncompressed Private Key\t:  ${kp.wifUncompressed}\n` +
        ` Uncompressed Bitcoin Address\t:  ${kp.uncompressedAddress}\n` +
        ` Uncompressed Balance: ${balances.uncompressed}\n\n`,
    );
    console.log("\nYou have just rung the bell of BTC Lottery !!!");
    return true;
  }
  if (balances.compressed > 0) {
    appendHit(
      cfg.outputFile,
      `Compressed Private Key\t:  ${kp.wifCompressed}\n` +
        ` Compressed Bitcoin Address\t:  ${kp.compressedAddress}\n` +
        ` Compressed Balance: ${balances.compressed}\n\n`,
    );
    console.log("\nYou have just rung the bell of BTC Lottery !!!");
    return true;
  }
  if (multi && balances.multi > 0) {
    appendHit(
      cfg.outputFile,
      `Multi BTC Address\t:  ${multi.address}\n` +
        ` Multisig Private Keys (WIF)\t:  ${multi.privateKeysWif.join(", ")}\n` +
        ` Multi Balance: ${balances.multi}\n\n`,
    );
    console.log("\nYou have just rung the bell of BTC Lottery !!!");
    return true;
  }
  return false;
}

async function runMain() {
  const cfg = loadConfig();
  console.log(
    `Starting BTC lottery — workers: ${cfg.workerCount}, delay/addr: ${cfg.perAddressDelayMs}ms, output: ${cfg.outputFile}`,
  );

  const stats = {
    count: 0,
    errors: 0,
    hits: 0,
    lastSnapshotCount: 0,
    lastSnapshotAt: Date.now(),
  };
  const startedAt = Date.now();
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
    console.log(
      `\n\t==== FINAL STATS (${reason}) ==== total: ${stats.count} | hits: ${stats.hits} | errors: ${stats.errors} | overall: ${overallRate}/min | uptime: ${totalElapsedMin.toFixed(1)}min\n`,
    );
  }

  async function stopAll(reason) {
    if (stopping) return;
    stopping = true;
    console.log(`\n\t!!! ${reason} — stopping all workers ...\n`);
    await Promise.all(workers.map((w) => w.terminate().catch(() => {})));
    printFinalStats(reason);
    console.log("\t All workers stopped. Check the output file for details.");
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
