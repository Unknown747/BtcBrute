/*
 * btc-balance.js
 *
 * JavaScript port of the original Python "BTC lottery" script.
 * Generates random Bitcoin keypairs (uncompressed, compressed, and a 2-of-3
 * P2SH multisig), checks their balances on blockchain.info, and appends any
 * non-zero hits to "Lottery_BTC.txt".
 *
 * Educational/curiosity use only. The probability of randomly hitting a
 * funded address is effectively zero (~1 in 2^160). Be a good citizen and
 * don't hammer blockchain.info — the script throttles itself with sleeps.
 *
 * Requirements (Node.js 18+ for global fetch):
 *   npm install bitcoinjs-lib tiny-secp256k1 ecpair
 *
 * Run:
 *   node btc-balance.js
 */

import { appendFileSync } from "node:fs";
import { setTimeout as sleep } from "node:timers/promises";
import * as bitcoin from "bitcoinjs-lib";
import * as ecc from "tiny-secp256k1";
import { ECPairFactory } from "ecpair";

bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);
const NETWORK = bitcoin.networks.bitcoin;

const TOOLBAR_WIDTH = 40;
const ADDRESSES_PER_ROUND = 20;
const PER_ADDRESS_DELAY_MS = 3000;
const ROUND_PAUSE_MS = 60_000;
const ERROR_BACKOFF_MS = 15_000;

/** Generate a random keypair and derive uncompressed + compressed P2PKH addresses. */
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
    privateKeyHex: compressedKey.privateKey.toString("hex"),
    wifCompressed: compressedKey.toWIF(),
    wifUncompressed: uncompressedKey.toWIF(),
    compressedAddress,
    uncompressedAddress,
    compressedPubKey: compressedKey.publicKey,
  };
}

/** Build a 2-of-3 P2SH multisig address from three random compressed pubkeys. */
function makeMultisigAddress() {
  const keys = [0, 1, 2].map(() =>
    ECPair.makeRandom({ network: NETWORK, compressed: true }),
  );
  const pubkeys = keys.map((k) => k.publicKey);
  const redeem = bitcoin.payments.p2ms({ m: 2, pubkeys, network: NETWORK });
  const { address } = bitcoin.payments.p2sh({ redeem, network: NETWORK });
  return {
    address,
    privateKeysWif: keys.map((k) => k.toWIF()),
  };
}

/** Look up the final balance (in satoshis) for a single address via blockchain.info. */
async function getFinalBalance(address) {
  const url = `https://blockchain.info/balance?active=${address}`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`blockchain.info responded ${res.status} for ${address}`);
  }
  const data = await res.json();
  return Number(data[address].final_balance);
}

function appendHit(text) {
  appendFileSync("Lottery_BTC.txt", text);
}

function printRow(count, kp, multi, balances) {
  const sep =
    "\t-------------------------------------------------------------------------------------------------------\n";
  process.stdout.write(sep);
  console.log(`\t${count}\t Private Key (WIF-Uncompressed) \t: ${kp.wifUncompressed}`);
  console.log(`\t\t Private Key (WIF-Compressed) \t\t: ${kp.wifCompressed}\n`);
  console.log(`\t\t Uncompressed Bitcoin Address \t\t: ${kp.uncompressedAddress}`);
  console.log(`\t\t Final Balance \t\t\t\t:  ${balances.uncompressed}\n`);
  console.log(`\t\t Compressed Bitcoin Address \t\t: ${kp.compressedAddress}`);
  console.log(`\t\t Final Balance \t\t\t\t:  ${balances.compressed}\n`);
  console.log(`\t\t Private Key Hexadecimal \t\t:  ${kp.privateKeyHex}`);
  console.log(`\t\t Multiple BTC Address \t\t\t:  ${multi.address}`);
  console.log(`\t\t Third Final Balance \t\t\t:  ${balances.multi}\n`);
  console.log("\n \t\t\t\t\t You have no lucky yet !!! \n");
}

async function progressBar() {
  for (let i = 0; i < TOOLBAR_WIDTH; i++) {
    await sleep(ROUND_PAUSE_MS / TOOLBAR_WIDTH);
    process.stdout.write(" |||");
  }
  process.stdout.write("\n\n");
}

async function main() {
  let btc = ADDRESSES_PER_ROUND;
  let round = 1;
  let count = 1;

  while (true) {
    try {
      if (count <= ADDRESSES_PER_ROUND) {
        const kp = makeKeyPair();
        const multi = makeMultisigAddress();

        const [uncompressed, compressed, multiBal] = await Promise.all([
          getFinalBalance(kp.uncompressedAddress),
          getFinalBalance(kp.compressedAddress),
          getFinalBalance(multi.address),
        ]);

        const balances = { uncompressed, compressed, multi: multiBal };

        if (uncompressed > 0) {
          appendHit(
            `Uncompressed Private Key\t\t:  ${kp.wifUncompressed}\n` +
              ` Uncompressed Bitcoin Address\t:  ${kp.uncompressedAddress} \n` +
              ` Uncompressed Balance: ${uncompressed}\n\n`,
          );
          console.log("\nYou have just rung the bell of BTC Lottery !!!");
        } else if (compressed > 0) {
          appendHit(
            `Compressed Private key\t:  ${kp.wifCompressed}\n` +
              ` Compressed Bitcoin Address\t:  ${kp.compressedAddress}\n` +
              ` Compressed Balance: ${compressed}\n\n`,
          );
          console.log("\nYou have just rung the bell of BTC Lottery !!!");
        } else if (multiBal > 0) {
          appendHit(
            `Multi BTC Address\t:  ${multi.address}\n` +
              ` Multisig Private Keys (WIF)\t:  ${multi.privateKeysWif.join(", ")}\n` +
              ` Multi Balance: ${multiBal}\n\n`,
          );
          console.log("\nYou have just rung the bell of BTC Lottery !!!");
        } else {
          printRow(count, kp, multi, balances);
        }

        count += 1;
        await sleep(PER_ADDRESS_DELAY_MS);
      } else {
        console.log(
          `\t${round} round(s) done, ${btc} BTC Address have been generated, wait 60 seconds ... \n`,
        );
        btc += ADDRESSES_PER_ROUND;
        round += 1;
        await progressBar();
        console.log("\t Restarting ... \n");
        await sleep(5000);
        count = 1;
      }
    } catch (err) {
      console.log(`\t Something went wrong: ${err.message}, please wait ...\n`);
      await sleep(ERROR_BACKOFF_MS);
      console.log("\t Error solved, Restarting ... \n");
      count = 1;
    }
  }
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
