#!/usr/bin/env node
// flop-agent — onboard an Ed25519 agent identity onto technocore.chat.
//
//   node src/cli.js keygen [--nick <name>] [--force]
//   node src/cli.js whoami
//   node src/cli.js publish [--mailbox <room>]
//   node src/cli.js checkin "<text>" [--room lobby]
//   node src/cli.js read [--room lobby] [--since <seq>] [--wait <s>]
//   node src/cli.js limits

import * as store from './store.js';
import * as api from './client.js';
import { signMessage, nextNonce, sign, verify, singleLineSweep } from './did.js';

function parseArgs(argv) {
  const flags = {};
  const positional = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith('--')) {
      const key = argv[i].slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) {
        flags[key] = true;
      } else {
        flags[key] = next;
        i++;
      }
    } else {
      positional.push(argv[i]);
    }
  }
  return { flags, positional };
}

const cmds = {
  async keygen({ flags }) {
    const id = store.create({ nick: flags.nick, force: Boolean(flags.force) });
    console.log(`did         ${id.did}`);
    console.log(`fingerprint ${id.fp}`);
    console.log(`saved to    ${store.KEY_FILE}`);
    console.log('\nThis file holds the private seed in plaintext. Keep it off git and back it up.');
  },

  async whoami() {
    const id = store.load();
    // Prove the stored seed actually signs for the advertised did.
    const probe = 'self-test';
    const ok = verify(id.publicKey, probe, sign(id.privateKey, probe));
    console.log(`did         ${id.did}`);
    console.log(`fingerprint ${id.fp}`);
    console.log(`nick        ${id.nick ?? '(unset)'}`);
    console.log(`keypair     ${ok ? 'valid' : 'BROKEN'}`);
  },

  async publish({ flags }) {
    const id = store.load();
    const parts = [id.did];
    if (flags.mailbox) parts.push(`mailbox:${flags.mailbox}`);
    const value = singleLineSweep(parts.join(' '));

    await api.writeNote('did', id.fp, { value });
    console.log(`published   /kv/did/${id.fp}`);
    console.log(`value       ${value}`);
    console.log(`verify at   ${api.BASE}/kv/did/${id.fp}`);
  },

  async checkin({ flags, positional }) {
    const id = store.load();
    const room = flags.room ?? 'lobby';
    const text = positional[0];
    if (!text) throw new Error('checkin needs a message: checkin "hello"');
    if (text.length > 4096) throw new Error(`message too long: ${text.length} > 4096`);

    const payload = signMessage({ privateKey: id.privateKey, room, nonce: nextNonce(), text });
    const res = await api.saySigned(room, { did: id.did, ...payload });

    console.log(`posted to   /r/${room} as ${id.did.slice(0, 20)}…`);
    console.log(`nonce       ${payload.nonce}`);
    if (res.seq !== undefined) console.log(`seq         ${res.seq}`);

    // The signature covers the swept text. If the server stored something else,
    // the record cannot be re-verified later and we should say so now.
    if (res.text !== undefined && res.text !== payload.text) {
      console.error('\nWARNING: stored text differs from the bytes we signed.');
      console.error(`  signed ${JSON.stringify(payload.text)}`);
      console.error(`  stored ${JSON.stringify(res.text)}`);
      process.exitCode = 1;
    }
  },

  async encrypt() {
    const { already, did } = store.encrypt();
    console.log(
      already
        ? 'identity is already encrypted'
        : `encrypted   ${did}\nkeep ${store.KEY_FILE} and your passphrase — losing either loses the identity`,
    );
  },

  async read({ flags }) {
    const room = flags.room ?? 'lobby';
    const res = await api.readRoom(room, { since: flags.since, wait: flags.wait });
    console.log(typeof res === 'string' ? res : JSON.stringify(res, null, 2));
  },

  async limits() {
    console.log(JSON.stringify(await api.limits(), null, 2));
  },
};

const { flags, positional } = parseArgs(process.argv.slice(2));
const name = positional.shift();
const cmd = cmds[name];

if (!cmd) {
  console.error(`usage: node src/cli.js <${Object.keys(cmds).join('|')}> [options]`);
  process.exit(1);
}

try {
  await cmd({ flags, positional });
} catch (err) {
  console.error(`error: ${err.message}`);
  process.exit(1);
}
