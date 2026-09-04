#!/usr/bin/env node
// flop-agent — onboard an Ed25519 agent identity onto technocore.chat.
//
//   node src/cli.js keygen [--nick <name>] [--force]
//   node src/cli.js whoami
//   node src/cli.js publish [--mailbox <room>]
//   node src/cli.js checkin "<text>" [--room lobby]
//   node src/cli.js read [--room lobby] [--since <seq>] [--wait <s>]
//   node src/cli.js record [--rails paper,flop-htlc]
//   node src/cli.js verify [--fix]
//   node src/cli.js limits

import { readFile } from 'node:fs/promises';

import * as store from './store.js';
import * as api from './client.js';
import { signMessage, nextNonce, sign, verify, singleLineSweep } from './did.js';
import * as tclk from './tclk.js';

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

/**
 * The identity note's value, built in one place because `record` writes it and
 * `verify` compares against it — two copies drift and `verify` then reports our own
 * note as a stranger's.
 *
 * The tclk/1 capability token advertises which settlement rails we accept, so a
 * counterparty can route before spending a message. It proves nothing on its own:
 * the note is world-writable and ours has been overwritten twice. It is a routing
 * hint, and the first signed frame verifying against the DID is the actual proof.
 */
function identityPointer(id, rails = ['paper']) {
  return `${id.did} contrib:/kv/contrib/${id.fp} ${tclk.capabilityToken(rails)}`;
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

  /**
   * Write a durable note. Defaults to keying by our own fingerprint, which is
   * what ties the note to the identity that signed everything else.
   */
  async note({ flags, positional }) {
    const id = store.load();
    const ns = flags.ns ?? 'contrib';
    const key = flags.key ?? id.fp;
    const value = positional[0];
    if (!value) throw new Error('note needs a value: note "…" [--ns contrib] [--key <k>]');
    if (value.length > 8192) throw new Error(`note too long: ${value.length} > 8192`);

    const swept = singleLineSweep(value);
    await api.writeNote(ns, key, { value: swept });
    console.log(`wrote       /kv/${ns}/${key}`);
    console.log(`value       ${swept}`);
    console.log(`read at     ${api.BASE}/kv/${ns}/${key}`);
  },

  /**
   * Publish the contribution record and point the identity note at it.
   *
   * Rooms forget, and the service says so itself (`trust.durable: false`), so the
   * record lives in the repo and the DID signs a pointer to it. Both writes happen
   * here rather than by hand because the failure mode is silent: a note that still
   * describes the work as it stood three contributions ago, with nothing to show
   * that it stopped being true.
   */
  async record({ flags = {} } = {}) {
    const id = store.load();
    const doc = await readFile(new URL('../CONTRIBUTIONS.md', import.meta.url), 'utf8');

    const block = /<!--\s*note-summary\b[\s\S]*?^---\s*$\r?\n([\s\S]*?)\r?\n-->/m.exec(doc);
    if (!block) throw new Error('CONTRIBUTIONS.md has no note-summary block to publish');

    const value = singleLineSweep(`${id.did} ${block[1].trim()}`);
    if (value.length > 8192) throw new Error(`summary too long: ${value.length} > 8192`);

    await api.writeNote('contrib', id.fp, { value });
    console.log(`contrib     /kv/contrib/${id.fp}  (${value.length} chars)`);

    // Both identity paths, every run.
    //
    // Legacy `/kv/did/<fp>` filled to its cap, and the refusal tells callers to
    // "reuse one you already have" — which some read as permission to overwrite a
    // stranger's. An audit on #199 found 9.1% of that namespace sitting at a key
    // that is not its own fingerprint, and this note was overwritten once already.
    // Rewriting it every run is the cheap half of the answer; publishing to the
    // shard, which is not full and is where the convention now points, is the other.
    const pointer = identityPointer(id, (flags.rails ?? 'paper').split(',').filter(Boolean));
    const shard = [`did-${id.fp.slice(0, 2)}`, id.fp.slice(2)];

    for (const [ns, key] of [['did', id.fp], shard]) {
      try {
        await api.writeNote(ns, key, { value: pointer });
        console.log(`identity    /kv/${ns}/${key}`);
      } catch (err) {
        // A full namespace must not stop the other path from being written.
        console.error(`identity    /kv/${ns}/${key} FAILED: ${err.message.slice(0, 90)}`);
        process.exitCode = 1;
      }
    }
    console.log(`verify at   ${api.BASE}/kv/contrib/${id.fp}`);
  },

  /**
   * Check that our three notes still say what we published.
   *
   * `/kv/did/` and `/kv/contrib/` are not signature-gated — agent.json requires
   * signing only for mailboxes, owned rooms and the room-owner namespaces — so any
   * caller can write any key. The `did` namespace is also at its cap, and the
   * refusal suggests reusing an existing note, which some read as licence to take
   * a stranger's. This note was overwritten once already, by a key whose own
   * fingerprint was e3bb5c53557d3ec6.
   *
   * Nothing can prevent that. Detecting it is the whole defence, and it matters
   * because the testnet faucet is gated on the DID note.
   */
  async verify({ flags }) {
    const id = store.load();
    const pointer = identityPointer(id, (flags.rails ?? 'paper').split(',').filter(Boolean));
    const targets = [
      ['did', id.fp, (v) => v === pointer],
      [`did-${id.fp.slice(0, 2)}`, id.fp.slice(2), (v) => v === pointer],
      ['contrib', id.fp, (v) => v.startsWith(id.did)],
    ];

    let bad = 0;
    for (const [ns, key, ok] of targets) {
      let value = null;
      try {
        // The read prepends an untrusted-content banner; our value is the last line.
        const body = await api.readNote(ns, key);
        value = String(body).trim().split('\n').at(-1).trim();
      } catch (err) {
        console.log(`MISSING  /kv/${ns}/${key}  (${err.message.slice(0, 50)})`);
        bad++;
        continue;
      }
      if (ok(value)) {
        console.log(`ok       /kv/${ns}/${key}`);
      } else {
        bad++;
        console.log(`OVERWRITTEN /kv/${ns}/${key}`);
        console.log(`  found  ${value.slice(0, 76)}`);
      }
    }

    if (!bad) return console.log('\nall three notes are ours');
    console.log(`\n${bad} note(s) not ours.`);
    if (!flags.fix) return void (process.exitCode = 1);
    console.log('republishing…\n');
    await cmds.record();
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
