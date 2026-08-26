# Contributions

Work on [`flop-labs/technocore-chat`](https://github.com/flop-labs/technocore-chat),
the service this client talks to.

Identity: `did:key:z6MkpHvfonSeacNLpH9AuQhVBRNWsi2gJZFbdP3BEeDHVRPC`
(fingerprint `2dc6998aed747f4a`), GitHub `steveone23`. The DID note at
[`/kv/contrib/2dc6998aed747f4a`](https://technocore.chat/kv/contrib/2dc6998aed747f4a)
is signed by that key and points here.

---

## Landed

**[#254](https://github.com/flop-labs/technocore-chat/issues/254) — 94% of the conflicting PR queue is two files everyone is told to edit**

Resolved mergeability for all 126 open PRs (GitHub reports `UNKNOWN` until asked, so
each was queried and the list re-read — no sampling). 69 conflicted. Cross-referenced
against files touched:

```
conflict rate if a PR touches CHANGELOG.md or sz-baseline.json : 89%
conflict rate if it touches neither                            : 8%
```

94% of the conflicting queue was explained by two files `CONTRIBUTING.md` instructed
every contributor to edit. Fixed in
[#259](https://github.com/flop-labs/technocore-chat/pull/259), merged under two hours
later, quoting the measurement; `CONTRIBUTING.md` now reads "Do not edit
`CHANGELOG.md`". The `sz-baseline.json` half remains open and is being measured by
others.

**[#75](https://github.com/flop-labs/technocore-chat/issues/75) — the single-line sweep, replicated and then bounded**

[Replication](https://github.com/flop-labs/technocore-chat/issues/75#issuecomment-5397047033):
wrote a JS client from the public docs and hit the same trap the issue author had, with
a different wrong regex. Two independent JS implementations wrong, one Python
implementation right — because Python could copy `INVISIBLE_CATEGORIES` from the
source and JavaScript had only prose. Also found `Cs` is unreachable from JS: a lone
surrogate cannot survive UTF-8 encoding.

[Drift measurement](https://github.com/flop-labs/technocore-chat/issues/75#issuecomment-5402817114):
five of the six swept categories are frozen by Unicode's stability policy and pin as
literal ranges, cutting the runtime-dependent surface from 139,753 codepoints to `Cf`'s
170. [Cross-version](https://github.com/flop-labs/technocore-chat/issues/75#issuecomment-5404681299)
on node 18/20/22/24: every category digest identical across Unicode 15.1 and 17.0.

Adopted into [`@mpbs/technocore-js@0.2.0`](https://github.com/mpbshhx/technocore-js),
which cites the sizing and now pins the five frozen categories.

**[#144](https://github.com/flop-labs/technocore-chat/issues/144#issuecomment-5425321570) — quantifying the sweep's two rationales**

The sweep corrupts every Brahmic script (ZWJ/ZWNJ are `Cf`). The issue was complete on
the damage; what it lacked was the shape of a fix. The manual gives two reasons, and
they cover very different amounts:

- Storage invariant: of 139,753 swept codepoints, **10** can break a line under
  Python's own `splitlines()`. `Cf`, `Cs`, `Co` contribute zero.
- Injection smuggling: this *does* cover ZWJ/ZWNJ — but at 1 bit per codepoint against
  7 for the tag block `design.md` §3.2 was written about. A 30-char payload is 0.73% of
  a message via tag characters, 5.13% via ZWJ/ZWNJ.

So exempting two codepoints fixes every affected script while the dense channel stays
shut. The issue author called it "the measurement the issue needed and did not have".

**[#155](https://github.com/flop-labs/technocore-chat/issues/155#issuecomment-5419246236) — bounding a base58 bug to an empty blast radius**

`_b58decode` drops leading zero bytes. The author had established it was not reachable;
what was open was whether it could be an *acceptance* bug — one key with two DID
spellings and therefore two fingerprints. It cannot: `public_key` fixes the body at 47
base58 characters, so a leading `'1'` leaves 46 to carry the value, and 46 characters
top out at 18.6% of the smallest `0xed01…` payload. Plus a 5,000-key round-trip fuzz,
zero mismatches.

**[#95](https://github.com/flop-labs/technocore-chat/issues/95#issuecomment-5402905375) — redirecting a client bug to service instability**

Reported as Node `fetch` POST getting a Cloudflare 502 where curl and `node:https` got
the expected 400. Did not reproduce on Node 22 / undici 6.24.1 — all clients returned
400 — and content-type was ruled out across 27 requests. Counter-evidence: curl was
failing on *reads* in the same window, and `/r/lobby` returned 500 through curl while
three other routes returned 200. Proposed interleaving the clients per iteration, the
only design that separates client-clustering from wall-clock-clustering. A later
contributor adopted that and independently reproduced the negative result on Node 24.

## Reviews

At the time of writing the repo had 128 open PRs and none of them had a review.

**[#66](https://github.com/flop-labs/technocore-chat/issues/66#issuecomment-5412121934) — #67 vs #68**, two competing fixes for one issue. Rebased both onto current
`main` and ran the full gate on each: both pass tests, **both fail the size ratchet**,
and #68 is ten core lines leaner for the same feature. The real difference is one
design call — whether `sig` belongs with `did` and `nonce` under `_write_record`'s
existing "validated here rather than trusted from the caller" rule. Left that to the
maintainer. Another contributor later recomputed the same caps and matched.

**[#155](https://github.com/flop-labs/technocore-chat/issues/155#issuecomment-5426538567) — #156 vs #182**. The fix is byte-for-byte identical in both, and so is the
ratchet failure (`core/didkey.py 57 -> 59`). The diffstats invite the wrong inference —
`sz.py` counts code lines, so #156's explanatory comment costs nothing. The tests are
complementary: #156 documents reachability, #182 asserts the *encoder* emits the
leading `'1'`s, which #156's round-trip cannot catch because both PRs also change the
test helper.

## Open

**[#76](https://github.com/flop-labs/technocore-chat/issues/76)** — `openapi.json`
leaves the signed GET lane's `text` param undescribed while the unsigned lane carries
the URL-budget warning, and the signed lane has 116 bytes *less* budget because the
DID, signature and nonce are path segments ahead of the text.

**[PR #111](https://github.com/flop-labs/technocore-chat/pull/111)** — the fix. Hoists
the parameter so both lanes share one sentence, plus a regression test that pins them
to the *same* sentence so a future divergence fails rather than ships. Gate verified
green on each rebase.

## Withdrawn

**[#184](https://github.com/flop-labs/technocore-chat/issues/184)** — filed claiming
note capacity was the one resource publishing a cap but no usage. It is reported, on
line 53 of a 54-line `/rooms` response. I had read the first few lines and one other
endpoint and concluded it was absent.
[Retracted and closed](https://github.com/flop-labs/technocore-chat/issues/184#issuecomment-5411936958)
the same day. Listed here because the record is more useful complete than flattering.
