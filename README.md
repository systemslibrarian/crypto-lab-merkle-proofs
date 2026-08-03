# crypto-lab-merkle-proofs

## What It Is

This is an interactive demo of **Merkle trees** and **Merkle inclusion proofs**, built on **SHA-256** via the browser's WebCrypto API. A Merkle tree hashes a set of data blocks into a single root hash that commits to all of them at once; an inclusion proof is the short list of sibling hashes that lets anyone re-derive that root from a single leaf. The security model is purely **hash-based**: it relies on the collision and second-preimage resistance of SHA-256, with no keys or signatures involved. Hashing follows **RFC 6962** domain separation (`leaf = SHA-256(0x00 ∥ data)`, `node = SHA-256(0x01 ∥ left ∥ right)`), which is what makes the second-preimage defense in the demo real rather than decorative. It is a teaching tool, not a production library.

## Where This Sits Next to crypto-lab-merkle-vault

Two labs in this catalog cover Merkle trees, and they are not interchangeable. **This one is about
proof semantics**: where the trusted root must come from, the exact bytes hashed at every step, RFC
9162 index-based verification, consistency proofs with the history attacks they catch, the
second-preimage and CVE-2012-2459 constructions broken on the page, and a pinned real Certificate
Transparency entry verified against Google's Argon log.
**[crypto-lab-merkle-vault](https://systemslibrarian.github.io/crypto-lab-merkle-vault/) is about
the structure**: the tree drawn with parent-to-child connectors, a single proof walked one level at
a time with the corresponding nodes lighting up as the running hash rises, and the recomputed and
committed roots asserted equal byte for byte at the top. Start there for *what a Merkle tree is and
how one climb works*; come here for *what a proof does and does not entitle you to believe*.

## When to Use It

- **To prove one element belongs to a large committed set, cheaply.** A proof is `⌈log₂ n⌉` hashes, so a single transaction can be shown to be in a block of millions without sending the block.
- **To detect tampering against a trusted root.** If you already hold the root, you can verify any leaf+proof and reject anything that doesn't recompute to it.
- **To give light clients integrity without full state.** SPV wallets and stateless clients check membership against a header's root instead of downloading everything.
- **To make a log verifiably append-only.** Certificate Transparency uses exactly this RFC 6962 construction.
- **Do NOT use a Merkle proof to prove *non*-membership or order** unless the tree is specifically a sorted/sparse Merkle tree — a plain inclusion proof says nothing about what is absent, and a tree built without domain separation is open to second-preimage forgery.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-merkle-proofs](https://systemslibrarian.github.io/crypto-lab-merkle-proofs/)**

Add or remove data blocks to build a tree live, choose any leaf to generate its inclusion proof, then verify it — recomputing the root from only the leaf and its sibling hashes. You can **step through or animate** the recompute one hash at a time (watching the running hash climb the tree), expand **“show bytes”** on any step to see the exact SHA-256 preimage (`0x00 ∥ data` for leaves, `0x01 ∥ L ∥ R` for nodes), tamper with the leaf or flip a bit in any proof step and watch verification flip to REJECTED, and scale a slider to see proofs stay logarithmic up to 2³⁰ leaves (plus build real 256–4,096-leaf trees). A **trust-model demo** stages the classic misconception directly: a prover who supplies leaf, proof, *and root* produces a triple that verifies — and proves nothing. Two security demos let you toggle RFC 6962 domain separation on/off to make the second-preimage forgery succeed then fail, and compare Bitcoin's odd-node duplication against RFC 6962 promotion to reproduce the **CVE-2012-2459** root collision. **Consistency (append-only) proofs** get their own visualization — the old tree shaded inside the new one, with the proof's subtree roots marked — plus three history-tampering attacks (rewrite, delete, reorder) that the proof catches. Finally, the page verifies a **real Certificate Transparency entry**: a pinned Let's Encrypt certificate at index 1,234,567,890 of Google's Argon2026h1 log (2.8 billion certificates), proven included with 32 hashes using RFC 9162 index-based verification — the same code path as the rest of the lab. Learning objectives, predict-then-reveal prompts, self-check quizzes, glossary tooltips, a recap table, and further reading support active learning; **“Copy link to this tree”** deep-links any tree state for slides or assignments.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-merkle-proofs
cd crypto-lab-merkle-proofs
npm install
npm run dev
```

There are no environment variables. Run the test suite (RFC 6962 vectors, proof round-trips, tamper rejection, the second-preimage attack/defense, consistency proofs, fuzzing against an independent reference implementation, and the pinned real-world CT proof) with `npm test`.

`npm run test:a11y` runs the browser gate (Playwright). `e2e/claims.spec.ts` drives the real page and re-derives every verdict from what the page printed — INCLUDED only when the recomputed root shown equals the trusted root shown, ROOTS COLLIDE only when the two roots printed are equal, the efficiency headline from its own arithmetic — and walks each tamper path (leaf, proof bit, log rewrite/delete/reorder, the CT certificate bit-flip) to assert it reaches rejection, names the cause, and recovers. `e2e/a11y.spec.ts` is the axe-core WCAG A/AA scan. Both run in CI before every Pages deploy.

## Teaching With It

See **[TEACHING.md](TEACHING.md)** for an instructor guide: a 50-minute lesson flow, discussion questions, the misconceptions each section is designed to break, and homework extensions.

## Part of the Crypto-Lab Suite

> One of 170+ live browser demos at
> [systemslibrarian.github.io/crypto-lab](https://systemslibrarian.github.io/crypto-lab/)
> — spanning Atbash (600 BCE) through NIST FIPS 203/204/205 (2024).

---

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
