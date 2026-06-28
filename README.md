# crypto-lab-merkle-proofs

## What It Is

This is an interactive demo of **Merkle trees** and **Merkle inclusion proofs**, built on **SHA-256** via the browser's WebCrypto API. A Merkle tree hashes a set of data blocks into a single root hash that commits to all of them at once; an inclusion proof is the short list of sibling hashes that lets anyone re-derive that root from a single leaf. The security model is purely **hash-based**: it relies on the collision and second-preimage resistance of SHA-256, with no keys or signatures involved. Hashing follows **RFC 6962** domain separation (`leaf = SHA-256(0x00 ∥ data)`, `node = SHA-256(0x01 ∥ left ∥ right)`), which is what makes the second-preimage defense in the demo real rather than decorative. It is a teaching tool, not a production library.

## When to Use It

- **To prove one element belongs to a large committed set, cheaply.** A proof is `⌈log₂ n⌉` hashes, so a single transaction can be shown to be in a block of millions without sending the block.
- **To detect tampering against a trusted root.** If you already hold the root, you can verify any leaf+proof and reject anything that doesn't recompute to it.
- **To give light clients integrity without full state.** SPV wallets and stateless clients check membership against a header's root instead of downloading everything.
- **To make a log verifiably append-only.** Certificate Transparency uses exactly this RFC 6962 construction.
- **Do NOT use a Merkle proof to prove *non*-membership or order** unless the tree is specifically a sorted/sparse Merkle tree — a plain inclusion proof says nothing about what is absent, and a tree built without domain separation is open to second-preimage forgery.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-merkle-proofs](https://systemslibrarian.github.io/crypto-lab-merkle-proofs/)**

Add or remove data blocks to build a tree live, choose any leaf to generate its inclusion proof, then verify it — recomputing the root from only the leaf and its sibling hashes. You can **step through or animate** the recompute one hash at a time (watching the running hash climb the tree), expand **“show bytes”** on any step to see the exact SHA-256 preimage (`0x00 ∥ data` for leaves, `0x01 ∥ L ∥ R` for nodes), tamper with the leaf or flip a bit in any proof step and watch verification flip to REJECTED, and scale a slider to see proofs stay logarithmic up to 2³⁰ leaves (plus build real 256–4,096-leaf trees). Two security demos let you toggle RFC 6962 domain separation on/off to make the second-preimage forgery succeed then fail, and compare Bitcoin's odd-node duplication against RFC 6962 promotion to reproduce the **CVE-2012-2459** root collision. Predict-then-reveal prompts, self-check quizzes, and glossary tooltips support active learning.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-merkle-proofs
cd crypto-lab-merkle-proofs
npm install
npm run dev
```

There are no environment variables. Run the test suite (RFC 6962 vectors, proof round-trips, tamper rejection, and the second-preimage attack/defense) with `npm test`.

## Part of the Crypto-Lab Suite

> One of 60+ live browser demos at
> [systemslibrarian.github.io/crypto-lab](https://systemslibrarian.github.io/crypto-lab/)
> — spanning Atbash (600 BCE) through NIST FIPS 203/204/205 (2024).

---

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
