# Instructor Guide — Merkle Tree Proofs

This lab is designed to run as a guided 50-minute session or as self-paced homework. Everything below maps to numbered sections of the live page.

**Live demo:** [systemslibrarian.github.io/crypto-lab-merkle-proofs](https://systemslibrarian.github.io/crypto-lab-merkle-proofs/)

**Tip — deep links:** the *"Copy link to this tree"* button (section 2) stamps the current leaves and selection into the URL, so you can put an exact tree state on a slide or in an assignment. Example: a 5-leaf tree with leaf 3 selected is a single shareable URL.

## Suggested 50-minute lesson flow

| Time | Section | Beat |
|------|---------|------|
| 0–5 | 1–2 | Build a tree together. Add a leaf, watch the root change. Ask: *"what does this one hash 'know' about?"* |
| 5–15 | 3–4 | Pick a leaf, walk the proof with **Step ▸**. Have students predict each running hash's side before revealing. Expand *show bytes* once so they see there is no magic — just `0x00`/`0x01` prefixes and SHA-256. |
| 15–20 | 4 | Tamper. One student flips a proof bit, another changes the leaf. Verdict flips to REJECTED. Ask *why one bit is enough* (avalanche + chaining). |
| 20–25 | 4 | **The trust-model demo.** Run "Attack: prover supplies the root too." This is the highest-value 5 minutes of the session — most students believe verification alone proves inclusion until they watch a forged triple verify. |
| 25–30 | 5 | Efficiency slider to 2³⁰, then build a real 4,096-leaf tree. Anchor the numbers: a billion leaves → 30 hashes. |
| 30–38 | 6 | Break it twice: domain-separation toggle (forgery accepted → rejected), then CVE-2012-2459. Emphasize both were *real* production failures. |
| 38–46 | 7 | Consistency proofs. Use the tree diagram: the old prefix is shaded; the proof is just the marked subtree roots. Run all three attacks. Point out the honest limit: tampering *after* position m is invisible to that old root. |
| 46–50 | 8, 10 | Verify the real CT entry — 2.8 billion certificates, 32 hashes, in the browser. Close with the recap table. |

## Discussion questions

1. Why is proof size `⌈log₂ n⌉` and not `n/2` or `log₁₀ n`? What property of the tree gives the logarithm its base?
2. Where does the verifier's trusted root come from in Bitcoin? In Certificate Transparency? What breaks if that channel is compromised? (§4's attack demo is the setup for this.)
3. A plain inclusion proof cannot prove something is *absent*. Why not? What tree structure would you need? (Sorted / sparse Merkle trees.)
4. Bitcoin duplicates the odd node; RFC 6962 promotes it. Both "work." Why is one a CVE and the other fine?
5. A consistency proof for (m, n) verifies, but a certificate present in the size-m log doesn't appear when you search the size-n log. Is that a contradiction? (No — inclusion and consistency answer different questions; monitors need both.)
6. Why does CT need gossip between clients if tree heads are already signed? (A log could show different signed histories to different victims — split-view attacks.)

## Misconceptions to expect (and where the lab confronts them)

| Misconception | Reality | Where |
|---|---|---|
| "The proof verified, so the leaf is in *the* tree" | It's tied to *some* root; only the root's provenance gives that meaning | §4 trust demo |
| "The verifier needs the other leaves" | Only the leaf + sibling hashes; the other leaves never travel | §3–4 trace |
| "The 0x00/0x01 prefixes are formatting" | Removing them enables a working forgery, live | §6 toggle |
| "Consistency means nothing anywhere changed" | Only positions the *old root committed to* are protected | §7 honest-limit note |
| "This demo is a simplification of the real thing" | The same code verifies a real CT entry against a real log root | §8 |
| "Bitcoin's Merkle root should match this construction" | Double SHA-256, byte-reversed txids, no domain separation | §9 Bitcoin card |

## Homework extensions

- **Paper trace:** hand-compute the root of a 3-leaf tree (promote mode) with SHA-256 in any language, and check it against the lab. Forces engagement with promotion and prefixes.
- **Break it yourself:** given the lab's `src/merkle/security.ts`, explain in one paragraph why the forged "leaf" is exactly 64 bytes.
- **Fetch your own proof:** use any CT log's `get-proof-by-hash` endpoint for a certificate of a site you visit, and verify it with `verifyInclusionAtIndex` from `src/merkle/rfc9162.ts` (this repo runs in Node just fine — see `tests/ct.test.ts` for the pattern).
- **Design question:** sketch how you'd extend the tree to prove *non*-membership (sorted leaves + two adjacent inclusion proofs), and what new attack surface ordering introduces.

## Fidelity notes

- All hashing is real SHA-256 via WebCrypto; nothing is simulated.
- Trees follow RFC 6962 exactly (domain separation, odd-node promotion); the insecure variants exist only inside the two clearly-labeled security demos.
- Consistency generation follows RFC 6962 §2.1.2; verification follows RFC 9162 §2.1.4.2; index-based inclusion verification follows RFC 9162 §2.1.3.2.
- The CT fixture in section 8 is pinned real data (log, tree size, root, entry, audit path) fetched 2026-07-11 from Google's Argon2026h1 log; it verifies offline forever.
- The test suite includes fuzzing against an independently implemented recursive reference — see `tests/merkle.test.ts`.
