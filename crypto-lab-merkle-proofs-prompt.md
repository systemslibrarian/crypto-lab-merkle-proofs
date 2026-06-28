# Prompt: Create "crypto-lab-merkle-proofs-prompt" Demo

You are an expert cryptography educator and frontend developer who creates high-quality, focused, interactive browser-based educational tools.

## Project Goal
Create a new standalone browser demo called **Merkle Tree Proofs** that helps students deeply understand how Merkle trees work, how Merkle proofs are generated, and how they can be efficiently verified — even for very large datasets.

## Why This Is Valuable for Students
Merkle trees are a foundational data structure in cryptography and distributed systems (used in Bitcoin, Ethereum, Git, certificate transparency, etc.). While many students learn the basic concept, few get hands-on experience with:

- How a Merkle proof actually works
- Why Merkle proofs are so efficient (logarithmic size)
- How verification works without needing the entire tree
- The security properties (collision resistance, etc.)

An interactive demo that lets students build trees, generate proofs, and verify them helps turn an abstract concept into something concrete and memorable.

## Learning Objectives
By using this demo, a student should be able to:
- Explain how a Merkle tree is constructed from a set of data blocks
- Generate a Merkle proof for a specific leaf
- Verify a Merkle proof efficiently using only the proof and the root hash
- Understand why the proof size grows logarithmically with the number of leaves
- Recognize real-world applications of Merkle proofs (blockchains, Git, certificate transparency, etc.)

## Required Sections & Flow

### 1. What is a Merkle Tree?
- Clear explanation of the structure (binary tree of hashes).
- Show how leaf nodes contain data hashes and internal nodes contain hashes of their children.
- Visual representation of a small Merkle tree.

### 2. Interactive Tree Builder
- Allow the user to add/remove data blocks (leaves).
- Automatically build and display the Merkle tree.
- Show hash values at each node (use a simple hash function like SHA-256 truncated for readability, or a toy hash).

### 3. Merkle Proof Generation (Core Feature)
- User selects a specific leaf.
- The demo generates and displays the Merkle proof (the minimal set of sibling hashes needed to reconstruct the root).
- Visualize which nodes are included in the proof and why.

### 4. Merkle Proof Verification
- Show how a verifier can take the proof + the leaf data + the root hash and efficiently verify inclusion.
- Allow the user to tamper with either the leaf or part of the proof and see verification fail.
- Highlight why verification is much faster than rebuilding the entire tree.

### 5. Efficiency and Security
- Show how proof size grows with tree depth (logarithmic scaling).
- Demonstrate collision resistance: why it’s hard to create a fake proof that verifies against the correct root.
- Optional: Compare proof size vs full tree size as the number of leaves increases.

### 6. Real-World Applications
- Brief but clear examples:
  - Bitcoin and Ethereum transaction inclusion
  - Git commit history and object storage
  - Certificate Transparency logs
  - Stateless clients / light clients in blockchains
- Keep this section educational and high-level.

## Technical Preferences
- Browser-native (HTML + TypeScript/JavaScript). Canvas or SVG recommended for clean tree visualization.
- Use a real hash function (SHA-256) but display truncated or readable versions for clarity.
- Support reasonably large trees (hundreds or thousands of leaves) while keeping the UI responsive.
- Clean, focused, educational aesthetic consistent with Crypto Lab demos.
- Strong emphasis on visual clarity of the tree structure and proof path.

## Relationship to Existing Work
- This would deepen and complement the existing `Merkle Vault` demo by focusing specifically on **proof generation and verification**.
- It has strong connections to blockchain-related demos (e.g., `Bitcoin Wallet`).

## Output Requested
Please provide:
1. A recommended final display title for the demo page
2. High-level architecture and component breakdown
3. Key interactive elements (tree building, proof generation, verification)
4. Suggested visualization approach for the tree and proof path
5. How to handle larger trees while keeping the experience smooth
6. Any important pedagogical notes

Start with the proposed structure, then we can iterate on implementation details.
