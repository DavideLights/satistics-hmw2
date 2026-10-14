Here is a direct, technical implementation plan for your homework web application, matching the minimalist monochrome dashboard design of your reference image.

---

### 1. Best JavaScript Library Selection

For experimenting with the complete Ethereum cryptographic pipeline inside a browser without build-step complexity or overengineering:

* **Primary Recommendation: `ethers.js` (v6 via CDN)**
* **Why:** A single UMD script import (`[https://cdnjs.cloudflare.com/ajax/libs/ethers/6.13.2/ethers.umd.min.js](https://cdnjs.cloudflare.com/ajax/libs/ethers/6.13.2/ethers.umd.min.js)`) exposes every primitive required by the assignment (`Mnemonic`, `HDNodeWallet`, `SigningKey`, `keccak256`, `getAddress`) natively in plain JavaScript.


* **Granular Alternative (for low-level inspection): `@noble` & `@scure` suites (`@scure/bip39`, `@scure/bip32`, `@noble/secp256k1`, `@noble/hashes`)**
* **Why:** Audited, zero-dependency libraries ideal if you want to inspect raw byte arrays at each intermediate step (e.g., viewing the exact 64-byte PBKDF2 output or uncompressed 65-byte EC point before slicing).



---

### 2. UI/UX & CSS Architecture (Reference Style)

The interface replicates the exact aesthetic of your screenshot:

* **Palette:** Pure white background (`#ffffff`), high-contrast black text (`#111111`), muted gray labels/subtitles (`#666666`), light gray card borders (`#e0e0e0`), and solid black primary buttons (`#111111`) paired with outlined secondary buttons.


* **Typography:** System sans-serif (`Inter`, `-apple-system`, `sans-serif`) for headings and explanations; clean monospace (`JetBrains Mono`, `Fira Code`, `monospace`) for hex digests, derivation paths, and equations.


* **Structure:** Vertical stack of numbered cards (`1. PIPELINE CONTROLS`, `2. STEP-BY-STEP DERIVATION TRACE`, `3. STATISTICAL PROPERTIES`, `4. TAXONOMY & HISTORICAL CONTEXT`), each with an uppercase bold title and a thin bottom border.



---

### 3. Application Modules & Content Plan

#### Header

* **Title:** **Ethereum Cryptographic Wallet Pipeline**
* **Subtitle:** Visualizing deterministic key derivation, elliptic-curve cryptography, hashing, and checksum encoding from BIP-39 to EIP-55.
* **Divider:** Solid `2px` black horizontal rule.



---

#### Section 1: Interactive Execution Controls (Card 1)

A 3-column control grid matching the reference layout:

* **Inputs:**
1. **Entropy / Mnemonic Phrase:** Text input (or 128-bit / 256-bit selector) + optional BIP-39 passphrase.
2. **BIP-44 Account & Index (`m/44'/60'/0'/0/i`):** Numeric input for address index `i` (default `0`).
3. **Test Vector Preset:** Dropdown to load standard test vectors or compare against live outputs from **MetaMask / Rabby**.


* **Actions:** Solid black **`Run Pipeline`** button and outlined **`Generate Random Entropy`** button.



---

#### Section 2: Live Pipeline Trace & Primitive Breakdown (Card 2)

A key-value specification grid displaying the live intermediate outputs alongside concise technical explanations:

1. **Entropy & BIP-39 (Mnemonic & Seed Generation):**
* *Live Output:* 128-bit Raw Hex Entropy $\rightarrow$ 12 Mnemonic Words $\rightarrow$ 512-bit Seed Hex.
* *Role:* Encodes CSPRNG entropy (128 bits + 4-bit SHA-256 checksum = 132 bits, split into twelve 11-bit indices mapping to a 2048-word dictionary) for human-readable backup. Uses **PBKDF2-HMAC-SHA512** (2048 iterations, salt `"mnemonic" + passphrase`) to stretch the phrase into a 512-bit seed.


2. **BIP-32 & BIP-44 (HD Key Derivation & Path Standard):**
* *Live Output:* Master Extended Key (`xprv`), Chain Code (256-bit), Child Private Key $k$ at `m/44'/60'/0'/0/0`.
* *Role:* **BIP-32** uses **HMAC-SHA512** to deterministically derive child keys and chain codes from a single seed in a tree structure, supporting hardened derivation (preventing parent public key compromise from leaking the master tree) and unhardened derivation (allowing watch-only `xpub` wallets). **BIP-44** standardizes the 5-level tree hierarchy: `m / purpose' (44') / coin_type' (60' for ETH) / account' / change / address_index`.


3. **secp256k1 (Elliptic-Curve Public-Key Cryptography):**
* *Live Output:* Private scalar $k \in [1, n-1]$ $\rightarrow$ Uncompressed Public Key $Q = k \cdot G$ (`0x04` + 64-byte $X, Y$ coordinates).
* *Role:* Provides trapdoor one-wayness via the Elliptic Curve Discrete Logarithm Problem (ECDLP) over $\mathbb{F}_p$ ($y^2 \equiv x^3 + 7 \pmod p$). Used to derive the public key and sign transactions via ECDSA.




4. **Keccak-256 (Address Hashing):**
* *Live Output:* 32-byte digest of the 64-byte public key ($X \parallel Y$, stripping `0x04`) $\rightarrow$ Last 20 bytes (`160 bits`) prefixed with `0x`.
* *Role:* Compresses the 512-bit public key into a fixed 160-bit identifier while providing preimage and collision resistance.


5. **EIP-55 (Mixed-Case Checksum Encoding):**
* *Live Output:* Lowercase hex hash (`keccak256(ascii_address)`) $\rightarrow$ Final mixed-case address (char $i$ uppercase if nibble $i \ge 8$).
* *Role:* Embeds an error-detection checksum directly into the hexadecimal casing without changing the address length or breaking backwards compatibility.



---

#### Section 3: Statistical Properties & Visual Verification (Card 3)

Interactive plain-JS `<canvas>` plots (monochrome bar charts/metrics) demonstrating the statistical properties of the pipeline:

* **Uniformity & Entropy Preservation:**
* *Concept:* True random key generation occurs only at the initial CSPRNG step. Every subsequent step is deterministic. However, cryptographic PRF/hashing primitives (HMAC-SHA512, Keccak-256) act as randomness extractors/expanders, ensuring outputs are computationally indistinguishable from a uniform distribution over their target spaces ($\mathbb{Z}_n$ for keys, $\{0,1\}^{256}$ for hashes).


* **Interactive Avalanche Effect Test (Bit-Flip Experiment):**
* *Control:* A button to flip 1 bit in the seed/private key or increment index `i` by 1.
* *Visualization:* A simple bar/metric showing the **Hamming distance** between the previous and new Keccak-256 output, empirically confirming the Strict Avalanche Criterion ($p \approx 0.5$, flipping $\sim 128$ of 256 bits) and uniform nibble distribution ($\chi^2$ goodness-of-fit across hex digits `0-f`).


* **EIP-55 Error Detection Probability:**
* *Statistic:* Because an Ethereum address has 40 hex characters and roughly $40 \times \frac{6}{16} = 15$ alphabetic characters (`a–f`), random casing yields $2^{15}$ combinations, achieving a **$99.997\%$ ($1 - 2^{-15}$) detection rate** against random typing/transcription errors.



---

#### Section 4: Taxonomic Distinctions & Historical Context (Card 4)

Clean, structured tables and direct bullet points answering the theoretical prompts:

1. **Core Cryptographic Distinctions:**
* **Key Generation vs. Key Derivation:** Generation samples fresh physical/OS entropy via a CSPRNG (non-deterministic); derivation deterministically expands an existing secret into child keys using PRF/HMAC functions (BIP-32/39).
* **Public-Key Cryptography:** Asymmetric mathematical trapdoors (secp256k1 ECDLP) enabling public verification of private signatures.
* **Hashing:** One-way, fixed-length compression (SHA-512, Keccak-256) providing preimage, second-preimage, and collision resistance.
* **Checksums:** Redundant data derived from a payload to detect accidental corruption/typos (BIP-39 4-bit SHA-256 tail; EIP-55 casing), offering no cryptographic security against intentional tampering.
* **Encoding:** Reversible format translation for human usability or transport (11-bit binary to BIP-39 English words; raw bytes to Hexadecimal) with zero security properties.


2. **Why Multiple Primitives Instead of One Single Algorithm?**
* *Separation of Concerns & Algebraic Incompatibility:* A single primitive cannot satisfy conflicting mathematical requirements. Asymmetric signatures require rich algebraic group structure (abelian group over secp256k1 points), whereas hash functions and KDFs must destroy algebraic structure through non-linear confusion and diffusion (sponge construction / ARX) to prevent structural shortcuts. Checksums and encodings optimize for human transcription ergonomics rather than computational hardness.


3. **Chronological Timeline & SHA-2 vs. Keccak/SHA-3:**
* **Timeline:** **RSA (1977)** [Foundational asymmetric crypto] $\rightarrow$ **SHA-2 / SHA-512 (2001)** [NSA/NIST Merkle–Damgård hash standard] $\rightarrow$ **BIP-32 (2012)** [HD wallets] $\rightarrow$ **BIP-39 (2013)** [Mnemonic seeds using SHA-512] $\rightarrow$ **BIP-44 (2014)** [Multi-coin paths] $\rightarrow$ **SHA-3 (2015)** [NIST sponge-based hash standard] $\rightarrow$ **EIP-55 (2016)** [Vitalik Buterin's backward-compatible hex checksum].
* **SHA-2/512 vs. Keccak-256 vs. SHA3-256:**
* *Construction:* SHA-2 uses the **Merkle–Damgård** construction (vulnerable to length-extension attacks in raw form), whereas Keccak/SHA-3 uses the **sponge construction** (absorbing input and squeezing output via state permutations).
* *Ethereum's Keccak-256 vs. NIST SHA3-256:* Ethereum launched in July 2015 right as NIST finalized FIPS 202 (August 2015). NIST changed the domain-separation padding byte from original Keccak's `0x01` to `0x06` (`01` bit string + `10*1` pad). Consequently, `Keccak-256(x) != SHA3-256(x)` for the exact same input.





---

### 4. JavaScript Architecture (Zero Overengineering)

* **Single-File Structure:** Standard `index.html`, `style.css`, and `app.js` (or combined into a single self-contained HTML file).
* **Procedural Flow:**
* One main function `runPipeline()` triggered on button click or input change.
* Sequential execution: `entropy -> mnemonic -> seed -> hdNode -> keyPair -> keccakHash -> eip55Address`.
* Direct `document.getElementById(...).textContent = ...` updates—no virtual DOM, no reactive state managers, no classes.
* One small helper function `drawAvalancheChart(hashA, hashB)` using native 2D `<canvas>` `fillRect` calls to render the bit-flip comparison and hex frequency bars in monochrome black/gray.



---

Would you like me to generate the complete, self-contained HTML/CSS/JS code for this application now?