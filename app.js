/**
 * Ethereum Cryptographic Wallet Pipeline — Procedural JavaScript
 * 
 * Pipeline: Entropy -> BIP-39 (Mnemonic & Seed) -> BIP-32/BIP-44 (HD Key Derivation) 
 *           -> secp256k1 (Public Key EC Multiplication) -> Keccak-256 -> EIP-55 Checksum
 */

(function () {
  "use strict";

  // Pre-configured test vectors
  const TEST_VECTORS = {
    metamask: {
      phrase: "test test test test test test test test test test test junk",
      bits: 128,
      passphrase: "",
      note: "Standard MetaMask & Hardhat local development seed"
    },
    trezor: {
      entropy: "00000000000000000000000000000000",
      phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
      bits: 128,
      passphrase: "",
      note: "Standard BIP-39 Vector 1 (Trezor suite)"
    },
    allzero: {
      entropy: "00000000000000000000000000000000",
      phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
      bits: 128,
      passphrase: "TREZOR",
      note: "All-zero entropy with passphrase salt extension"
    },
    allones: {
      entropy: "ffffffffffffffffffffffffffffffff",
      phrase: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
      bits: 128,
      passphrase: "",
      note: "All-ones entropy standard vector"
    }
  };

  // State management
  let currentEntropyBits = 128;
  let previousDigest = null;
  let currentDigest = null;
  let currentCanonicalAddress = "";
  let lastExecutionState = null;

  // DOM Elements
  const presetSelect = document.getElementById("presetSelect");
  const entropyLengthControl = document.getElementById("entropyLengthControl");
  const passphraseInput = document.getElementById("passphraseInput");
  const entropyPhraseInput = document.getElementById("entropyPhraseInput");
  const addressIndex = document.getElementById("addressIndex");
  const pathPreview = document.getElementById("pathPreview");
  const btnIndexPrev = document.getElementById("btnIndexPrev");
  const btnIndexNext = document.getElementById("btnIndexNext");
  const btnRun = document.getElementById("btnRun");
  const btnRandom = document.getElementById("btnRandom");
  const btnBitFlip = document.getElementById("btnBitFlip");
  const btnCopyTrace = document.getElementById("btnCopyTrace");
  const perfTime = document.getElementById("perfTime");
  const pipelineStatus = document.getElementById("pipelineStatus");
  const toast = document.getElementById("toast");

  // Trace DOM Elements
  const entropyBitLength = document.getElementById("entropyBitLength");
  const dispEntropyHex = document.getElementById("dispEntropyHex");
  const dispChecksumBits = document.getElementById("dispChecksumBits");
  const dispChecksumNote = document.getElementById("dispChecksumNote");
  const dispMnemonicWords = document.getElementById("dispMnemonicWords");
  const dispSalt = document.getElementById("dispSalt");
  const dispSeedHex = document.getElementById("dispSeedHex");

  const dispMasterXprv = document.getElementById("dispMasterXprv");
  const dispMasterChainCode = document.getElementById("dispMasterChainCode");
  const dispTargetDerivationPath = document.getElementById("dispTargetDerivationPath");
  const dispChildPrivKey = document.getElementById("dispChildPrivKey");
  const dispChildChainCode = document.getElementById("dispChildChainCode");
  const dispChildXpub = document.getElementById("dispChildXpub");

  const dispCoordX = document.getElementById("dispCoordX");
  const dispCoordY = document.getElementById("dispCoordY");
  const dispCurveCheck = document.getElementById("dispCurveCheck");
  const dispUncompressedPub = document.getElementById("dispUncompressedPub");
  const dispCompressedPub = document.getElementById("dispCompressedPub");

  const dispPreHashPayload = document.getElementById("dispPreHashPayload");
  const dispKeccakDigest = document.getElementById("dispKeccakDigest");
  const dispSplitDiscard = document.getElementById("dispSplitDiscard");
  const dispSplitKeep = document.getElementById("dispSplitKeep");
  const dispRawAddress = document.getElementById("dispRawAddress");

  const dispAsciiHash = document.getElementById("dispAsciiHash");
  const eip55InspectorGrid = document.getElementById("eip55InspectorGrid");
  const dispFinalAddress = document.getElementById("dispFinalAddress");

  // Stats Elements
  const btnRunBitFlip = document.getElementById("btnRunBitFlip");
  const btnNextIndexFlip = document.getElementById("btnNextIndexFlip");
  const metricHamming = document.getElementById("metricHamming");
  const metricHammingPct = document.getElementById("metricHammingPct");
  const metricSacStatus = document.getElementById("metricSacStatus");
  const metricSacSub = document.getElementById("metricSacSub");
  const metricChiSquare = document.getElementById("metricChiSquare");
  const metricChiStatus = document.getElementById("metricChiStatus");
  const avalancheMatrixCanvas = document.getElementById("avalancheMatrixCanvas");
  const nibbleHistCanvas = document.getElementById("nibbleHistCanvas");

  // Tamper Elements
  const tamperInput = document.getElementById("tamperInput");
  const btnInjectTypo = document.getElementById("btnInjectTypo");
  const btnToggleCase = document.getElementById("btnToggleCase");
  const btnResetTamper = document.getElementById("btnResetTamper");
  const tamperStatusPill = document.getElementById("tamperStatusPill");
  const tamperStatsReadout = document.getElementById("tamperStatsReadout");

  /**
   * Display toast notification
   */
  function showToast(message) {
    if (!toast) return;
    toast.textContent = message;
    toast.classList.remove("hidden");
    clearTimeout(toast._timeout);
    toast._timeout = setTimeout(() => {
      toast.classList.add("hidden");
    }, 2000);
  }

  /**
   * Helper: Hex to binary string with fixed width
   */
  function hexToBinary(hexStr, bitCount) {
    const clean = hexStr.startsWith("0x") ? hexStr.slice(2) : hexStr;
    let bin = "";
    for (let i = 0; i < clean.length; i++) {
      const n = parseInt(clean[i], 16);
      bin += n.toString(2).padStart(4, "0");
    }
    return bitCount ? bin.slice(0, bitCount) : bin;
  }

  /**
   * Helper: Convert uint8 array to hex string
   */
  function bytesToHex(bytes) {
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");
  }

  /**
   * Helper: Convert hex string to Uint8Array
   */
  function hexToBytes(hex) {
    const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < clean.length; i += 2) {
      bytes[i / 2] = parseInt(clean.substr(i, 2), 16);
    }
    return bytes;
  }

  /**
   * Verify secp256k1 curve equation: y^2 = x^3 + 7 (mod p)
   */
  function verifySecp256k1(xHex, yHex) {
    try {
      const P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
      const x = BigInt(xHex);
      const y = BigInt(yHex);
      const lhs = (y * y) % P;
      const rhs = ((x * x * x + 7n) % P + P) % P;
      return lhs === rhs;
    } catch (e) {
      return false;
    }
  }

  /**
   * Core derivation pipeline execution
   */
  function runPipeline() {
    if (!window.ethers) {
      pipelineStatus.textContent = "STATUS: ERROR (ethers.js not loaded)";
      return;
    }

    const tStart = performance.now();
    pipelineStatus.textContent = "STATUS: COMPUTING...";

    try {
      const phraseOrEntropy = entropyPhraseInput.value.trim();
      const passphrase = passphraseInput.value;
      const indexVal = parseInt(addressIndex.value, 10) || 0;
      const path = `m/44'/60'/0'/0/${indexVal}`;
      pathPreview.textContent = path;
      dispTargetDerivationPath.textContent = path;

      let mnemonicObj = null;
      let rawEntropyHex = "";

      // Check if input is a hex string (16 or 32 bytes)
      const cleanHex = phraseOrEntropy.replace(/^0x/, "").replace(/\s+/g, "");
      const isHex = /^[0-9a-fA-F]+$/.test(cleanHex) && (cleanHex.length === 32 || cleanHex.length === 64);

      if (isHex) {
        rawEntropyHex = "0x" + cleanHex.toLowerCase();
        mnemonicObj = ethers.Mnemonic.fromEntropy(rawEntropyHex);
      } else {
        // Assume phrase
        mnemonicObj = ethers.Mnemonic.fromPhrase(phraseOrEntropy);
        rawEntropyHex = mnemonicObj.entropy;
      }

      currentEntropyBits = rawEntropyHex.slice(2).length * 4;
      entropyBitLength.textContent = currentEntropyBits.toString();

      // Update segment control buttons visually
      document.querySelectorAll(".segment-btn").forEach(btn => {
        btn.classList.toggle("active", parseInt(btn.dataset.bits, 10) === currentEntropyBits);
      });

      // 1. STEP 1: BIP-39 Display
      dispEntropyHex.textContent = rawEntropyHex;
      
      // Compute checksum bits
      const sha256Entropy = ethers.sha256(rawEntropyHex);
      const csLength = currentEntropyBits / 32; // 4 bits for 128-bit, 8 bits for 256-bit
      const checksumBits = hexToBinary(sha256Entropy, csLength);
      dispChecksumBits.textContent = checksumBits;
      dispChecksumNote.textContent = `(${csLength} bits from SHA-256 tail appended)`;

      // Render mnemonic words
      const words = mnemonicObj.phrase.split(" ");
      dispMnemonicWords.innerHTML = words.map((w, i) => `
        <div class="word-pill">
          <span class="word-index">${i + 1}.</span>
          <span class="word-text">${w}</span>
        </div>
      `).join("");

      // Salt and Seed
      const saltStr = `"mnemonic${passphrase}"`;
      dispSalt.textContent = saltStr;
      const seedHex = mnemonicObj.computeSeed(passphrase);
      dispSeedHex.textContent = seedHex;

      // 2. STEP 2: BIP-32 & BIP-44 Derivation
      const hdNode = ethers.HDNodeWallet.fromSeed(seedHex);
      dispMasterXprv.textContent = hdNode.extendedKey;
      dispMasterChainCode.textContent = hdNode.chainCode;

      const childNode = hdNode.derivePath(path);
      const childPrivKey = childNode.privateKey;
      const childChainCode = childNode.chainCode;
      const childXpub = childNode.neuter().extendedKey;

      dispChildPrivKey.textContent = childPrivKey;
      dispChildChainCode.textContent = childChainCode;
      dispChildXpub.textContent = childXpub;

      // 3. STEP 3: secp256k1 Curve Multiplication
      const signingKey = new ethers.SigningKey(childPrivKey);
      const uncompressedPub = signingKey.publicKey; // 0x04 + 64 bytes (130 hex chars)
      const compressedPub = signingKey.compressedPublicKey; // 0x02/0x03 + 32 bytes

      const qx = "0x" + uncompressedPub.slice(4, 68);
      const qy = "0x" + uncompressedPub.slice(68, 132);

      dispCoordX.textContent = qx;
      dispCoordY.textContent = qy;
      dispUncompressedPub.textContent = uncompressedPub;
      dispCompressedPub.textContent = compressedPub;

      const isValidCurve = verifySecp256k1(qx, qy);
      dispCurveCheck.textContent = isValidCurve ? "Q ∈ secp256k1 (VALID)" : "ERROR: Point not on curve";
      dispCurveCheck.className = isValidCurve ? "badge badge-success" : "badge badge-error";

      // 4. STEP 4: Keccak-256 & Truncation
      const preHashPayload = "0x" + uncompressedPub.slice(4); // 64 bytes
      const keccakDigest = ethers.keccak256(preHashPayload); // 32 bytes

      dispPreHashPayload.textContent = preHashPayload;
      dispKeccakDigest.textContent = keccakDigest;

      const discardPart = keccakDigest.slice(2, 26); // first 12 bytes
      const keepPart = keccakDigest.slice(26);       // last 20 bytes
      dispSplitDiscard.textContent = "0x" + discardPart;
      dispSplitKeep.textContent = keepPart;

      const rawAddress = "0x" + keepPart.toLowerCase();
      dispRawAddress.textContent = rawAddress;

      // 5. STEP 5: EIP-55 Mixed-Case Checksum
      const addrClean = rawAddress.slice(2);
      const asciiHash = ethers.keccak256(ethers.toUtf8Bytes(addrClean));
      dispAsciiHash.textContent = asciiHash;

      // Build character-by-character inspector
      const hashNibbles = asciiHash.slice(2);
      let checksummedAddr = "0x";
      let inspectorHTML = "";

      for (let i = 0; i < 40; i++) {
        const char = addrClean[i];
        const nibbleVal = parseInt(hashNibbles[i], 16);
        let finalChar = char;
        let cellType = "type-digit";

        if (/[a-f]/.test(char)) {
          if (nibbleVal >= 8) {
            finalChar = char.toUpperCase();
            cellType = "type-upper";
          } else {
            finalChar = char.toLowerCase();
            cellType = "type-lower";
          }
        }

        checksummedAddr += finalChar;

        inspectorHTML += `
          <div class="eip55-cell ${cellType}" title="Index ${i}: '${char}' with hash nibble 0x${hashNibbles[i]} (dec ${nibbleVal}) -> '${finalChar}'">
            <span class="eip55-char">${finalChar}</span>
            <span class="eip55-nibble">${hashNibbles[i]}</span>
          </div>
        `;
      }

      eip55InspectorGrid.innerHTML = inspectorHTML;
      dispFinalAddress.textContent = checksummedAddr;
      currentCanonicalAddress = checksummedAddr;

      // Also verify with ethers.getAddress
      const canonicalEthers = ethers.getAddress(rawAddress);
      if (checksummedAddr !== canonicalEthers) {
        console.warn("EIP-55 mismatch:", checksummedAddr, "vs ethers:", canonicalEthers);
      }

      // 6. Update Stats & Comparisons
      previousDigest = currentDigest;
      currentDigest = keccakDigest;

      updateAvalancheStats(previousDigest, currentDigest);
      drawNibbleHistogram(keccakDigest);

      // 7. Update Tamper Box
      tamperInput.value = checksummedAddr;
      validateTamperInput(checksummedAddr);

      // Save execution state
      lastExecutionState = {
        entropyHex: rawEntropyHex,
        phrase: mnemonicObj.phrase,
        passphrase,
        seedHex,
        path,
        privKey: childPrivKey,
        pubKey: uncompressedPub,
        keccakDigest,
        address: checksummedAddr
      };

      const tEnd = performance.now();
      perfTime.textContent = (tEnd - tStart).toFixed(2) + " ms";
      pipelineStatus.textContent = "STATUS: READY";

    } catch (err) {
      console.error(err);
      pipelineStatus.textContent = "STATUS: ERROR (" + err.message + ")";
    }
  }

  /**
   * Statistical Analysis: Strict Avalanche Criterion (SAC)
   */
  function updateAvalancheStats(prevHex, currHex) {
    if (!prevHex || !currHex || prevHex === currHex) {
      metricHamming.textContent = "0 / 256";
      metricHammingPct.textContent = "(0.00%)";
      metricSacStatus.textContent = "AWAITING COMPARISON";
      metricSacSub.textContent = "Click 'Flip 1 Bit' above to test avalanche";
      drawAvalancheMatrix(null);
      return;
    }

    const prevBin = hexToBinary(prevHex, 256);
    const currBin = hexToBinary(currHex, 256);

    let diffCount = 0;
    const diffMap = [];

    for (let i = 0; i < 256; i++) {
      const isDiff = prevBin[i] !== currBin[i];
      if (isDiff) diffCount++;
      diffMap.push(isDiff);
    }

    const pct = (diffCount / 256) * 100;
    metricHamming.textContent = `${diffCount} / 256`;
    metricHammingPct.textContent = `(${pct.toFixed(2)}%)`;

    // SAC tolerance: 50% +/- 10% (40% - 60% is typical for single sample 256-bit hash)
    if (pct >= 40 && pct <= 60) {
      metricSacStatus.textContent = "PASS (SAC COMPLIANT)";
      metricSacSub.textContent = `Flipped ${diffCount} bits (within 50% ± 10% normal variance)`;
    } else {
      metricSacStatus.textContent = "EVALUATED";
      metricSacSub.textContent = `Flipped ${diffCount} bits (expected ~128 bits)`;
    }

    drawAvalancheMatrix(diffMap);
  }

  /**
   * Render 256-bit difference matrix canvas (8 rows x 32 cols)
   */
  function drawAvalancheMatrix(diffMap) {
    const canvas = avalancheMatrixCanvas;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const width = canvas.width;
    const height = canvas.height;

    ctx.fillStyle = "#ffffff";
    ctx.fillRect(0, 0, width, height);

    const cols = 32;
    const rows = 8;
    const paddingX = 14;
    const paddingY = 12;
    const cellW = (width - paddingX * 2) / cols;
    const cellH = (height - paddingY * 2) / rows;

    for (let r = 0; r < rows; r++) {
      for (let c = 0; c < cols; c++) {
        const idx = r * cols + c;
        const x = paddingX + c * cellW;
        const y = paddingY + r * cellH;

        if (diffMap && diffMap[idx]) {
          // Flipped bit: solid black
          ctx.fillStyle = "#111111";
          ctx.fillRect(x + 1, y + 1, cellW - 2, cellH - 2);
        } else {
          // Unchanged: light border
          ctx.fillStyle = "#fafafa";
          ctx.fillRect(x + 1, y + 1, cellW - 2, cellH - 2);
          ctx.strokeStyle = "#e0e0e0";
          ctx.lineWidth = 1;
          ctx.strokeRect(x + 0.5, y + 0.5, cellW - 1, cellH - 1);
        }
      }
    }
  }

  /**
   * Render Hex Nibble Frequency Histogram & Chi-Square Test
   */
  function drawNibbleHistogram(keccakHex) {
    const canvas = nibbleHistCanvas;
    if (!canvas || !keccakHex) return;
    const ctx = canvas.getContext("2d");
    const width = canvas.width;
    const height = canvas.height;

    ctx.fillStyle = "#ffffff";
    ctx.fillRect(0, 0, width, height);

    // Count frequencies of 0-f in 64 hex characters (without 0x)
    const cleanHex = keccakHex.slice(2).toLowerCase();
    const counts = new Array(16).fill(0);
    for (let i = 0; i < cleanHex.length; i++) {
      const val = parseInt(cleanHex[i], 16);
      if (!isNaN(val)) counts[val]++;
    }

    // Expected count: 64 / 16 = 4.0
    const expected = 64 / 16;
    let chiSq = 0;
    for (let i = 0; i < 16; i++) {
      chiSq += Math.pow(counts[i] - expected, 2) / expected;
    }

    metricChiSquare.textContent = `χ² = ${chiSq.toFixed(2)}`;
    // Critical value for df=15 at alpha=0.05 is 24.996
    if (chiSq < 25.0) {
      metricChiStatus.textContent = "(Uniform: p > 0.05)";
    } else {
      metricChiStatus.textContent = "(Deviates: p ≤ 0.05)";
    }

    // Draw Histogram
    const paddingLeft = 24;
    const paddingRight = 14;
    const paddingTop = 20;
    const paddingBottom = 26;
    const plotW = width - paddingLeft - paddingRight;
    const plotH = height - paddingTop - paddingBottom;
    const barW = plotW / 16;
    const maxVal = Math.max(8, ...counts);

    // Draw grid lines
    ctx.strokeStyle = "#e8e8e8";
    ctx.lineWidth = 1;
    for (let v = 0; v <= maxVal; v += 2) {
      const y = paddingTop + plotH - (v / maxVal) * plotH;
      ctx.beginPath();
      ctx.moveTo(paddingLeft, y);
      ctx.lineTo(width - paddingRight, y);
      ctx.stroke();

      ctx.fillStyle = "#888888";
      ctx.font = "9px " + (getComputedStyle(document.body).fontFamily || "sans-serif");
      ctx.textAlign = "right";
      ctx.fillText(v.toString(), paddingLeft - 4, y + 3);
    }

    // Draw Expected line (at 4.0)
    const expY = paddingTop + plotH - (expected / maxVal) * plotH;
    ctx.setLineDash([4, 3]);
    ctx.strokeStyle = "#666666";
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    ctx.moveTo(paddingLeft, expY);
    ctx.lineTo(width - paddingRight, expY);
    ctx.stroke();
    ctx.setLineDash([]); // reset

    // Draw bars
    for (let i = 0; i < 16; i++) {
      const count = counts[i];
      const h = (count / maxVal) * plotH;
      const x = paddingLeft + i * barW + 4;
      const y = paddingTop + plotH - h;
      const w = barW - 8;

      ctx.fillStyle = "#111111";
      ctx.fillRect(x, y, w, h);

      // Hex label
      const hexChar = i.toString(16);
      ctx.fillStyle = "#111111";
      ctx.font = "10px monospace";
      ctx.textAlign = "center";
      ctx.fillText(hexChar, paddingLeft + i * barW + barW / 2, height - 8);
    }
  }

  /**
   * EIP-55 Tamper input live validation
   */
  function validateTamperInput(inputStr) {
    const val = inputStr.trim();
    if (!/^0x[0-9a-fA-F]{40}$/.test(val)) {
      tamperStatusPill.textContent = "INVALID FORMAT (Must be 0x + 40 hex characters)";
      tamperStatusPill.className = "tamper-status-pill error";
      return;
    }

    try {
      const canonical = ethers.getAddress(val.toLowerCase());
      if (val === canonical) {
        tamperStatusPill.textContent = "VALID EIP-55 CHECKSUM";
        tamperStatusPill.className = "tamper-status-pill";
      } else {
        // Find discrepancy
        let firstDiff = -1;
        for (let i = 2; i < 42; i++) {
          if (val[i] !== canonical[i]) {
            firstDiff = i - 2;
            break;
          }
        }
        tamperStatusPill.textContent = `TAMPER DETECTED: Casing mismatch at character #${firstDiff}`;
        tamperStatusPill.className = "tamper-status-pill error";
      }

      // Count letters
      const lettersCount = (val.slice(2).match(/[a-fA-F]/g) || []).length;
      const combos = Math.pow(2, lettersCount);
      const prob = (1 - (1 / combos)) * 100;
      tamperStatsReadout.innerHTML = `
        Letters in address: <strong>${lettersCount}</strong> | 
        Permutation space: <strong>2<sup>${lettersCount}</sup> = ${combos.toLocaleString()}</strong> | 
        Error detection rate: <strong>${prob.toFixed(3)}%</strong>
      `;

    } catch (e) {
      tamperStatusPill.textContent = "TAMPER DETECTED: Invalid Checksum";
      tamperStatusPill.className = "tamper-status-pill error";
    }
  }

  /**
   * Event listeners setup
   */
  function setupEventListeners() {
    // Preset change
    presetSelect.addEventListener("change", () => {
      const key = presetSelect.value;
      if (key === "custom") return;
      const vec = TEST_VECTORS[key];
      if (!vec) return;

      if (vec.phrase) {
        entropyPhraseInput.value = vec.phrase;
      } else if (vec.entropy) {
        entropyPhraseInput.value = vec.entropy;
      }
      passphraseInput.value = vec.passphrase || "";
      runPipeline();
    });

    // Entropy Length segmented control
    entropyLengthControl.querySelectorAll(".segment-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        const bits = parseInt(btn.dataset.bits, 10);
        if (bits === currentEntropyBits) return;
        currentEntropyBits = bits;
        
        // Generate new random entropy of selected bit size
        const byteCount = bits / 8;
        const randomBytes = ethers.randomBytes(byteCount);
        const randomHex = "0x" + bytesToHex(randomBytes);
        const mn = ethers.Mnemonic.fromEntropy(randomHex);
        entropyPhraseInput.value = mn.phrase;
        presetSelect.value = "custom";
        runPipeline();
      });
    });

    // Stepper buttons for address index
    btnIndexPrev.addEventListener("click", () => {
      let idx = parseInt(addressIndex.value, 10) || 0;
      if (idx > 0) {
        addressIndex.value = idx - 1;
        runPipeline();
      }
    });

    btnIndexNext.addEventListener("click", () => {
      let idx = parseInt(addressIndex.value, 10) || 0;
      addressIndex.value = idx + 1;
      runPipeline();
    });

    // Text input manual changes
    entropyPhraseInput.addEventListener("input", () => {
      presetSelect.value = "custom";
    });
    entropyPhraseInput.addEventListener("change", () => {
      presetSelect.value = "custom";
      runPipeline();
    });

    passphraseInput.addEventListener("input", () => {
      presetSelect.value = "custom";
    });
    passphraseInput.addEventListener("change", () => {
      presetSelect.value = "custom";
      runPipeline();
    });

    // Run Pipeline Button
    btnRun.addEventListener("click", () => {
      runPipeline();
    });

    // Generate Random Entropy Button
    btnRandom.addEventListener("click", () => {
      const byteCount = currentEntropyBits / 8;
      const randomBytes = ethers.randomBytes(byteCount);
      const randomHex = "0x" + bytesToHex(randomBytes);
      const mn = ethers.Mnemonic.fromEntropy(randomHex);
      entropyPhraseInput.value = mn.phrase;
      presetSelect.value = "custom";
      runPipeline();
    });

    // Flip 1 Bit in Entropy (Avalanche SAC test)
    function flipOneBitInEntropy() {
      if (!lastExecutionState) return;
      let rawHex = lastExecutionState.entropyHex.slice(2);
      const bytes = hexToBytes(rawHex);

      // Pick a random bit to invert
      const bitIndex = Math.floor(Math.random() * (bytes.length * 8));
      const byteIndex = Math.floor(bitIndex / 8);
      const bitInByte = bitIndex % 8;

      bytes[byteIndex] ^= (1 << bitInByte);

      const modifiedHex = "0x" + bytesToHex(bytes);
      const mn = ethers.Mnemonic.fromEntropy(modifiedHex);
      entropyPhraseInput.value = mn.phrase;
      presetSelect.value = "custom";

      showToast(`Inverted bit #${bitIndex} in entropy`);
      runPipeline();
    }

    btnBitFlip.addEventListener("click", flipOneBitInEntropy);
    btnRunBitFlip.addEventListener("click", flipOneBitInEntropy);

    // Increment index flip
    btnNextIndexFlip.addEventListener("click", () => {
      let idx = parseInt(addressIndex.value, 10) || 0;
      addressIndex.value = idx + 1;
      runPipeline();
    });

    // Copy Full Derivation Summary
    btnCopyTrace.addEventListener("click", () => {
      if (!lastExecutionState) return;
      const s = lastExecutionState;
      const text = [
        `# Ethereum Wallet Cryptographic Derivation Trace`,
        `* **BIP-39 Mnemonic:** ${s.phrase}`,
        `* **Passphrase:** ${s.passphrase ? `"${s.passphrase}"` : `(empty)`}`,
        `* **Derivation Path:** ${s.path}`,
        `* **Child Private Key (k):** ${s.privKey}`,
        `* **Uncompressed Public Key (Q):** ${s.pubKey}`,
        `* **Keccak-256 Digest:** ${s.keccakDigest}`,
        `* **Canonical Address (EIP-55):** ${s.address}`
      ].join("\n");

      navigator.clipboard.writeText(text).then(() => {
        showToast("Full derivation summary copied to clipboard!");
      });
    });

    // Global copy buttons
    document.querySelectorAll(".btn-copy").forEach(btn => {
      btn.addEventListener("click", () => {
        const targetId = btn.dataset.target;
        const targetEl = document.getElementById(targetId);
        if (targetEl) {
          const text = targetEl.textContent.trim();
          navigator.clipboard.writeText(text).then(() => {
            showToast("Copied to clipboard!");
          });
        }
      });
    });

    // Tamper controls
    tamperInput.addEventListener("input", () => {
      validateTamperInput(tamperInput.value);
    });

    btnInjectTypo.addEventListener("click", () => {
      let val = tamperInput.value;
      if (val.length !== 42) return;
      // Mutate one random character between index 2 and 41
      const pos = 2 + Math.floor(Math.random() * 40);
      const hexChars = "0123456789abcdefABCDEF";
      let newChar = hexChars[Math.floor(Math.random() * hexChars.length)];
      while (newChar === val[pos]) {
        newChar = hexChars[Math.floor(Math.random() * hexChars.length)];
      }
      tamperInput.value = val.substring(0, pos) + newChar + val.substring(pos + 1);
      validateTamperInput(tamperInput.value);
    });

    btnToggleCase.addEventListener("click", () => {
      let val = tamperInput.value;
      const letterIndices = [];
      for (let i = 2; i < 42; i++) {
        if (/[a-zA-Z]/.test(val[i])) letterIndices.push(i);
      }
      if (letterIndices.length === 0) return;
      const pos = letterIndices[Math.floor(Math.random() * letterIndices.length)];
      const orig = val[pos];
      const toggled = orig === orig.toUpperCase() ? orig.toLowerCase() : orig.toUpperCase();
      tamperInput.value = val.substring(0, pos) + toggled + val.substring(pos + 1);
      validateTamperInput(tamperInput.value);
    });

    btnResetTamper.addEventListener("click", () => {
      tamperInput.value = currentCanonicalAddress;
      validateTamperInput(currentCanonicalAddress);
    });
  }

  // Initialize on page load
  window.addEventListener("DOMContentLoaded", () => {
    // Populate default preset
    const def = TEST_VECTORS.metamask;
    entropyPhraseInput.value = def.phrase;
    passphraseInput.value = def.passphrase;
    addressIndex.value = "0";

    setupEventListeners();
    runPipeline();
  });

})();
