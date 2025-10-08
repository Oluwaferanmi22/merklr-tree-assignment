// Airdrop Eligibility Checker using Merkle Tree (Browser)
// Dependencies loaded via CDN in index.html: ethers v5, merkletreejs, buffer (polyfill)

(function () {

  // Dependency guards
  if (typeof window === 'undefined') {
    console.error('This script is intended to run in a browser.');
    return;
  }
  if (!window.ethers) {
    console.error('ethers UMD not found. Ensure the CDN script is loaded before script.js');
    return;
  }
  const { utils } = window.ethers;
  // Try to resolve Merkletree constructor from different UMD globals
  let MerkleTreeCtor = window.MerkleTree || (window.merkle && window.merkle.MerkleTree);

  // 1) Define your allowlist here (sample addresses). Replace these with your real list.
  // You can paste dozens/hundreds; the tree is built client-side for demo purposes.
  const ELIGIBLE_ADDRESSES = [
    '0x0000000000000000000000000000000000000001',
    '0x0000000000000000000000000000000000000002',
    '0x0000000000000000000000000000000000000003',
    '0x0000000000000000000000000000000000000004',
    // Add more...
  ];

  // Optional: token allocations per address (demo). If not present, defaults to 0.
  const ALLOCATIONS = {
    // Example: will be normalized to checksum; keys can be lower/upper.
    '0x0000000000000000000000000000000000000001': 150,
    '0x0000000000000000000000000000000000000002': 80,
    '0x0000000000000000000000000000000000000003': 50,
    '0x0000000000000000000000000000000000000004': 30,
  };

  // Normalize to checksum addresses and deduplicate
  function normalizeAddresses(addrs) {
    const set = new Set();
    const out = [];
    for (const a of addrs) {
      try {
        const chk = utils.getAddress(a);
        if (!set.has(chk)) {
          set.add(chk);
          out.push(chk);
        }
      } catch (e) {
        // Skip invalid entries silently
      }
    }
    return out;
  }

  // Bytes/hex helpers (no Buffer required)
  const toBytes = (hex) => utils.arrayify(hex);
  const toHex = (bytes) => utils.hexlify(bytes);
  const concatBytes = (a, b) => {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
  };
  const compareBytes = (a, b) => {
    const len = Math.min(a.length, b.length);
    for (let i = 0; i < len; i++) {
      if (a[i] !== b[i]) return a[i] - b[i];
    }
    return a.length - b.length;
  };
  function keccakBytes(dataBytes) {
    // dataBytes: Uint8Array
    return utils.arrayify(utils.keccak256(dataBytes));
  }

  // Convert address -> leaf hash bytes: keccak256(abi.encodePacked(address))
  function leafForAddress(address) {
    const chk = utils.getAddress(address);
    const packed = utils.solidityPack(['address'], [chk]); // 0x...
    return keccakBytes(toBytes(packed));
  }

  // Local MerkleTree (Uint8Array-based, sortPairs=true supported)
  class LocalMerkleTree {
    constructor(leaves, hashFn, options = {}) {
      this.hashFn = hashFn; // (Uint8Array) -> Uint8Array
      this.sortPairs = !!options.sortPairs;
      const ensure32 = (u8) => {
        const b = u8 instanceof Uint8Array ? u8 : toBytes(u8);
        return b.length === 32 ? b : this.hashFn(b);
      };
      this.leaves = (leaves || []).map(ensure32);
      this.layers = [];
      this._buildLayers();
    }
    _buildLayers() {
      let level = this.leaves.slice();
      this.layers = [level];
      while (level.length > 1) {
        const next = [];
        for (let i = 0; i < level.length; i += 2) {
          const left = level[i];
          const right = level[i + 1];
          if (!right) {
            next.push(left);
          } else {
            let a = left, b = right;
            if (this.sortPairs && compareBytes(a, b) > 0) {
              a = right; b = left;
            }
            next.push(this.hashFn(concatBytes(a, b)));
          }
        }
        level = next;
        this.layers.push(level);
      }
    }
    getRoot() {
      const top = this.layers[this.layers.length - 1];
      return top && top[0] ? top[0] : new Uint8Array();
    }
    getProof(leaf) {
      const target = leaf instanceof Uint8Array ? leaf : toBytes(leaf);
      let idx = this.layers[0].findIndex((b) => b.length === target.length && compareBytes(b, target) === 0);
      if (idx === -1) return [];
      const proof = [];
      for (let level = 0; level < this.layers.length - 1; level++) {
        const layer = this.layers[level];
        const isRight = idx % 2 === 1;
        const pairIndex = isRight ? idx - 1 : idx + 1;
        if (pairIndex < layer.length) {
          proof.push(layer[pairIndex]); // store sibling only; side not needed for sortPairs
        }
        idx = Math.floor(idx / 2);
      }
      return proof;
    }
    getHexProof(leaf) {
      return this.getProof(leaf).map((b) => toHex(b));
    }
    verify(proof, leaf, root) {
      let hash = leaf instanceof Uint8Array ? leaf : toBytes(leaf);
      const r = root instanceof Uint8Array ? root : toBytes(root);
      for (const sib of proof) {
        const right = sib instanceof Uint8Array ? sib : toBytes(sib);
        let a = hash, b = right;
        if (this.sortPairs && compareBytes(a, b) > 0) {
          a = right; b = hash;
        }
        hash = this.hashFn(concatBytes(a, b));
      }
      return compareBytes(hash, r) === 0;
    }
  }

  // Build tree from addresses
  function buildTree(addresses) {
    const norm = normalizeAddresses(addresses);
    const leaves = norm.map(leafForAddress);
    // Prefer external merkletreejs only if available and Buffer exists; otherwise use local
    const hasExternal = !!MerkleTreeCtor && !!(window.Buffer || (window.buffer && window.buffer.Buffer));
    const Tree = hasExternal ? MerkleTreeCtor : LocalMerkleTree;
    const tree = new Tree(leaves, hasExternal ?
      // External expects Buffer in and returns Buffer; adapt
      (buf) => {
        const hex = utils.keccak256('0x' + Buffer.from(buf).toString('hex'));
        return Buffer.from(hex.slice(2), 'hex');
      } : keccakBytes,
      { sortPairs: true }
    );
    return { tree, norm };
  }

  function to0x(value) {
    if (value instanceof Uint8Array) return toHex(value);
    if (typeof value === 'string') return value.startsWith('0x') ? value : '0x' + value;
    // Buffer (if external path used)
    if (typeof Buffer !== 'undefined' && value && Buffer.isBuffer && Buffer.isBuffer(value)) {
      return '0x' + value.toString('hex');
    }
    return String(value);
  }

  function setResultOK(msg) {
    const panel = document.getElementById('resultPanel');
    const badge = document.getElementById('eligBadge');
    if (panel && badge) {
      panel.style.display = 'block';
      badge.className = 'badge success';
      badge.textContent = msg;
    } else {
      console.log(msg);
    }
  }
  function setResultErr(msg) {
    const panel = document.getElementById('resultPanel');
    const badge = document.getElementById('eligBadge');
    if (panel && badge) {
      panel.style.display = 'block';
      badge.className = 'badge error';
      badge.textContent = msg;
    } else {
      console.warn(msg);
    }
  }
  function clearResult() {
    const panel = document.getElementById('resultPanel');
    if (panel) panel.style.display = 'none';
  }

  // No-op ensure since we always have a local implementation; keep CDNs if available
  async function ensureMerkleTree() {
    if (!MerkleTreeCtor) {
      console.warn('Using built-in MerkleTree implementation (CDN not available).');
    }
    return true;
  }

  // Initialize on DOM ready
  document.addEventListener('DOMContentLoaded', async () => {
    const addrInput = document.getElementById('addr');
    const checkBtn = document.getElementById('checkBtn');
    const rootInput = document.getElementById('root');
    const eligibleCount = document.getElementById('eligibleCount');
    const demoBtns = document.getElementById('demoBtns');
    const resultPanel = document.getElementById('resultPanel');
    const eligBadge = document.getElementById('eligBadge');
    const resAddress = document.getElementById('resAddress');
    const resAmount = document.getElementById('resAmount');
    const proofDiv = document.getElementById('proof');

    // Ensure merkletreejs is available
    const ok = await ensureMerkleTree();
    if (!ok) {
      rootInput.value = 'Error: merkletreejs not loaded';
      setResultErr('Script error: merkletreejs not found. Check console and CDN.');
      return;
    }

    let tree, norm, root;
    try {
      ({ tree, norm } = buildTree(ELIGIBLE_ADDRESSES));
      root = tree.getRoot();
      rootInput.value = to0x(root);
      eligibleCount.value = String(norm.length);
      // Build demo buttons for first few addresses
      demoBtns.innerHTML = '';
      norm.slice(0, Math.min(3, norm.length)).forEach((a) => {
        const b = document.createElement('button');
        b.textContent = a.slice(0, 6) + '…' + a.slice(-4);
        b.addEventListener('click', () => {
          addrInput.value = a;
          checkBtn.click();
        });
        demoBtns.appendChild(b);
      });
      // Basic diagnostic in console
      console.log('Merkle root:', rootInput.value, 'Leaves:', norm.length);
    } catch (err) {
      console.error('Failed to build Merkle tree:', err);
      rootInput.value = 'Error building Merkle tree';
      setResultErr('Internal error while building Merkle tree.');
      return;
    }

    function verifyAddress(input) {
      try {
        const chk = utils.getAddress(String(input).trim());
        const leaf = leafForAddress(chk);
        // Hex proof for display/sharing
        const proofHex = tree.getHexProof(leaf);
        proofDiv.textContent = proofHex.length ? JSON.stringify(proofHex, null, 2) : '—';

        // Use binary proof for verification
        const proof = tree.getProof(leaf); // array of bytes when local tree; for external, it may be objects, but we prefer local
        const valid = tree.verify(proof, leaf, root);

        if (!valid) {
          // Update result panel UI
          resultPanel.style.display = 'block';
          eligBadge.className = 'badge error';
          eligBadge.textContent = 'Not eligible for airdrop';
          resAddress.textContent = chk;
          resAmount.textContent = '0 tokens';
          setResultErr('Not eligible for airdrop.');
          return;
        }
        const amount = (() => {
          try { return ALLOCATIONS[utils.getAddress(chk)] || ALLOCATIONS[chk] || 0; } catch { return 0; }
        })();
        resultPanel.style.display = 'block';
        eligBadge.className = 'badge success';
        eligBadge.textContent = 'Eligible for airdrop';
        resAddress.textContent = chk;
        resAmount.textContent = amount + ' tokens';
        setResultOK('Eligible for airdrop.');
      } catch (e) {
        proofDiv.textContent = '—';
        setResultErr('Invalid address format.');
      }
    }

    checkBtn.addEventListener('click', () => {
      clearResult();
      verifyAddress(addrInput.value);
    });

    addrInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        clearResult();
        verifyAddress(addrInput.value);
      }
    });
  });
})();
