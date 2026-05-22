/**
 * wallet/chains/bitcoin/scripts.js
 * ═══════════════════════════════════════════════════════════════
 * Construtores de scriptPubKey, scriptSig e witness stacks.
 *
 * TIPOS SUPORTADOS:
 *
 *   P2PKH  (Legacy)    — OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG
 *   P2WPKH (SegWit v0) — OP_0 <20-byte-hash>  (witness program)
 *   P2SH-P2WPKH        — OP_HASH160 <redeemScript-hash> OP_EQUAL
 *   P2WSH  (SegWit v0) — OP_0 <32-byte-hash>
 *   P2TR   (Taproot)   — OP_1 <32-byte-x-only-pubkey>
 *
 * OPCODES USADOS:
 *   OP_DUP         = 0x76
 *   OP_HASH160     = 0xa9
 *   OP_EQUALVERIFY = 0x88
 *   OP_CHECKSIG    = 0xac
 *   OP_EQUAL       = 0x87
 *   OP_0           = 0x00  (witness version 0)
 *   OP_1           = 0x51  (witness version 1 = Taproot)
 * ═══════════════════════════════════════════════════════════════
 */

'use strict';

const crypto = require('crypto');

// ─── Opcodes ─────────────────────────────────────────────────
const OP = {
  _0:           0x00,
  _1:           0x51,  // OP_1 (não OP_PUSHDATA para witness version)
  DUP:          0x76,
  HASH160:      0xa9,
  EQUALVERIFY:  0x88,
  CHECKSIG:     0xac,
  EQUAL:        0x87,
  RETURN:       0x6a,
  CHECKSIGADD:  0xba,  // BIP342 Tapscript
};

// ─── Hash utilities ──────────────────────────────────────────

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest();
}

function hash160(data) {
  return crypto.createHash('ripemd160').update(sha256(data)).digest();
}

// ─── Push data helpers ───────────────────────────────────────

/**
 * Serializa um push de dados com o opcode de tamanho correto.
 * Dados < 76 bytes: [len][data]
 * Dados 76-255 bytes: [OP_PUSHDATA1][len][data]
 * Dados 256-65535 bytes: [OP_PUSHDATA2][len_le16][data]
 */
function pushData(data) {
  const len = data.length;
  if (len < 76) {
    return Buffer.concat([Buffer.from([len]), data]);
  }
  if (len <= 0xff) {
    return Buffer.concat([Buffer.from([0x4c, len]), data]);
  }
  const lenBuf = Buffer.alloc(2);
  lenBuf.writeUInt16LE(len, 0);
  return Buffer.concat([Buffer.from([0x4d]), lenBuf, data]);
}

// ═══════════════════════════════════════════════════════════════
// SCRIPTPUBKEY BUILDERS
// ═══════════════════════════════════════════════════════════════

/**
 * P2PKH scriptPubKey (Legacy — endereços '1...').
 * OP_DUP OP_HASH160 <pubKeyHash(20B)> OP_EQUALVERIFY OP_CHECKSIG
 *
 * @param {Buffer} pubKeyHash - HASH160(pubKey), 20 bytes
 * @returns {Buffer}
 */
function p2pkhScript(pubKeyHash) {
  if (pubKeyHash.length !== 20) throw new Error('pubKeyHash deve ter 20 bytes');
  return Buffer.concat([
    Buffer.from([OP.DUP, OP.HASH160]),
    pushData(pubKeyHash),
    Buffer.from([OP.EQUALVERIFY, OP.CHECKSIG]),
  ]);
}

/**
 * P2WPKH scriptPubKey (SegWit v0 — endereços 'bc1q...' com 20 bytes).
 * OP_0 <pubKeyHash(20B)>
 *
 * @param {Buffer} pubKeyHash - HASH160(pubKey), 20 bytes
 * @returns {Buffer}
 */
function p2wpkhScript(pubKeyHash) {
  if (pubKeyHash.length !== 20) throw new Error('pubKeyHash deve ter 20 bytes');
  return Buffer.concat([
    Buffer.from([OP._0]),
    pushData(pubKeyHash),
  ]);
}

/**
 * P2SH scriptPubKey (usado para P2SH-P2WPKH — compat. SegWit).
 * OP_HASH160 <redeemScriptHash(20B)> OP_EQUAL
 *
 * @param {Buffer} redeemScriptHash - HASH160(redeemScript), 20 bytes
 * @returns {Buffer}
 */
function p2shScript(redeemScriptHash) {
  if (redeemScriptHash.length !== 20) throw new Error('redeemScriptHash deve ter 20 bytes');
  return Buffer.concat([
    Buffer.from([OP.HASH160]),
    pushData(redeemScriptHash),
    Buffer.from([OP.EQUAL]),
  ]);
}

/**
 * P2WSH scriptPubKey (SegWit v0 — multi-sig, scripts complexos).
 * OP_0 <scriptHash(32B)>
 *
 * @param {Buffer} scriptHash - SHA256(witnessScript), 32 bytes
 * @returns {Buffer}
 */
function p2wshScript(scriptHash) {
  if (scriptHash.length !== 32) throw new Error('scriptHash deve ter 32 bytes');
  return Buffer.concat([
    Buffer.from([OP._0]),
    pushData(scriptHash),
  ]);
}

/**
 * P2TR scriptPubKey (Taproot — OP_1 <x-only-pubkey(32B)>).
 * Witness version 1 → endereços 'bc1p...'.
 *
 * @param {Buffer} outputKey - x-only tweaked public key, 32 bytes
 * @returns {Buffer}
 */
function p2trScript(outputKey) {
  if (outputKey.length !== 32) throw new Error('outputKey deve ter 32 bytes (x-only)');
  return Buffer.concat([
    Buffer.from([OP._1]),  // OP_1 = witness version 1
    pushData(outputKey),
  ]);
}

/**
 * P2SH-P2WPKH redeemScript (20-byte SegWit program wrappado em P2SH).
 * Usado por wallets antigas compatíveis com SegWit.
 *
 * redeemScript = OP_0 <pubKeyHash(20B)>
 *
 * @param {Buffer} pubKeyHash
 * @returns {Buffer}
 */
function p2shP2wpkhRedeemScript(pubKeyHash) {
  return p2wpkhScript(pubKeyHash); // É literalmente o mesmo formato
}

// ═══════════════════════════════════════════════════════════════
// SCRIPTSIG BUILDERS (para inputs)
// ═══════════════════════════════════════════════════════════════

/**
 * scriptSig para P2PKH input.
 * <signature(DER+sighash)> <pubKey(compressed,33B)>
 *
 * @param {Buffer} derSignature  - DER + sighash type (71-73 bytes)
 * @param {Buffer} pubKey        - pubKey comprimida, 33 bytes
 * @returns {Buffer}
 */
function p2pkhScriptSig(derSignature, pubKey) {
  return Buffer.concat([pushData(derSignature), pushData(pubKey)]);
}

/**
 * scriptSig para P2WPKH input.
 * Para SegWit nativos: scriptSig é VAZIO (os dados ficam na witness).
 * @returns {Buffer} Buffer vazio
 */
function p2wpkhScriptSig() {
  return Buffer.alloc(0);
}

/**
 * scriptSig para P2SH-P2WPKH input.
 * <redeemScript>
 *
 * @param {Buffer} redeemScript
 * @returns {Buffer}
 */
function p2shP2wpkhScriptSig(redeemScript) {
  return pushData(redeemScript);
}

/**
 * scriptSig para P2TR input.
 * Taproot: scriptSig é sempre VAZIO (dados na witness).
 * @returns {Buffer} Buffer vazio
 */
function p2trScriptSig() {
  return Buffer.alloc(0);
}

// ═══════════════════════════════════════════════════════════════
// WITNESS STACKS
// ═══════════════════════════════════════════════════════════════

/**
 * Witness stack para P2WPKH input.
 * [<signature(DER+sighash)>, <pubKey(33B)>]
 *
 * @param {Buffer} derSignature
 * @param {Buffer} pubKey
 * @returns {Buffer[]}
 */
function p2wpkhWitness(derSignature, pubKey) {
  return [derSignature, pubKey];
}

/**
 * Witness stack para P2TR key-path spend (Schnorr).
 * [<schnorrSignature(64B)>]  — sighash type 0x00 é omitido (DEFAULT)
 *
 * @param {Buffer} schnorrSig - 64 bytes
 * @param {number} [sighashType=0] - 0 = DEFAULT (omitido), outros são appended
 * @returns {Buffer[]}
 */
function p2trKeyPathWitness(schnorrSig, sighashType = 0) {
  if (schnorrSig.length !== 64) throw new Error('Schnorr sig deve ter 64 bytes');
  if (sighashType === 0) return [schnorrSig]; // DEFAULT: não append sighash byte
  return [Buffer.concat([schnorrSig, Buffer.from([sighashType])])]; // 65 bytes
}

/**
 * Witness stack para P2TR script-path spend.
 * [<inputs...>, <script>, <control_block>]
 *
 * @param {Buffer[]} scriptInputs  - Dados do script (depende do script)
 * @param {Buffer}   script        - O script da folha sendo gasto
 * @param {Buffer}   controlBlock  - Version + parity + internalKey + proof
 * @returns {Buffer[]}
 */
function p2trScriptPathWitness(scriptInputs, script, controlBlock) {
  return [...scriptInputs, script, controlBlock];
}

// ═══════════════════════════════════════════════════════════════
// SCRIPT TYPE DETECTION
// ═══════════════════════════════════════════════════════════════

/**
 * Identifica o tipo de script a partir do scriptPubKey.
 *
 * @param {Buffer} script
 * @returns {'P2PKH'|'P2SH'|'P2WPKH'|'P2WSH'|'P2TR'|'OP_RETURN'|'UNKNOWN'}
 */
function classifyScript(script) {
  const len = script.length;
  // P2PKH: OP_DUP OP_HASH160 <20B> OP_EQUALVERIFY OP_CHECKSIG (25 bytes)
  if (len === 25 && script[0] === OP.DUP && script[1] === OP.HASH160 &&
      script[2] === 20 && script[23] === OP.EQUALVERIFY && script[24] === OP.CHECKSIG) {
    return 'P2PKH';
  }
  // P2SH: OP_HASH160 <20B> OP_EQUAL (23 bytes)
  if (len === 23 && script[0] === OP.HASH160 && script[1] === 20 && script[22] === OP.EQUAL) {
    return 'P2SH';
  }
  // P2WPKH: OP_0 <20B> (22 bytes)
  if (len === 22 && script[0] === OP._0 && script[1] === 20) {
    return 'P2WPKH';
  }
  // P2WSH: OP_0 <32B> (34 bytes)
  if (len === 34 && script[0] === OP._0 && script[1] === 32) {
    return 'P2WSH';
  }
  // P2TR: OP_1 <32B> (34 bytes)
  if (len === 34 && script[0] === OP._1 && script[1] === 32) {
    return 'P2TR';
  }
  // OP_RETURN
  if (script[0] === OP.RETURN) return 'OP_RETURN';
  return 'UNKNOWN';
}

/**
 * Extrai o witness program de um scriptPubKey SegWit.
 * @param {Buffer} script
 * @returns {{ version: number, program: Buffer } | null}
 */
function extractWitnessProgram(script) {
  const type = classifyScript(script);
  if (type === 'P2WPKH') return { version: 0, program: script.slice(2) };
  if (type === 'P2WSH')  return { version: 0, program: script.slice(2) };
  if (type === 'P2TR')   return { version: 1, program: script.slice(2) };
  return null;
}

/**
 * Verifica se um script é standard (aceito pelo mempool Bitcoin).
 * @param {Buffer} script
 * @returns {boolean}
 */
function isStandard(script) {
  const type = classifyScript(script);
  return ['P2PKH', 'P2SH', 'P2WPKH', 'P2WSH', 'P2TR'].includes(type);
}

// ═══════════════════════════════════════════════════════════════
// VARINT (usado na serialização)
// ═══════════════════════════════════════════════════════════════

/**
 * Encoda um número como Bitcoin varint.
 * @param {number} n
 * @returns {Buffer}
 */
function varInt(n) {
  if (n < 0xfd) {
    return Buffer.from([n]);
  }
  if (n <= 0xffff) {
    const b = Buffer.alloc(3);
    b[0] = 0xfd;
    b.writeUInt16LE(n, 1);
    return b;
  }
  if (n <= 0xffffffff) {
    const b = Buffer.alloc(5);
    b[0] = 0xfe;
    b.writeUInt32LE(n, 1);
    return b;
  }
  const b = Buffer.alloc(9);
  b[0] = 0xff;
  b.writeBigUInt64LE(BigInt(n), 1);
  return b;
}

/**
 * Lê um varint de um Buffer.
 * @param {Buffer} buf
 * @param {number} offset
 * @returns {{ value: number, size: number }}
 */
function readVarInt(buf, offset = 0) {
  const first = buf[offset];
  if (first < 0xfd) return { value: first, size: 1 };
  if (first === 0xfd) return { value: buf.readUInt16LE(offset + 1), size: 3 };
  if (first === 0xfe) return { value: buf.readUInt32LE(offset + 1), size: 5 };
  return { value: Number(buf.readBigUInt64LE(offset + 1)), size: 9 };
}

module.exports = {
  // Opcodes
  OP,

  // Hashing
  sha256,
  hash160,

  // Push data
  pushData,
  varInt,
  readVarInt,

  // scriptPubKey builders
  p2pkhScript,
  p2wpkhScript,
  p2shScript,
  p2wshScript,
  p2trScript,
  p2shP2wpkhRedeemScript,

  // scriptSig builders
  p2pkhScriptSig,
  p2wpkhScriptSig,
  p2shP2wpkhScriptSig,
  p2trScriptSig,

  // Witness stacks
  p2wpkhWitness,
  p2trKeyPathWitness,
  p2trScriptPathWitness,

  // Detection
  classifyScript,
  extractWitnessProgram,
  isStandard,
};

