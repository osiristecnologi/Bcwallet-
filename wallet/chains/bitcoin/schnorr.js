/**
 * wallet/chains/bitcoin/schnorr.js
 * ═══════════════════════════════════════════════════════════════
 * Assinaturas Schnorr BIP340 — implementação pura Node.js.
 *
 * BIP340 especifica:
 *   • Chaves x-only (32 bytes — apenas coordenada X)
 *   • Tagged hashes: SHA256(SHA256(tag) || SHA256(tag) || msg)
 *   • Assinatura: (R, s) = 64 bytes
 *   • R tem Y par (imposto pelo protocolo)
 *   • Determinístico: nonce k derivado de privKey + msg
 *
 * POR QUE SCHNORR vs ECDSA:
 *   • Sem maleabilidade de assinatura (ECDSA tem)
 *   • MuSig2: múltiplas chaves → 1 assinatura (batch verify)
 *   • Taproot exige Schnorr (BIP341/BIP342)
 *   • 64 bytes vs ~72 bytes ECDSA DER
 *
 * AVISO DE SEGURANÇA:
 *   Esta implementação usa randomBytes para nonce auxiliar.
 *   Para signing em produção crítica de alta segurança,
 *   considere @noble/secp256k1 que tem auditoria formal.
 *   Para geração de endereços (tweakKey), é seguro.
 *
 * Futuro:
 *   - MuSig2 (BIP327)
 *   - FROST threshold signatures
 *   - Adaptor signatures (cross-chain atomic swaps)
 * ═══════════════════════════════════════════════════════════════
 */

'use strict';

const crypto = require('crypto');
const { P, N, G, pointMul, pointAdd, hasEvenY, liftX, xOnlyPubKey, compressedPubKey, modp, modn, modInv } = require('./secp256k1');

// ─── Tagged Hash (BIP340) ────────────────────────────────────

/**
 * Calcula um tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)
 * Garante separação de domínios entre diferentes usos do hash.
 *
 * @param {string|Buffer} tag  - Nome do domínio (ex: "BIP0340/challenge")
 * @param {Buffer}        data - Dados a hashar
 * @returns {Buffer} 32 bytes
 */
function taggedHash(tag, data) {
  const tagBuf  = typeof tag === 'string' ? Buffer.from(tag, 'utf8') : tag;
  const tagHash = crypto.createHash('sha256').update(tagBuf).digest();
  return crypto.createHash('sha256')
    .update(tagHash)
    .update(tagHash)
    .update(data)
    .digest();
}

// Tags BIP340 pré-computadas
const TAG_AUX       = 'BIP0340/aux';
const TAG_NONCE     = 'BIP0340/nonce';
const TAG_CHALLENGE = 'BIP0340/challenge';
const TAG_TWEAK     = 'TapTweak';
const TAG_TAPLEAF   = 'TapLeaf';
const TAG_TAPBRANCH = 'TapBranch';

// ─── Schnorr Sign (BIP340) ───────────────────────────────────

/**
 * Assina uma mensagem de 32 bytes com Schnorr (BIP340).
 *
 * Algoritmo:
 *   1. Ajustar privKey para que pubKey tenha Y par
 *   2. Gerar nonce t = xor(privKey, taggedHash("BIP0340/aux", aux))
 *   3. k₀ = taggedHash("BIP0340/nonce", t || P || msg) mod N
 *   4. R = k₀ * G; ajustar k se R.y ímpar
 *   5. e = taggedHash("BIP0340/challenge", R.x || P.x || msg) mod N
 *   6. s = (k + e * privKey) mod N
 *   7. sig = R.x || s (64 bytes)
 *
 * @param {Buffer|string} privateKeyHex - 32 bytes hex ou Buffer
 * @param {Buffer}        msgHash       - Mensagem de 32 bytes (hash)
 * @param {Buffer}        [aux]         - Entropy auxiliar (32 bytes, BIP340 §3)
 * @returns {Buffer} Assinatura Schnorr de 64 bytes
 */
function schnorrSign(privateKeyHex, msgHash, aux) {
  // Normalizar inputs
  const privBuf = Buffer.isBuffer(privateKeyHex)
    ? privateKeyHex
    : Buffer.from(privateKeyHex, 'hex');
  if (privBuf.length !== 32) throw new Error('privKey deve ter 32 bytes');
  if (!Buffer.isBuffer(msgHash) || msgHash.length !== 32) {
    throw new Error('msgHash deve ser Buffer de 32 bytes');
  }

  let d0 = BigInt('0x' + privBuf.toString('hex'));
  if (d0 === 0n || d0 >= N) throw new Error('privKey inválida (fora do range)');

  // 1. Calcular pubKey e ajustar d para ter Y par
  const P_point = pointMul(d0, G);
  let d = hasEvenY(P_point) ? d0 : N - d0;

  const P_x = xOnlyPubKey(P_point); // 32 bytes

  // 2. Nonce determinístico BIP340
  const auxRand = aux || crypto.randomBytes(32);
  if (auxRand.length !== 32) throw new Error('aux deve ter 32 bytes');

  // t = xor(bytes(d), taggedHash("BIP0340/aux", aux))
  const auxHash = taggedHash(TAG_AUX, auxRand);
  const dBytes  = Buffer.from(d.toString(16).padStart(64, '0'), 'hex');
  const t       = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) t[i] = dBytes[i] ^ auxHash[i];

  // k₀ = int(taggedHash("BIP0340/nonce", t || P.x || msg)) mod N
  const rand = taggedHash(TAG_NONCE, Buffer.concat([t, P_x, msgHash]));
  let k0 = modn(BigInt('0x' + rand.toString('hex')));
  if (k0 === 0n) throw new Error('k0 inválido (zero) — tente outro aux');

  // 3. R = k₀ * G
  const R = pointMul(k0, G);
  if (R === null) throw new Error('R é ponto no infinito');

  // 4. Ajustar k para R.y par
  const k = hasEvenY(R) ? k0 : N - k0;

  // 5. Calcular desafio e
  const R_x = xOnlyPubKey(R); // 32 bytes
  const eHash = taggedHash(TAG_CHALLENGE, Buffer.concat([R_x, P_x, msgHash]));
  const e = modn(BigInt('0x' + eHash.toString('hex')));

  // 6. s = (k + e * d) mod N
  const s = modn(k + e * d);
  const sBuf = Buffer.from(s.toString(16).padStart(64, '0'), 'hex');

  // 7. Assinatura = R.x || s (64 bytes)
  return Buffer.concat([R_x, sBuf]);
}

// ─── Schnorr Verify (BIP340) ─────────────────────────────────

/**
 * Verifica uma assinatura Schnorr BIP340.
 *
 * @param {Buffer}        signature  - 64 bytes (R_x || s)
 * @param {Buffer}        msgHash    - Mensagem de 32 bytes
 * @param {Buffer|string} pubKeyHex  - x-only pubKey, 32 bytes
 * @returns {boolean}
 */
function schnorrVerify(signature, msgHash, pubKeyHex) {
  try {
    if (!Buffer.isBuffer(signature) || signature.length !== 64) return false;
    if (!Buffer.isBuffer(msgHash)   || msgHash.length !== 32)   return false;

    const pubBuf = Buffer.isBuffer(pubKeyHex)
      ? pubKeyHex
      : Buffer.from(pubKeyHex, 'hex');
    if (pubBuf.length !== 32) return false;

    const r = BigInt('0x' + signature.slice(0, 32).toString('hex'));
    const s = BigInt('0x' + signature.slice(32).toString('hex'));
    const px = BigInt('0x' + pubBuf.toString('hex'));

    if (r >= P || s >= N || px >= P) return false;

    // Levantar P.x → ponto com Y par
    const P_point = liftX(px);

    // e = taggedHash("BIP0340/challenge", bytes(r) || bytes(P.x) || msg) mod N
    const R_xBuf  = Buffer.from(r.toString(16).padStart(64, '0'), 'hex');
    const eHash   = taggedHash(TAG_CHALLENGE, Buffer.concat([R_xBuf, pubBuf, msgHash]));
    const e       = modn(BigInt('0x' + eHash.toString('hex')));

    // R = s*G - e*P
    const sG   = pointMul(s, G);
    const eP   = pointMul(e, P_point);
    // eP negado: [x, p-y]
    const ePneg = [eP[0], P - eP[1]];
    const R     = pointAdd(sG, ePneg);

    if (R === null || !hasEvenY(R)) return false;
    return R[0] === r;
  } catch {
    return false;
  }
}

// ─── Taproot Key Tweak (BIP341) ──────────────────────────────

/**
 * Calcula o ponto interno P após tweak Taproot.
 *
 * P_tweaked = P + t*G onde t = taggedHash("TapTweak", P.x || merkleRoot)
 *
 * Se merkleRoot = Buffer(0) → key-path only (sem script tree).
 *
 * @param {Buffer} internalPubKey - x-only pubKey, 32 bytes
 * @param {Buffer} [merkleRoot]   - Merkle root do script tree, 32 bytes ou Buffer(0)
 * @returns {{ outputKey: Buffer, parity: number }} outputKey = x-only, parity = 0 ou 1
 */
function tapTweakPublicKey(internalPubKey, merkleRoot = Buffer.alloc(0)) {
  if (internalPubKey.length !== 32) throw new Error('internalPubKey deve ter 32 bytes');

  // t = taggedHash("TapTweak", internalPubKey || merkleRoot)
  const tweak   = taggedHash(TAG_TWEAK, Buffer.concat([internalPubKey, merkleRoot]));
  const t       = BigInt('0x' + tweak.toString('hex'));
  if (t >= N) throw new Error('Tweak >= N — improvávelissimo, troque a chave');

  // Levantar P (com Y par, como exige BIP341)
  const px = BigInt('0x' + internalPubKey.toString('hex'));
  const P_point = liftX(px); // garante Y par

  // Q = P + t*G
  const tG    = pointMul(t, G);
  let   Q     = pointAdd(P_point, tG);
  if (Q === null) throw new Error('Ponto tweaked é infinito');

  const parity = hasEvenY(Q) ? 0 : 1;

  // Retorna a coordenada X do Q com Y par
  if (!hasEvenY(Q)) Q = [Q[0], P - Q[1]];

  return {
    outputKey: xOnlyPubKey(Q),  // 32 bytes — usado como P2TR witness program
    parity,                      // 0 = Y par, 1 = Y ímpar
    tweak,                       // 32 bytes — necessário para script-path spend
  };
}

/**
 * Calcula o tweak da privKey para gastar via key-path Taproot.
 *
 * @param {Buffer|string} privateKeyHex - 32 bytes
 * @param {Buffer}        [merkleRoot]
 * @returns {Buffer} tweaked private key (32 bytes)
 */
function tapTweakPrivateKey(privateKeyHex, merkleRoot = Buffer.alloc(0)) {
  const privBuf = Buffer.isBuffer(privateKeyHex)
    ? privateKeyHex : Buffer.from(privateKeyHex, 'hex');
  if (privBuf.length !== 32) throw new Error('privKey deve ter 32 bytes');

  let d = BigInt('0x' + privBuf.toString('hex'));

  // Calcular pubKey e ajustar d para Y par
  const P_pt = pointMul(d, G);
  if (!hasEvenY(P_pt)) d = N - d;

  const P_x  = xOnlyPubKey(P_pt);

  // t = taggedHash("TapTweak", P.x || merkleRoot)
  const tweak = taggedHash(TAG_TWEAK, Buffer.concat([P_x, merkleRoot]));
  const t     = BigInt('0x' + tweak.toString('hex'));

  // tweaked_d = (d + t) mod N
  const tweakedD = modn(d + t);
  return Buffer.from(tweakedD.toString(16).padStart(64, '0'), 'hex');
}

// ─── TapLeaf / TapBranch (BIP341) ────────────────────────────

/**
 * Hash de uma folha Tapscript.
 * @param {number} leafVersion - geralmente 0xc0
 * @param {Buffer} script      - script serializado
 * @returns {Buffer} 32 bytes
 */
function tapLeafHash(leafVersion, script) {
  const lenBuf = Buffer.alloc(1);
  lenBuf[0]    = script.length; // varint simplificado para scripts < 253 bytes
  return taggedHash(TAG_TAPLEAF,
    Buffer.concat([Buffer.from([leafVersion]), lenBuf, script])
  );
}

/**
 * Hash de um ramo Tapscript (dois hashes em ordem lexicográfica).
 * @param {Buffer} hash1
 * @param {Buffer} hash2
 * @returns {Buffer} 32 bytes
 */
function tapBranchHash(hash1, hash2) {
  // Ordem canônica: menor primeiro
  const [a, b] = hash1.compare(hash2) <= 0 ? [hash1, hash2] : [hash2, hash1];
  return taggedHash(TAG_TAPBRANCH, Buffer.concat([a, b]));
}

module.exports = {
  // Tagged hashes
  taggedHash,
  TAG_AUX,
  TAG_NONCE,
  TAG_CHALLENGE,
  TAG_TWEAK,
  TAG_TAPLEAF,
  TAG_TAPBRANCH,

  // Schnorr
  schnorrSign,
  schnorrVerify,

  // Taproot
  tapTweakPublicKey,
  tapTweakPrivateKey,
  tapLeafHash,
  tapBranchHash,
};

