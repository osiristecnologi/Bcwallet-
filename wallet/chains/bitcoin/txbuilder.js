/**
 * wallet/chains/bitcoin/txbuilder.js
 * ═══════════════════════════════════════════════════════════════
 * Transaction Builder — constrói, assina e serializa transações
 * Bitcoin reais para broadcast.
 *
 * FLUXO COMPLETO:
 *   1. build()     → monta inputs/outputs com coin selection
 *   2. sign()      → assina cada input com a chave correta
 *   3. serialize() → gera raw hex pronto para broadcast
 *   4. broadcast() → envia via Electrum/mempool.space
 *
 * TIPOS SUPORTADOS:
 *   P2PKH  — legacy, assina com ECDSA, sighash legacy
 *   P2WPKH — native SegWit, assina com ECDSA, BIP143 sighash
 *   P2TR   — Taproot, assina com Schnorr, BIP341 sighash
 *
 * FEATURES:
 *   • RBF opt-in (sequence = 0xFFFFFFFD)
 *   • Locktime support
 *   • Automatic change output
 *   • Dust prevention
 *   • Anti-overflow: BigInt para todos os valores em sat
 *   • Validação de outputs antes de assinar
 *
 * Futuro:
 *   • CPFP (Child-Pays-For-Parent)
 *   • Multi-sig (P2WSH/P2TR MuSig2)
 *   • Partially Signed Bitcoin Transactions (PSBT — BIP174)
 *   • Tapscript spend
 * ═══════════════════════════════════════════════════════════════
 */

'use strict';

const crypto = require('crypto');
const { SIGHASH, legacySighash, segwitV0Sighash, taprootSighash, serializeTransaction, txid: calcTxid, calcWeight } = require('./serialization');
const { p2pkhScript, p2wpkhScript, p2trScript, p2pkhScriptSig, p2wpkhScriptSig, p2trScriptSig, p2wpkhWitness, p2trKeyPathWitness, hash160, classifyScript } = require('./scripts');
const { schnorrSign, tapTweakPublicKey } = require('./schnorr');
const { selectUTXOs, DUST_LIMITS, estimateTxVbytes, calculateFee } = require('./utxo');
const { encodeSegwitAddress } = require('./bech32');
const secp = require('./secp256k1');

// ─── ECDSA DER signing via Node.js native ───────────────────
const { privateKeyToPublicKey: privToPub } = require('../../../utils/crypto');

/**
 * Assina um hash de 32 bytes com ECDSA secp256k1.
 * Usa Node.js crypto.createSign internamente (OpenSSL).
 * Retorna assinatura DER + sighash type byte.
 *
 * @param {Buffer} hash32      - 32 bytes do sighash
 * @param {string} privKeyHex  - 64 chars hex
 * @param {number} sighashType - ex: SIGHASH.ALL = 0x01
 * @returns {Buffer} DER signature + sighash byte (71-73 bytes)
 */
function ecdsaSign(hash32, privKeyHex, sighashType = SIGHASH.ALL) {
  // Reconstruir PEM PKCS8 para crypto.createSign
  const { privateKeyToPublicKey } = require('../../../utils/crypto');
  const { privateKeyPem } = privateKeyToPublicKey(privKeyHex);

  const signer = crypto.createSign('SHA256');
  // createSign faz SHA256(hash32) internamente — para passar o hash diretamente
  // usamos o modo "raw" via sign com padding=null
  // Node.js approach: sign the preimage such that SHA256(preimage) = hash32
  // Since we already have the hash, we use crypto.createPrivateKey + sign
  const privKeyObj = crypto.createPrivateKey(privateKeyPem);

  // Usar crypto.sign com digest='SHA256' que espera dados pré-hashados... não.
  // Na verdade, createSign('SHA256').update(hash32).sign(key) faz SHA256(hash32)
  // Workaround: usar algorithm='id-dsa-with-sha1' não funciona.
  // REAL solution: usar createSign com o hash já calculado manualmente.
  // Node.js: createSign('SHA256') calls SHA256(input) then signs.
  // Mas queremos assinar hash32 diretamente (sem double hash).
  // Solução: usar 'SHA256' e passar um preimage tal que SHA256(preimage) = hash32
  // Não é possível. Usar abordagem alternativa via ECDH + BigInt Schnorr-style
  // OU usar o truque de passar dados via SHA256 update com dados pré-hashados.
  //
  // ABORDAGEM CORRETA para Bitcoin:
  // Bitcoin ECDSA assina o hash SHA256d diretamente.
  // Node.js crypto.sign('sha256', data, key) = sign(SHA256(data))
  // Para assinar um hash arbitrário de 32 bytes: usar signMessage com 'id-rsassa-pkcs1-v1_5'
  // NÃO funciona para EC.
  //
  // SOLUÇÃO REAL: implementar ECDSA sign diretamente com BigInt
  // (idêntico ao Schnorr mas com eq diferente)
  return ecdsaSignRaw(hash32, privKeyHex, sighashType);
}

/**
 * ECDSA sign implementado em BigInt puro (sem double-hash).
 * Assina hash32 diretamente com RFC 6979 deterministic nonce.
 *
 * @param {Buffer} hash32
 * @param {string} privKeyHex
 * @param {number} sighashType
 * @returns {Buffer} DER + sighash type byte
 */
function ecdsaSignRaw(hash32, privKeyHex, sighashType = SIGHASH.ALL) {
  const { N, G, pointMul, modp, modn, modInv } = secp;

  const d = BigInt('0x' + privKeyHex);
  if (d <= 0n || d >= N) throw new Error('privKey fora do range');

  const z = BigInt('0x' + hash32.toString('hex'));

  // RFC 6979 deterministic nonce
  const k = rfc6979Nonce(hash32, privKeyHex);

  const R = pointMul(k, G);
  if (R === null) throw new Error('R é infinito');

  const r = secp.modn(R[0]);
  if (r === 0n) throw new Error('r = 0');

  // s = k⁻¹ * (z + r*d) mod N
  let s = secp.modn(secp.modInv(k, N) * secp.modn(z + secp.modn(r * d)));
  if (s === 0n) throw new Error('s = 0');

  // Low-S normalization (BIP62 — previne maleabilidade de assinatura)
  if (s > N / 2n) s = N - s;

  // Codificar como DER
  const der = encodeDER(r, s);
  return Buffer.concat([der, Buffer.from([sighashType])]);
}

/**
 * RFC 6979 — nonce determinístico para ECDSA.
 * Garante que o mesmo (privKey, msg) sempre produz a mesma assinatura.
 * Previne leakage de privKey por nonce repetido.
 *
 * @param {Buffer} msgHash   - 32 bytes
 * @param {string} privKeyHex - 64 chars
 * @returns {bigint} k (nonce)
 */
function rfc6979Nonce(msgHash, privKeyHex) {
  const { N } = secp;
  const privBuf = Buffer.from(privKeyHex, 'hex');

  // HMAC-DRBG (simplificado, suficiente para Bitcoin ECDSA)
  let V = Buffer.alloc(32, 0x01);
  let K = Buffer.alloc(32, 0x00);

  const hmac = (key, ...data) =>
    crypto.createHmac('sha256', key).update(Buffer.concat(data)).digest();

  K = hmac(K, V, Buffer.from([0x00]), privBuf, msgHash);
  V = hmac(K, V);
  K = hmac(K, V, Buffer.from([0x01]), privBuf, msgHash);
  V = hmac(K, V);

  while (true) {
    V = hmac(K, V);
    const k = BigInt('0x' + V.toString('hex'));
    if (k >= 1n && k < N) return k;
    K = hmac(K, V, Buffer.from([0x00]));
    V = hmac(K, V);
  }
}

/**
 * Codifica r e s em formato DER (Distinguished Encoding Rules).
 * Formato: 0x30 [total_len] 0x02 [r_len] [r] 0x02 [s_len] [s]
 */
function encodeDER(r, s) {
  function encodeInt(n) {
    let hex = n.toString(16);
    if (hex.length % 2) hex = '0' + hex;
    let buf = Buffer.from(hex, 'hex');
    // Prefixar com 0x00 se o MSB é 1 (seria interpretado como negativo)
    if (buf[0] & 0x80) buf = Buffer.concat([Buffer.from([0x00]), buf]);
    return buf;
  }
  const rBuf = encodeInt(r);
  const sBuf = encodeInt(s);
  const inner = Buffer.concat([
    Buffer.from([0x02, rBuf.length]),
    rBuf,
    Buffer.from([0x02, sBuf.length]),
    sBuf,
  ]);
  return Buffer.concat([Buffer.from([0x30, inner.length]), inner]);
}

/**
 * Verifica assinatura ECDSA DER (sem o byte de sighash).
 * @param {Buffer} hash32
 * @param {Buffer} derSig    - DER bytes (sem sighash byte)
 * @param {Buffer} pubKey33  - pubKey comprimida 33 bytes
 * @returns {boolean}
 */
function ecdsaVerify(hash32, derSig, pubKey33) {
  try {
    const { N, G, pointMul, pointAdd } = secp;
    const { r, s } = decodeDER(derSig);
    if (r <= 0n || r >= N || s <= 0n || s >= N) return false;

    const z   = BigInt('0x' + hash32.toString('hex'));
    const pt  = secp.decompressPubKey(pubKey33);
    const w   = secp.modInv(s, N);
    const u1  = secp.modn(z * w);
    const u2  = secp.modn(r * w);
    const R   = secp.pointAdd(pointMul(u1, G), pointMul(u2, pt));
    if (R === null) return false;
    return secp.modn(R[0]) === r;
  } catch {
    return false;
  }
}

function decodeDER(der) {
  if (der[0] !== 0x30) throw new Error('DER: byte inicial inválido');
  let offset = 2; // skip 0x30 + length
  if (der[offset] !== 0x02) throw new Error('DER: esperado 0x02 para r');
  const rLen = der[offset + 1];
  const r    = BigInt('0x' + der.slice(offset + 2, offset + 2 + rLen).toString('hex'));
  offset    += 2 + rLen;
  if (der[offset] !== 0x02) throw new Error('DER: esperado 0x02 para s');
  const sLen = der[offset + 1];
  const s    = BigInt('0x' + der.slice(offset + 2, offset + 2 + sLen).toString('hex'));
  return { r, s };
}

// ═══════════════════════════════════════════════════════════════
// TRANSACTION BUILDER
// ═══════════════════════════════════════════════════════════════

class TxBuilder {
  /**
   * @param {object} [opts]
   * @param {'mainnet'|'testnet'} [opts.network='mainnet']
   */
  constructor(opts = {}) {
    this.network    = opts.network || 'mainnet';
    this.hrp        = this.network === 'mainnet' ? 'bc' : 'tb';
    this._inputs    = [];   // inputs adicionados manualmente
    this._outputs   = [];   // outputs
    this._version   = 2;
    this._locktime  = 0;
    this._rbf       = true; // RBF opt-in por padrão (melhores práticas)
    this._signed    = false;
  }

  // ── Configuration ─────────────────────────────────────────

  /** Habilita/desabilita RBF (Replace-By-Fee). */
  setRBF(enabled) { this._rbf = enabled; return this; }

  /** Define locktime (0 = sem locktime; unix timestamp ou altura de bloco). */
  setLocktime(locktime) { this._locktime = locktime; return this; }

  /** Define version da transação (1 ou 2). */
  setVersion(v) { this._version = v; return this; }

  // ── Build from UTXOs ──────────────────────────────────────

  /**
   * Constrói uma transação completa com coin selection automático.
   *
   * @param {object} params
   * @param {import('./utxo').UTXOEntry[]} params.utxos       - UTXOs disponíveis
   * @param {string}  params.toAddress    - Endereço destino
   * @param {bigint}  params.amountSats   - Valor em satoshis
   * @param {string}  params.changeAddress - Endereço para troco
   * @param {bigint}  params.feeRate       - sat/vbyte
   * @param {string}  [params.inputType='P2WPKH']
   * @param {'LARGEST'|'OLDEST'|'BNB'} [params.algorithm='BNB']
   * @returns {{ tx: object, fee: bigint, change: bigint, vbytes: number }}
   */
  build({
    utxos, toAddress, amountSats, changeAddress,
    feeRate = 5n, inputType = 'P2WPKH', algorithm = 'BNB',
  }) {
    amountSats = BigInt(amountSats);
    feeRate    = BigInt(feeRate);

    // Detectar tipo do output destino
    const outputType = detectAddressType(toAddress, this.hrp);

    // Coin selection
    const sel = selectUTXOs({
      utxos, amountSats, feeRate,
      inputType, outputType,
      algorithm, outputCount: 1,
    });

    if (sel.error) throw new Error(sel.error);

    // Construir inputs
    const sequence = this._rbf ? 0xFFFFFFFD : 0xFFFFFFFF;
    const inputs   = sel.selected.map(u => ({
      txid:      u.txid,
      vout:      u.vout,
      scriptSig: Buffer.alloc(0),
      sequence,
      witness:   [],
      // Metadata para signing (não serializado)
      _utxo:     u,
    }));

    // Construir outputs
    const outputs = [buildOutput(toAddress, amountSats, this.hrp)];

    if (sel.change > 0n) {
      const dustLimit = BigInt(DUST_LIMITS[detectAddressType(changeAddress, this.hrp)] || 294);
      if (sel.change >= dustLimit) {
        outputs.push(buildOutput(changeAddress, sel.change, this.hrp));
      }
      // Se change < dust, já foi absorvido no fee pelo selectUTXOs
    }

    this._inputs  = inputs;
    this._outputs = outputs;
    this._utxoMap = new Map(sel.selected.map(u => [`${u.txid}:${u.vout}`, u]));

    const tx = {
      version:  this._version,
      inputs:   this._inputs,
      outputs:  this._outputs,
      locktime: this._locktime,
    };

    return {
      tx,
      fee:    sel.fee,
      change: sel.change,
      vbytes: sel.vbytes,
      inputs: sel.selected,
    };
  }

  /**
   * Assina todos os inputs de uma transação.
   *
   * @param {object}   tx          - Resultado de build()
   * @param {string[]} privateKeys - Uma privKey (hex) por input, na mesma ordem
   * @param {object[]} prevouts    - UTXOs sendo gastos [{ value, scriptPubKey }]
   * @returns {object} tx com inputs assinados e witness preenchida
   */
  sign(tx, privateKeys, prevouts) {
    if (privateKeys.length !== tx.inputs.length) {
      throw new Error(`Necessário ${tx.inputs.length} chaves, recebeu ${privateKeys.length}`);
    }

    for (let i = 0; i < tx.inputs.length; i++) {
      const privKeyHex = privateKeys[i];
      const prevout    = prevouts[i];
      const scriptType = classifyScript(prevout.scriptPubKey);

      switch (scriptType) {
        case 'P2PKH':
          this._signP2PKH(tx, i, privKeyHex, prevout);
          break;
        case 'P2WPKH':
          this._signP2WPKH(tx, i, privKeyHex, prevout);
          break;
        case 'P2TR':
          this._signP2TR(tx, i, privKeyHex, prevouts);
          break;
        default:
          throw new Error(`Tipo de script não suportado para signing: ${scriptType}`);
      }
    }

    this._signed = true;
    return tx;
  }

  // ── Private signing methods ───────────────────────────────

  _signP2PKH(tx, i, privKeyHex, prevout) {
    const pubKey   = this._pubKeyFromPriv(privKeyHex);
    const subScript = prevout.scriptPubKey; // scriptPubKey do UTXO
    const sighash  = legacySighash(tx, i, subScript, SIGHASH.ALL);
    const derSig   = ecdsaSignRaw(sighash, privKeyHex, SIGHASH.ALL);
    tx.inputs[i].scriptSig = p2pkhScriptSig(derSig, pubKey);
    tx.inputs[i].witness   = [];
  }

  _signP2WPKH(tx, i, privKeyHex, prevout) {
    const pubKey     = this._pubKeyFromPriv(privKeyHex);
    const pubKeyHash = hash160(pubKey);
    // scriptCode para P2WPKH BIP143: p2pkh(pubKeyHash)
    const scriptCode = p2pkhScript(pubKeyHash);
    const sighash    = segwitV0Sighash(tx, i, scriptCode, BigInt(prevout.value), SIGHASH.ALL);
    const derSig     = ecdsaSignRaw(sighash, privKeyHex, SIGHASH.ALL);
    tx.inputs[i].scriptSig = p2wpkhScriptSig();
    tx.inputs[i].witness   = p2wpkhWitness(derSig, pubKey);
  }

  _signP2TR(tx, i, privKeyHex, prevouts) {
    const prevoutsList = prevouts.map(p => ({
      value:       BigInt(p.value),
      scriptPubKey: Buffer.isBuffer(p.scriptPubKey) ? p.scriptPubKey : Buffer.from(p.scriptPubKey, 'hex'),
    }));

    // Taproot key-path: tweakear a privkey antes de assinar
    const tweakedPriv = tapTweakPrivateKey(Buffer.from(privKeyHex, 'hex'));
    const sighash     = taprootSighash(tx, i, prevoutsList, 0); // hashType=0 (DEFAULT)
    const schnorrSig  = schnorrSign(tweakedPriv, sighash);

    tx.inputs[i].scriptSig = p2trScriptSig();
    tx.inputs[i].witness   = p2trKeyPathWitness(schnorrSig, 0); // hashType DEFAULT = omitido
  }

  _pubKeyFromPriv(privKeyHex) {
    const k  = BigInt('0x' + privKeyHex);
    const pt = secp.pointMul(k, secp.G);
    return secp.compressedPubKey(pt);
  }

  // ── Serialize ─────────────────────────────────────────────

  /**
   * Serializa a transação assinada para hex.
   * @param {object} tx
   * @returns {{ hex: string, txid: string, wtxid: string, vbytes: number }}
   */
  serialize(tx) {
    const rawBuf  = serializeTransaction(tx);
    const hex     = rawBuf.toString('hex');
    const id      = calcTxid(tx);
    const weight  = calcWeight(tx);

    return {
      hex,
      txid:   id,
      wtxid:  require('./serialization').wtxid(tx),
      vbytes: weight.vbytes,
      weight: weight.weight,
      size:   rawBuf.length,
    };
  }
}

// ═══════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════

/**
 * Detecta o tipo de endereço e retorna o tipo de output.
 */
function detectAddressType(address, hrp = 'bc') {
  if (!address) throw new Error('Endereço vazio');
  const lower = address.toLowerCase();
  if (lower.startsWith(hrp + '1p')) return 'P2TR';
  if (lower.startsWith(hrp + '1q')) return 'P2WPKH';
  if (lower.startsWith(hrp + '1')) {
    // Verificar witness version
    const { witnessVersion } = require('./bech32').decodeSegwitAddress(hrp, lower);
    return witnessVersion === 1 ? 'P2TR' : 'P2WPKH';
  }
  if (address.startsWith('1') || address.startsWith('m') || address.startsWith('n')) return 'P2PKH';
  if (address.startsWith('3') || address.startsWith('2')) return 'P2SH';
  throw new Error('Tipo de endereço desconhecido: ' + address);
}

/**
 * Constrói um output a partir de um endereço.
 */
function buildOutput(address, valueSats, hrp = 'bc') {
  const lower = address.toLowerCase();
  let scriptPubKey;

  if (lower.startsWith(hrp + '1')) {
    // Bech32/Bech32m
    const { witnessVersion, program } = require('./bech32').decodeSegwitAddress(hrp, lower);
    if (witnessVersion === 0 && program.length === 20) scriptPubKey = p2wpkhScript(program);
    else if (witnessVersion === 1) scriptPubKey = p2trScript(program);
    else throw new Error('Witness program não suportado: v' + witnessVersion);
  } else if (address.startsWith('1') || address.startsWith('m')) {
    // P2PKH legacy
    const decoded = require('../../bitcoin').decodeBase58CheckAddr(address);
    scriptPubKey  = p2pkhScript(decoded.pubKeyHash);
  } else {
    throw new Error('Formato de endereço não suportado: ' + address);
  }

  return { value: BigInt(valueSats), scriptPubKey };
}

/**
 * Converte satoshis para BTC string.
 */
function satsToBtc(sats) {
  return (Number(BigInt(sats)) / 1e8).toFixed(8);
}

/**
 * Converte BTC string para satoshis BigInt.
 */
function btcToSats(btc) {
  return BigInt(Math.round(parseFloat(btc) * 1e8));
}

module.exports = {
  TxBuilder,
  ecdsaSignRaw,
  ecdsaVerify,
  encodeDER,
  decodeDER,
  rfc6979Nonce,
  detectAddressType,
  buildOutput,
  satsToBtc,
  btcToSats,

  // Re-exports úteis
  SIGHASH,
};

