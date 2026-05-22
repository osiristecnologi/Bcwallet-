/**
 * wallet/chains/bitcoin/serialization.js
 * ═══════════════════════════════════════════════════════════════
 * Serialização e deserialização de transações Bitcoin.
 * Compatível com Bitcoin Core, Electrum, Sparrow, Ledger.
 *
 * FORMATOS:
 *   Legacy (pre-SegWit):
 *     [version][vin_count][vin...][vout_count][vout...][locktime]
 *
 *   SegWit (BIP141):
 *     [version][marker=0x00][flag=0x01][vin_count][vin...]
 *     [vout_count][vout...][witness...][locktime]
 *
 * TXID vs WTXID:
 *   txid  = SHA256d(legacy serialization)  — sem witness
 *   wtxid = SHA256d(segwit serialization)  — com witness
 *
 * WEIGHT / VIRTUAL BYTES:
 *   weight = (base_size * 3) + total_size
 *   vbytes = ceil(weight / 4)
 *   Fee    = vbytes * fee_rate_sat_per_vbyte
 * ═══════════════════════════════════════════════════════════════
 */

'use strict';

const crypto  = require('crypto');
const { varInt, readVarInt } = require('./scripts');

// ─── SHA256d ─────────────────────────────────────────────────
function sha256d(data) {
  return crypto.createHash('sha256')
    .update(crypto.createHash('sha256').update(data).digest())
    .digest();
}

// ─── LE helpers ──────────────────────────────────────────────
function int32LE(n) {
  const b = Buffer.alloc(4);
  b.writeInt32LE(n >>> 0, 0);
  return b;
}
function uint32LE(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n >>> 0, 0);
  return b;
}
function int64LE(n) {
  const b = Buffer.alloc(8);
  b.writeBigInt64LE(BigInt(n), 0);
  return b;
}
function reverseBuffer(buf) {
  return Buffer.from(buf).reverse();
}

// ═══════════════════════════════════════════════════════════════
// TRANSACTION INPUT / OUTPUT TYPES
// ═══════════════════════════════════════════════════════════════

/**
 * @typedef {object} TxInput
 * @property {string}   txid      - txid em hex (little-endian internamente)
 * @property {number}   vout      - output index
 * @property {Buffer}   scriptSig - scriptSig (vazio para SegWit)
 * @property {number}   sequence  - 0xffffffff = final, 0xfffffffd = RBF
 * @property {Buffer[]} witness   - Stack de witness ([] para legacy)
 */

/**
 * @typedef {object} TxOutput
 * @property {bigint|number} value       - Valor em satoshis
 * @property {Buffer}        scriptPubKey - Output script
 */

/**
 * @typedef {object} Transaction
 * @property {number}    version  - 1 ou 2
 * @property {TxInput[]} inputs
 * @property {TxOutput[]}outputs
 * @property {number}    locktime - 0 = sem locktime
 */

// ═══════════════════════════════════════════════════════════════
// SERIALIZE
// ═══════════════════════════════════════════════════════════════

/**
 * Serializa um input de transação.
 * @param {TxInput} input
 * @returns {Buffer}
 */
function serializeInput(input) {
  const txidBuf = reverseBuffer(Buffer.from(input.txid, 'hex')); // txid em LE
  const voutBuf = uint32LE(input.vout);
  const script  = input.scriptSig || Buffer.alloc(0);
  const seqBuf  = uint32LE(input.sequence !== undefined ? input.sequence : 0xffffffff);
  return Buffer.concat([txidBuf, voutBuf, varInt(script.length), script, seqBuf]);
}

/**
 * Serializa um output de transação.
 * @param {TxOutput} output
 * @returns {Buffer}
 */
function serializeOutput(output) {
  const valueBuf  = int64LE(output.value);
  const script    = output.scriptPubKey;
  return Buffer.concat([valueBuf, varInt(script.length), script]);
}

/**
 * Serializa a witness de um input (para cálculo de wtxid e broadcast).
 * @param {Buffer[]} witnessItems
 * @returns {Buffer}
 */
function serializeWitness(witnessItems) {
  const parts = [varInt(witnessItems.length)];
  for (const item of witnessItems) {
    parts.push(varInt(item.length), item);
  }
  return Buffer.concat(parts);
}

/**
 * Serializa uma transação completa.
 *
 * @param {Transaction} tx
 * @param {object} [opts]
 * @param {boolean} [opts.forSigning=false]  - Omitir witness (para cálculo de txid)
 * @param {boolean} [opts.segwitMarker=true] - Incluir marker+flag SegWit se necessário
 * @returns {Buffer} Transação serializada em bytes
 */
function serializeTransaction(tx, opts = {}) {
  const { forSigning = false } = opts;

  const hasWitness = !forSigning && tx.inputs.some(
    inp => inp.witness && inp.witness.length > 0
  );

  const parts = [];

  // Version (4 bytes LE)
  parts.push(int32LE(tx.version));

  // SegWit marker + flag
  if (hasWitness) {
    parts.push(Buffer.from([0x00, 0x01]));
  }

  // Inputs
  parts.push(varInt(tx.inputs.length));
  for (const inp of tx.inputs) {
    parts.push(serializeInput(inp));
  }

  // Outputs
  parts.push(varInt(tx.outputs.length));
  for (const out of tx.outputs) {
    parts.push(serializeOutput(out));
  }

  // Witness data (um stack por input)
  if (hasWitness) {
    for (const inp of tx.inputs) {
      parts.push(serializeWitness(inp.witness || []));
    }
  }

  // Locktime (4 bytes LE)
  parts.push(uint32LE(tx.locktime || 0));

  return Buffer.concat(parts);
}

// ═══════════════════════════════════════════════════════════════
// TXID / WTXID
// ═══════════════════════════════════════════════════════════════

/**
 * Calcula o txid de uma transação (SHA256d da serialização legacy).
 * txid NÃO inclui dados witness — compatível com nodes antigos.
 *
 * @param {Transaction} tx
 * @returns {string} txid em hex (big-endian, como exibido em explorers)
 */
function txid(tx) {
  const legacy = serializeTransaction(tx, { forSigning: true });
  return reverseBuffer(sha256d(legacy)).toString('hex');
}

/**
 * Calcula o wtxid (SHA256d da serialização completa com witness).
 * @param {Transaction} tx
 * @returns {string} wtxid em hex
 */
function wtxid(tx) {
  const full = serializeTransaction(tx);
  return reverseBuffer(sha256d(full)).toString('hex');
}

// ═══════════════════════════════════════════════════════════════
// WEIGHT / VBYTES (BIP141)
// ═══════════════════════════════════════════════════════════════

/**
 * Calcula o weight de uma transação (para fee estimation).
 *
 * weight = base_size * 4 + witness_size * 1
 *   base_size   = tamanho sem witness (legacy serialization)
 *   witness_size = tamanho só dos dados witness
 *
 * @param {Transaction} tx
 * @returns {{ weight: number, vbytes: number, baseSize: number, witnessSize: number }}
 */
function calcWeight(tx) {
  const baseSerialized = serializeTransaction(tx, { forSigning: true });
  const fullSerialized = serializeTransaction(tx);

  const baseSize    = baseSerialized.length;
  const totalSize   = fullSerialized.length;

  // SegWit overhead: 2 bytes (marker + flag) contam como witness weight
  const hasWitness  = tx.inputs.some(i => i.witness && i.witness.length > 0);
  const witnessSize = hasWitness ? totalSize - baseSize + 2 : 0;

  // weight = base * 4 + witness * 1
  // Mas o padrão BIP141 é: non-witness * 4 + witness * 1
  // non-witness = baseSize (sem os 2 bytes de marker/flag)
  const weight = baseSize * 4 + witnessSize;
  const vbytes = Math.ceil(weight / 4);

  return { weight, vbytes, baseSize, witnessSize, totalSize };
}

// ═══════════════════════════════════════════════════════════════
// SIGHASH (BIP143 — SegWit v0)
// ═══════════════════════════════════════════════════════════════

/** Tipos de sighash */
const SIGHASH = {
  ALL:          0x01,
  NONE:         0x02,
  SINGLE:       0x03,
  ANYONECANPAY: 0x80,
};

/**
 * Calcula o sighash para um input P2WPKH (BIP143).
 *
 * Este é o preimage que será assinado com ECDSA para SegWit v0.
 * Inclui hashPrevouts, hashSequence, hashOutputs para proteger
 * contra ataques de replay e malleabilidade.
 *
 * @param {Transaction} tx
 * @param {number}      inputIndex  - Índice do input sendo assinado
 * @param {Buffer}      scriptCode  - Para P2WPKH: p2pkhScript(pubKeyHash)
 * @param {bigint}      amount      - Valor do UTXO sendo gasto (satoshis)
 * @param {number}      [hashType=SIGHASH.ALL]
 * @returns {Buffer} 32 bytes para assinar
 */
function segwitV0Sighash(tx, inputIndex, scriptCode, amount, hashType = SIGHASH.ALL) {
  const anyoneCanPay = !!(hashType & SIGHASH.ANYONECANPAY);
  const baseType     = hashType & 0x1f;

  // hashPrevouts
  let hashPrevouts = Buffer.alloc(32);
  if (!anyoneCanPay) {
    const prevouts = tx.inputs.map(inp =>
      Buffer.concat([reverseBuffer(Buffer.from(inp.txid,'hex')), uint32LE(inp.vout)])
    );
    hashPrevouts = sha256d(Buffer.concat(prevouts));
  }

  // hashSequence
  let hashSequence = Buffer.alloc(32);
  if (!anyoneCanPay && baseType !== SIGHASH.SINGLE && baseType !== SIGHASH.NONE) {
    const seqs = tx.inputs.map(inp => uint32LE(inp.sequence !== undefined ? inp.sequence : 0xffffffff));
    hashSequence = sha256d(Buffer.concat(seqs));
  }

  // hashOutputs
  let hashOutputs = Buffer.alloc(32);
  if (baseType !== SIGHASH.SINGLE && baseType !== SIGHASH.NONE) {
    const outs = tx.outputs.map(out => serializeOutput(out));
    hashOutputs = sha256d(Buffer.concat(outs));
  } else if (baseType === SIGHASH.SINGLE && inputIndex < tx.outputs.length) {
    hashOutputs = sha256d(serializeOutput(tx.outputs[inputIndex]));
  }

  const inp = tx.inputs[inputIndex];
  const preimage = Buffer.concat([
    int32LE(tx.version),
    hashPrevouts,
    hashSequence,
    reverseBuffer(Buffer.from(inp.txid, 'hex')),   // outpoint txid (LE)
    uint32LE(inp.vout),                            // outpoint index
    varInt(scriptCode.length), scriptCode,          // scriptCode
    int64LE(amount),                               // value in satoshis
    uint32LE(inp.sequence !== undefined ? inp.sequence : 0xffffffff),
    hashOutputs,
    uint32LE(tx.locktime || 0),
    uint32LE(hashType),
  ]);

  return sha256d(preimage);
}

/**
 * Calcula o sighash BIP341 (Taproot / SegWit v1).
 *
 * @param {Transaction} tx
 * @param {number}      inputIndex
 * @param {TxOutput[]}  prevouts    - Todos os UTXOs sendo gastos nesta tx
 * @param {number}      [hashType=0] - 0 = DEFAULT (ALL)
 * @param {number}      [extFlag=0]  - 0 = key-path, 1 = script-path
 * @param {Buffer}      [annex]      - Taproot annex (opcional)
 * @returns {Buffer} 32 bytes para assinar com Schnorr
 */
function taprootSighash(tx, inputIndex, prevouts, hashType = 0, extFlag = 0, annex = null) {
  const { taggedHash } = require('./schnorr');

  // Validar sighash type
  const baseType     = hashType === 0 ? 0 : hashType & 0x03;
  const anyoneCanPay = !!(hashType & SIGHASH.ANYONECANPAY);
  if (hashType > 3 && hashType !== 0x81 && hashType !== 0x82 && hashType !== 0x83) {
    throw new Error('hashType inválido para Taproot: ' + hashType);
  }

  // Epoch + hashType
  const parts = [
    Buffer.from([0x00]),       // epoch (sempre 0)
    Buffer.from([hashType]),
  ];

  // nVersion + nLockTime
  parts.push(int32LE(tx.version), uint32LE(tx.locktime || 0));

  if (!anyoneCanPay) {
    // sha_prevouts
    const prevsBuf = tx.inputs.map(inp =>
      Buffer.concat([reverseBuffer(Buffer.from(inp.txid,'hex')), uint32LE(inp.vout)])
    );
    parts.push(sha256d(Buffer.concat(prevsBuf)));

    // sha_amounts
    const amtsBuf = prevouts.map(o => int64LE(o.value));
    parts.push(sha256d(Buffer.concat(amtsBuf)));

    // sha_scriptpubkeys
    const spksBuf = prevouts.map(o =>
      Buffer.concat([varInt(o.scriptPubKey.length), o.scriptPubKey])
    );
    parts.push(sha256d(Buffer.concat(spksBuf)));

    // sha_sequences
    const seqsBuf = tx.inputs.map(inp =>
      uint32LE(inp.sequence !== undefined ? inp.sequence : 0xffffffff)
    );
    parts.push(sha256d(Buffer.concat(seqsBuf)));
  }

  if (baseType !== SIGHASH.NONE) {
    const outsBuf = tx.outputs.map(o => serializeOutput(o));
    if (baseType === SIGHASH.SINGLE) {
      parts.push(sha256d(serializeOutput(tx.outputs[inputIndex])));
    } else {
      parts.push(sha256d(Buffer.concat(outsBuf)));
    }
  }

  // spend_type: extFlag * 2 + (annex ? 1 : 0)
  const spendType = extFlag * 2 + (annex ? 1 : 0);
  parts.push(Buffer.from([spendType]));

  if (anyoneCanPay) {
    const inp = tx.inputs[inputIndex];
    parts.push(
      reverseBuffer(Buffer.from(inp.txid,'hex')),
      uint32LE(inp.vout),
      int64LE(prevouts[inputIndex].value),
      varInt(prevouts[inputIndex].scriptPubKey.length),
      prevouts[inputIndex].scriptPubKey,
      uint32LE(inp.sequence !== undefined ? inp.sequence : 0xffffffff)
    );
  } else {
    parts.push(uint32LE(inputIndex));
  }

  if (annex) {
    const annexHash = sha256d(Buffer.concat([varInt(annex.length), annex]));
    parts.push(annexHash);
  }

  const preimage = Buffer.concat(parts);
  return taggedHash('TapSighash', preimage);
}

// ═══════════════════════════════════════════════════════════════
// LEGACY SIGHASH (P2PKH)
// ═══════════════════════════════════════════════════════════════

/**
 * Sighash legacy para P2PKH (pré-SegWit).
 *
 * @param {Transaction} tx
 * @param {number}      inputIndex
 * @param {Buffer}      subscript   - scriptPubKey do UTXO sendo gasto
 * @param {number}      [hashType=SIGHASH.ALL]
 * @returns {Buffer} 32 bytes
 */
function legacySighash(tx, inputIndex, subscript, hashType = SIGHASH.ALL) {
  // Clonar tx com scriptSig substituído
  const txCopy = {
    ...tx,
    inputs: tx.inputs.map((inp, i) => ({
      ...inp,
      scriptSig: i === inputIndex ? subscript : Buffer.alloc(0),
      witness:   [],
    })),
  };

  const preimage = Buffer.concat([
    serializeTransaction(txCopy, { forSigning: true }),
    uint32LE(hashType),
  ]);

  return sha256d(preimage);
}

// ═══════════════════════════════════════════════════════════════
// DESERIALIZE (para parsing de txs recebidas)
// ═══════════════════════════════════════════════════════════════

/**
 * Deserializa uma transação raw Bitcoin.
 * @param {Buffer|string} raw - Buffer ou hex string
 * @returns {Transaction}
 */
function deserializeTransaction(raw) {
  const buf = Buffer.isBuffer(raw) ? raw : Buffer.from(raw, 'hex');
  let offset = 0;

  // Version
  const version = buf.readInt32LE(offset); offset += 4;

  // SegWit marker?
  let hasWitness = false;
  if (buf[offset] === 0x00 && buf[offset + 1] === 0x01) {
    hasWitness = true;
    offset += 2;
  }

  // Inputs
  const { value: inCount, size: inVarSize } = readVarInt(buf, offset);
  offset += inVarSize;

  const inputs = [];
  for (let i = 0; i < inCount; i++) {
    const txid    = reverseBuffer(buf.slice(offset, offset + 32)).toString('hex');
    offset += 32;
    const vout    = buf.readUInt32LE(offset); offset += 4;
    const { value: scriptLen, size: scriptVarSize } = readVarInt(buf, offset);
    offset += scriptVarSize;
    const scriptSig = buf.slice(offset, offset + scriptLen); offset += scriptLen;
    const sequence  = buf.readUInt32LE(offset); offset += 4;
    inputs.push({ txid, vout, scriptSig, sequence, witness: [] });
  }

  // Outputs
  const { value: outCount, size: outVarSize } = readVarInt(buf, offset);
  offset += outVarSize;

  const outputs = [];
  for (let i = 0; i < outCount; i++) {
    const value = buf.readBigInt64LE(offset); offset += 8;
    const { value: scriptLen, size: scriptVarSize } = readVarInt(buf, offset);
    offset += scriptVarSize;
    const scriptPubKey = buf.slice(offset, offset + scriptLen); offset += scriptLen;
    outputs.push({ value, scriptPubKey });
  }

  // Witness
  if (hasWitness) {
    for (let i = 0; i < inputs.length; i++) {
      const { value: wCount, size: wVarSize } = readVarInt(buf, offset);
      offset += wVarSize;
      const witness = [];
      for (let j = 0; j < wCount; j++) {
        const { value: itemLen, size: itemVarSize } = readVarInt(buf, offset);
        offset += itemVarSize;
        witness.push(buf.slice(offset, offset + itemLen));
        offset += itemLen;
      }
      inputs[i].witness = witness;
    }
  }

  // Locktime
  const locktime = buf.readUInt32LE(offset);

  return { version, inputs, outputs, locktime };
}

module.exports = {
  // Core serialize
  serializeTransaction,
  serializeInput,
  serializeOutput,
  serializeWitness,
  deserializeTransaction,

  // IDs
  txid,
  wtxid,

  // Weight
  calcWeight,

  // Sighash
  SIGHASH,
  legacySighash,
  segwitV0Sighash,
  taprootSighash,

  // Helpers
  sha256d,
  int32LE,
  uint32LE,
  int64LE,
  reverseBuffer,
};

