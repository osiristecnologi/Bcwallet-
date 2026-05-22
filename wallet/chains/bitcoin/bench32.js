/**
 * wallet/chains/bitcoin/bech32.js
 * ═══════════════════════════════════════════════════════════════
 * Bech32 (BIP173) e Bech32m (BIP350) — zero dependências externas.
 *
 * Bech32:  usado em P2WPKH (bc1q...) e P2WSH (bc1q...)
 * Bech32m: usado em P2TR   (bc1p...) — Taproot (BIP341)
 *
 * A diferença entre Bech32 e Bech32m é a constante do polinômio:
 *   Bech32:  CONST = 1
 *   Bech32m: CONST = 0x2bc830a3
 *
 * ENDEREÇOS GERADOS:
 *   P2WPKH: bc1q<20-byte-hash>  (witness v0, 42 chars)
 *   P2TR:   bc1p<32-byte-xonly> (witness v1, 62 chars)
 * ═══════════════════════════════════════════════════════════════
 */

'use strict';

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

const BECH32_CONST   = 1;
const BECH32M_CONST  = 0x2bc830a3;

// ─── Core polymod ────────────────────────────────────────────

function polymod(values) {
  let chk = 1;
  for (const v of values) {
    const b = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if ((b >>> i) & 1) chk ^= GENERATOR[i];
    }
  }
  return chk;
}

function hrpExpand(hrp) {
  const ret = [];
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) >>> 5);
  ret.push(0);
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) & 31);
  return ret;
}

// ─── Checksum ────────────────────────────────────────────────

function createChecksum(hrp, data, constant) {
  const values = [...hrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0];
  const pm = polymod(values) ^ constant;
  return Array.from({ length: 6 }, (_, i) => (pm >>> (5 * (5 - i))) & 31);
}

function verifyChecksum(hrp, data) {
  const pm = polymod([...hrpExpand(hrp), ...data]);
  if (pm === BECH32_CONST)  return 'bech32';
  if (pm === BECH32M_CONST) return 'bech32m';
  return null;
}

// ─── Bit conversion ──────────────────────────────────────────

/**
 * Converte bits de fromBits para toBits (usado para 8→5 e 5→8).
 * @param {number[]} data
 * @param {number}   fromBits
 * @param {number}   toBits
 * @param {boolean}  pad
 */
function convertBits(data, fromBits, toBits, pad = true) {
  let acc = 0, bits = 0;
  const ret = [];
  const maxv = (1 << toBits) - 1;
  for (const v of data) {
    if (v < 0 || v >>> fromBits !== 0) throw new Error('convertBits: valor inválido');
    acc = (acc << fromBits) | v;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      ret.push((acc >>> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) ret.push((acc << (toBits - bits)) & maxv);
  } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) !== 0) {
    throw new Error('convertBits: padding inválido');
  }
  return ret;
}

// ─── Encode ──────────────────────────────────────────────────

/**
 * Codifica dados em Bech32 ou Bech32m.
 *
 * @param {string}   hrp      - Human-readable part ('bc', 'ltc', etc.)
 * @param {number[]} data     - Dados em 5-bit groups
 * @param {number}   constant - BECH32_CONST ou BECH32M_CONST
 * @returns {string}
 */
function bech32Encode(hrp, data, constant) {
  const checksum = createChecksum(hrp, data, constant);
  return hrp + '1' + [...data, ...checksum].map(d => CHARSET[d]).join('');
}

/**
 * Decodifica um endereço Bech32/Bech32m.
 *
 * @param {string} str
 * @returns {{ hrp: string, data: number[], encoding: 'bech32'|'bech32m' }}
 * @throws {Error} se inválido
 */
function bech32Decode(str) {
  const lower = str.toLowerCase();
  const upper = str.toUpperCase();
  if (str !== lower && str !== upper) throw new Error('Case mixing inválido');

  const pos = lower.lastIndexOf('1');
  if (pos < 1 || pos + 7 > lower.length || lower.length > 90) {
    throw new Error('Comprimento inválido');
  }

  const hrp  = lower.slice(0, pos);
  const data = [];
  for (let i = pos + 1; i < lower.length; i++) {
    const d = CHARSET.indexOf(lower[i]);
    if (d < 0) throw new Error(`Caractere inválido: '${lower[i]}'`);
    data.push(d);
  }

  const encoding = verifyChecksum(hrp, data);
  if (!encoding) throw new Error('Checksum Bech32 inválido');

  return { hrp, data: data.slice(0, -6), encoding };
}

// ─── Segwit Address API ──────────────────────────────────────

/**
 * Codifica um endereço SegWit (P2WPKH ou P2TR).
 *
 * @param {string} hrp          - 'bc' (mainnet), 'tb' (testnet)
 * @param {number} witnessVersion - 0 = P2WPKH/P2WSH, 1 = P2TR
 * @param {Buffer} program      - 20 bytes (P2WPKH) ou 32 bytes (P2TR)
 * @returns {string} Endereço Bech32 ou Bech32m
 */
function encodeSegwitAddress(hrp, witnessVersion, program) {
  if (witnessVersion < 0 || witnessVersion > 16) {
    throw new Error('Witness version inválida: ' + witnessVersion);
  }
  if (program.length < 2 || program.length > 40) {
    throw new Error('Witness program inválido: ' + program.length + ' bytes');
  }
  if (witnessVersion === 0 && program.length !== 20 && program.length !== 32) {
    throw new Error('P2WPKH deve ter 20 bytes, P2WSH deve ter 32 bytes');
  }

  const data = [witnessVersion, ...convertBits([...program], 8, 5)];
  const constant = witnessVersion === 0 ? BECH32_CONST : BECH32M_CONST;
  const addr = bech32Encode(hrp, data, constant);

  // Verificar comprimento esperado
  if (witnessVersion === 0 && program.length === 20 && addr.length !== 42) {
    throw new Error('P2WPKH deve ter 42 chars: ' + addr.length);
  }

  return addr;
}

/**
 * Decodifica um endereço SegWit.
 *
 * @param {string} hrp     - HRP esperado ('bc', 'tb', etc.)
 * @param {string} address - Endereço a decodificar
 * @returns {{ witnessVersion: number, program: Buffer }}
 * @throws {Error} se inválido
 */
function decodeSegwitAddress(hrp, address) {
  const { hrp: decodedHrp, data, encoding } = bech32Decode(address);

  if (decodedHrp !== hrp) {
    throw new Error(`HRP inválido: esperado '${hrp}', recebido '${decodedHrp}'`);
  }
  if (data.length < 1) throw new Error('Witness data vazio');

  const witnessVersion = data[0];
  const expectedEncoding = witnessVersion === 0 ? 'bech32' : 'bech32m';
  if (encoding !== expectedEncoding) {
    throw new Error(`Encoding inválido para witness v${witnessVersion}: esperado ${expectedEncoding}`);
  }

  const program = Buffer.from(convertBits(data.slice(1), 5, 8, false));
  if (program.length < 2 || program.length > 40) {
    throw new Error('Witness program de tamanho inválido');
  }

  return { witnessVersion, program };
}

/**
 * Valida um endereço Bech32/Bech32m sem lançar erro.
 * @param {string} address
 * @param {string} hrp
 * @returns {boolean}
 */
function isValidSegwitAddress(address, hrp = 'bc') {
  try {
    decodeSegwitAddress(hrp, address.toLowerCase());
    return true;
  } catch {
    return false;
  }
}

module.exports = {
  // Constantes
  BECH32_CONST,
  BECH32M_CONST,

  // Core
  bech32Encode,
  bech32Decode,
  convertBits,

  // SegWit API
  encodeSegwitAddress,
  decodeSegwitAddress,
  isValidSegwitAddress,
};

