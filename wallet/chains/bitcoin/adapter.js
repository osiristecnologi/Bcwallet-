/**
 * wallet/chains/bitcoin/adapter.js
 * ═══════════════════════════════════════════════════════════════
 * Adapter Bitcoin unificado — interface pública para HDWallet.
 *
 * Suporta os três tipos de endereço modernos:
 *   P2PKH  — Legacy    (1...)   — compatibilidade máxima
 *   P2WPKH — SegWit v0 (bc1q...) — fees menores
 *   P2TR   — Taproot   (bc1p...) — fees mínimos, privacidade
 *
 * Esta é a camada de integração entre o HDWallet (BIP44) e os
 * módulos de baixo nível (secp256k1, bech32, scripts, taproot).
 * ═══════════════════════════════════════════════════════════════
 */

'use strict';

const crypto   = require('crypto');
const secp     = require('./secp256k1');
const bech32   = require('./bech32');
const scripts  = require('./scripts');
const schnorr  = require('./schnorr');

// ─── Parâmetros de rede ──────────────────────────────────────
const NETWORKS = {
  mainnet: {
    bech32Hrp:     'bc',
    p2pkhVersion:  0x00,
    p2shVersion:   0x05,
    coinType:      0,
    chainId:       'btc-mainnet-1',
  },
  testnet: {
    bech32Hrp:     'tb',
    p2pkhVersion:  0x6f,
    p2shVersion:   0xc4,
    coinType:      1,
    chainId:       'btc-testnet-1',
  },
};

// BIP44 coin types
const COIN_TYPES = { BTC: 0, LTC: 2, DOGE: 3 };

// ─── Base58Check helpers ─────────────────────────────────────
const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest();
}
function hash160(data) {
  return crypto.createHash('ripemd160').update(sha256(data)).digest();
}
function checksum4(payload) {
  return sha256(sha256(payload)).slice(0, 4);
}

function base58CheckEncode(payload) {
  const full    = Buffer.concat([payload, checksum4(payload)]);
  let   num     = BigInt('0x' + full.toString('hex'));
  let   encoded = '';
  while (num > 0n) {
    encoded = BASE58[Number(num % 58n)] + encoded;
    num /= 58n;
  }
  for (const b of full) {
    if (b !== 0) break;
    encoded = '1' + encoded;
  }
  return encoded;
}

function base58CheckDecode(address) {
  let num = 0n;
  for (const c of address) {
    const i = BASE58.indexOf(c);
    if (i < 0) throw new Error(`Caractere inválido em Base58: '${c}'`);
    num = num * 58n + BigInt(i);
  }
  let hex = num.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  const raw = Buffer.from(hex, 'hex');

  // Restaurar zeros à frente
  const leadingZeros = address.match(/^1*/)[0].length;
  const full = leadingZeros > 0
    ? Buffer.concat([Buffer.alloc(leadingZeros), raw])
    : raw;

  if (full.length !== 25) throw new Error(`Tamanho inválido: ${full.length}`);
  const payload   = full.slice(0, 21);
  const cs        = full.slice(21);
  const expected  = checksum4(payload);
  if (!cs.equals(expected)) throw new Error('Checksum Base58Check inválido');
  return { version: payload[0], pubKeyHash: payload.slice(1) };
}

// ═══════════════════════════════════════════════════════════════
// ADDRESS GENERATORS
// ═══════════════════════════════════════════════════════════════

/**
 * Gera endereço P2PKH (Legacy) a partir da chave pública.
 * Formato: Base58Check com version byte 0x00 (mainnet).
 *
 * @param {Buffer} pubKey  - 33 bytes comprimido
 * @param {object} network
 * @returns {string} "1..."
 */
function p2pkhAddress(pubKey, network) {
  const pubKeyHash = hash160(pubKey);
  const versioned  = Buffer.concat([Buffer.from([network.p2pkhVersion]), pubKeyHash]);
  return base58CheckEncode(versioned);
}

/**
 * Gera endereço P2WPKH (Native SegWit) — "bc1q...".
 * Witness program = HASH160(pubKey), 20 bytes.
 *
 * @param {Buffer} pubKey
 * @param {object} network
 * @returns {string} "bc1q..."
 */
function p2wpkhAddress(pubKey, network) {
  const pubKeyHash = hash160(pubKey);
  return bech32.encodeSegwitAddress(network.bech32Hrp, 0, pubKeyHash);
}

/**
 * Gera endereço P2TR (Taproot) — "bc1p...".
 * Witness program = x-only tweaked pubKey, 32 bytes.
 * Key-path only (sem script tree → merkleRoot vazio).
 *
 * @param {Buffer} pubKey  - 33 bytes comprimido
 * @param {object} network
 * @param {Buffer} [merkleRoot] - Merkle root do script tree (default: vazio = key-path only)
 * @returns {string} "bc1p..."
 */
function p2trAddress(pubKey, network, merkleRoot = Buffer.alloc(0)) {
  // x-only internal key (32 bytes)
  const internalKey = secp.xOnlyPubKey(secp.decompressPubKey(pubKey));
  // Taproot output key = tweak(internalKey, merkleRoot)
  const { outputKey } = schnorr.tapTweakPublicKey(internalKey, merkleRoot);
  return bech32.encodeSegwitAddress(network.bech32Hrp, 1, outputKey);
}

// ═══════════════════════════════════════════════════════════════
// ADDRESS VALIDATION
// ═══════════════════════════════════════════════════════════════

/**
 * Valida qualquer tipo de endereço Bitcoin (Legacy, SegWit, Taproot).
 * @param {string} address
 * @param {object} network
 * @returns {boolean}
 */
function validateAddress(address, network) {
  if (!address || typeof address !== 'string') return false;
  const lower = address.toLowerCase();

  // Bech32/Bech32m (bc1...)
  if (lower.startsWith(network.bech32Hrp + '1')) {
    return bech32.isValidSegwitAddress(address, network.bech32Hrp);
  }

  // Base58Check (Legacy P2PKH / P2SH)
  try {
    const { version } = base58CheckDecode(address);
    return version === network.p2pkhVersion || version === network.p2shVersion;
  } catch {
    return false;
  }
}

/**
 * Identifica o tipo de um endereço Bitcoin.
 * @param {string} address
 * @param {object} network
 * @returns {'P2PKH'|'P2SH'|'P2WPKH'|'P2WSH'|'P2TR'|'UNKNOWN'}
 */
function classifyAddress(address, network) {
  if (!address) return 'UNKNOWN';
  const lower = address.toLowerCase();

  if (lower.startsWith(network.bech32Hrp + '1')) {
    try {
      const { witnessVersion, program } = bech32.decodeSegwitAddress(network.bech32Hrp, lower);
      if (witnessVersion === 0 && program.length === 20) return 'P2WPKH';
      if (witnessVersion === 0 && program.length === 32) return 'P2WSH';
      if (witnessVersion === 1)                          return 'P2TR';
    } catch {}
    return 'UNKNOWN';
  }

  try {
    const { version } = base58CheckDecode(address);
    if (version === network.p2pkhVersion) return 'P2PKH';
    if (version === network.p2shVersion)  return 'P2SH';
  } catch {}

  return 'UNKNOWN';
}

// ═══════════════════════════════════════════════════════════════
// SIGNING PAYLOAD (para HDWallet.signTransaction)
// ═══════════════════════════════════════════════════════════════

/**
 * Payload canônico para assinatura de mensagens off-chain.
 * Inclui chainId para anti-replay cross-chain.
 *
 * Para transações REAIS, use txbuilder.js que calcula o sighash correto.
 *
 * @param {object} tx
 * @param {string} chainId
 * @returns {string} SHA256 hex
 */
function signingPayload(tx, chainId) {
  const canonical = [
    chainId,
    tx.fromAddress || '',
    tx.toAddress,
    String(tx.amount || 0),
    String(tx.fee    || 0),
    String(tx.nonce  || 0),
    tx.type || 'transfer',
    String(tx.timestamp || 0),
  ].join('|');
  return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
}

// ═══════════════════════════════════════════════════════════════
// DERIVATION PATHS
// ═══════════════════════════════════════════════════════════════

/**
 * Retorna o path BIP44/49/84/86 correto para cada tipo de endereço.
 *
 * BIP44: m/44'/0'/account'/change/index — P2PKH
 * BIP49: m/49'/0'/account'/change/index — P2SH-P2WPKH (wrapped SegWit)
 * BIP84: m/84'/0'/account'/change/index — P2WPKH (native SegWit)
 * BIP86: m/86'/0'/account'/change/index — P2TR (Taproot)
 *
 * @param {string} addrType    - 'P2PKH' | 'P2WPKH' | 'P2TR'
 * @param {number} [account=0]
 * @param {number} [change=0]
 * @param {number} [index=0]
 * @param {number} [coinType=0]
 * @returns {string}
 */
function derivationPath(addrType = 'P2WPKH', account = 0, change = 0, index = 0, coinType = 0) {
  const PURPOSE = { P2PKH: 44, P2WPKH: 84, P2TR: 86 };
  const purpose = PURPOSE[addrType] || 84;
  return `m/${purpose}'/${coinType}'/${account}'/${change}/${index}`;
}

// ═══════════════════════════════════════════════════════════════
// WATCH-ONLY: BIP32 child public key derivation
// ═══════════════════════════════════════════════════════════════

/**
 * Deriva uma chave pública filha a partir de uma chave pública pai
 * e um chain code (watch-only — sem necessidade de privKey).
 *
 * childPub = point(IL) + parentPub
 * onde IL = primeiros 32 bytes de HMAC-SHA512(chainCode, parentPub || index)
 *
 * IMPLEMENTAÇÃO REAL com adição de pontos via secp256k1.pointAdd.
 * Substitui a aproximação anterior que usava apenas IL como ponto.
 *
 * @param {Buffer} parentPubKey  - 33 bytes comprimido
 * @param {Buffer} chainCode     - 32 bytes
 * @param {number} index         - 0..0x7FFFFFFF (apenas normal, não hardened)
 * @returns {{ publicKey: Buffer, chainCode: Buffer }}
 */
function deriveChildPubKey(parentPubKey, chainCode, index) {
  if (index >= 0x80000000) {
    throw new Error('Watch-only: derivação hardened requer privKey');
  }

  // data = pubKey (33B) || index (4B BE)
  const indexBuf = Buffer.alloc(4);
  indexBuf.writeUInt32BE(index, 0);
  const data = Buffer.concat([parentPubKey, indexBuf]);

  const I  = crypto.createHmac('sha512', chainCode).update(data).digest();
  const IL = I.slice(0, 32);
  const IR = I.slice(32);

  const ilNum  = BigInt('0x' + IL.toString('hex'));
  if (ilNum >= secp.N) throw new Error('IL >= N: índice inválido, tente o próximo');

  // point(IL) = IL * G
  const ilPoint = secp.pointMul(ilNum, secp.G);

  // Descomprimir parentPub para ponto
  const parentPoint = secp.decompressPubKey(parentPubKey);

  // childPub = point(IL) + parentPub
  const childPoint = secp.pointAdd(ilPoint, parentPoint);
  if (childPoint === null) throw new Error('childPoint é ponto no infinito');

  return {
    publicKey: secp.compressedPubKey(childPoint),
    chainCode: IR,
  };
}

// ═══════════════════════════════════════════════════════════════
// ADAPTER FACTORY
// ═══════════════════════════════════════════════════════════════

/**
 * Cria um adapter Bitcoin para uma rede e tipo de endereço específicos.
 *
 * @param {object} [opts]
 * @param {'mainnet'|'testnet'} [opts.network='mainnet']
 * @param {'P2PKH'|'P2WPKH'|'P2TR'} [opts.addressType='P2WPKH']
 * @returns {object} Chain adapter compatível com HDWallet
 */
function createAdapter(opts = {}) {
  const {
    network: networkName = 'mainnet',
    addressType = 'P2WPKH',
    coinType = 0,
  } = opts;

  const network = NETWORKS[networkName];
  if (!network) throw new Error(`Rede desconhecida: ${networkName}`);

  return {
    name:        'Bitcoin',
    symbol:      coinType === 0 ? 'BTC' : coinType === 2 ? 'LTC' : 'DOGE',
    coinType,
    chainId:     network.chainId,
    decimals:    8,
    algorithm:   addressType === 'P2TR' ? 'schnorr' : 'ecdsa-secp256k1',
    addressType,
    network:     networkName,

    /**
     * Gera endereço a partir da chave pública comprimida.
     * @param {Buffer|string} publicKey - 33 bytes
     * @param {'P2PKH'|'P2WPKH'|'P2TR'} [type] - Override do tipo
     */
    getAddress(publicKey, type) {
      const pub  = Buffer.isBuffer(publicKey) ? publicKey : Buffer.from(publicKey, 'hex');
      const aType = type || addressType;
      if (aType === 'P2PKH')  return p2pkhAddress(pub, network);
      if (aType === 'P2WPKH') return p2wpkhAddress(pub, network);
      if (aType === 'P2TR')   return p2trAddress(pub, network);
      throw new Error(`Tipo de endereço inválido: ${aType}`);
    },

    validateAddress(address) {
      return validateAddress(address, network);
    },

    classifyAddress(address) {
      return classifyAddress(address, network);
    },

    signingPayload(tx) {
      return signingPayload(tx, network.chainId);
    },

    derivationPath(account = 0, change = 0, index = 0) {
      return derivationPath(addressType, account, change, index, coinType);
    },

    deriveChildPubKey(parentPubKey, chainCode, index) {
      return deriveChildPubKey(parentPubKey, chainCode, index);
    },

    // Acesso aos módulos de baixo nível
    modules: {
      secp256k1:    secp,
      bech32,
      scripts,
      schnorr,
    },
  };
}

// ─── Adapters pré-configurados ───────────────────────────────

/** Bitcoin mainnet, Native SegWit P2WPKH (bc1q...) — padrão moderno */
const bitcoin = createAdapter({ network: 'mainnet', addressType: 'P2WPKH', coinType: 0 });

/** Bitcoin mainnet, Taproot P2TR (bc1p...) — padrão 2022+ */
const bitcoinTaproot = createAdapter({ network: 'mainnet', addressType: 'P2TR', coinType: 0 });

/** Bitcoin mainnet, Legacy P2PKH (1...) — compatibilidade */
const bitcoinLegacy = createAdapter({ network: 'mainnet', addressType: 'P2PKH', coinType: 0 });

/** Litecoin mainnet */
const litecoin = createAdapter({ network: 'mainnet', addressType: 'P2WPKH', coinType: 2 });

/** Dogecoin mainnet */
const dogecoin = createAdapter({ network: 'mainnet', addressType: 'P2PKH', coinType: 3 });

module.exports = {
  createAdapter,
  NETWORKS,
  COIN_TYPES,

  // Pre-built adapters
  bitcoin,
  bitcoinTaproot,
  bitcoinLegacy,
  litecoin,
  dogecoin,

  // Exported utilities
  p2pkhAddress,
  p2wpkhAddress,
  p2trAddress,
  validateAddress,
  classifyAddress,
  derivationPath,
  deriveChildPubKey,
  base58CheckEncode,
  base58CheckDecode,
  hash160,
};

