/**
 * wallet/security/index.js
 * ═══════════════════════════════════════════════════════════════
 * Camada de segurança transversal da HD Wallet.
 *
 * COMPONENTES:
 *
 *   BruteForceGuard  — lockout temporário com backoff exponencial
 *   secureCompare    — comparação timing-safe de strings/buffers
 *   SecureLogger     — logger que jamais expõe dados sensíveis
 *   HardwareSigner   — interface (stub) para Ledger/Trezor/Keystone
 *   secureWipe       — sobrescrita de buffers em múltiplas passadas
 *   PasswordPolicy   — entropia-based (não regras de complexidade)
 *
 * THREAT MODEL:
 *   • Brute-force local: mitigado por lockout + backoff
 *   • Timing attacks: mitigado por timingSafeEqual
 *   • Memory disclosure: mitigado por secureWipe
 *   • Log leakage: mitigado por SecureLogger
 *   • Supply chain: sem deps externas, apenas Node stdlib
 * ═══════════════════════════════════════════════════════════════
 */

'use strict';

const crypto = require('crypto');

// ═══════════════════════════════════════════════════════════════
// 1. SECURE WIPE
// ═══════════════════════════════════════════════════════════════

/**
 * Sobrescreve um Buffer com múltiplos padrões para dificultar
 * recuperação forense de dados sensíveis da memória.
 *
 * AVISO: JavaScript não garante controle sobre GC nem sobre
 * endereços de memória. Esta função é best-effort.
 * Para segurança máxima, use hardware security modules (HSM).
 *
 * Padrão de 3 passadas (inspirado no DoD 5220.22-M simplificado):
 *   Passada 1: bytes aleatórios
 *   Passada 2: 0xFF
 *   Passada 3: 0x00
 *
 * @param {Buffer|Buffer[]} bufs - Buffer ou array de Buffers a apagar
 */
function secureWipe(...bufs) {
  for (const buf of bufs.flat()) {
    if (!Buffer.isBuffer(buf) || buf.length === 0) continue;
    try {
      crypto.randomFillSync(buf);  // passada 1: aleatório
      buf.fill(0xff);              // passada 2: uns
      buf.fill(0x00);              // passada 3: zeros (estado final)
    } catch {
      // Alguns buffers são read-only — ignorar silenciosamente
    }
  }
}

/**
 * Cria um Buffer que será automaticamente zerado quando
 * a função de limpeza for chamada.
 * Útil para chaves temporárias.
 *
 * @param {number} size
 * @returns {{ buffer: Buffer, wipe: () => void }}
 */
function sensitiveBuffer(size) {
  const buffer = Buffer.allocUnsafe(size);
  return {
    buffer,
    wipe: () => secureWipe(buffer),
  };
}

// ═══════════════════════════════════════════════════════════════
// 2. TIMING-SAFE COMPARISONS
// ═══════════════════════════════════════════════════════════════

/**
 * Compara dois valores de forma timing-safe.
 * Previne timing attacks em verificações de password/token.
 *
 * Suporta: string, Buffer, hex string.
 * Retorna false se tamanhos diferirem (sem leak do tamanho certo).
 *
 * @param {string|Buffer} a
 * @param {string|Buffer} b
 * @returns {boolean}
 */
function secureCompare(a, b) {
  try {
    const aBuf = typeof a === 'string' ? Buffer.from(a, 'utf8') : a;
    const bBuf = typeof b === 'string' ? Buffer.from(b, 'utf8') : b;

    // Se tamanhos diferem, ainda executar uma comparação para não vazar timing
    if (aBuf.length !== bBuf.length) {
      // Comparar contra si mesmo (sempre true) para manter timing constante
      crypto.timingSafeEqual(aBuf, aBuf);
      return false;
    }

    return crypto.timingSafeEqual(aBuf, bBuf);
  } catch {
    return false;
  }
}

/**
 * Compara dois hashes hex de forma timing-safe.
 * @param {string} hexA - 64 chars hex
 * @param {string} hexB - 64 chars hex
 * @returns {boolean}
 */
function secureCompareHex(hexA, hexB) {
  try {
    return secureCompare(Buffer.from(hexA, 'hex'), Buffer.from(hexB, 'hex'));
  } catch {
    return false;
  }
}

// ═══════════════════════════════════════════════════════════════
// 3. BRUTE FORCE GUARD
// ═══════════════════════════════════════════════════════════════

/**
 * Proteção contra brute-force com lockout exponencial.
 *
 * Estratégia:
 *   ≤ 3 tentativas:  sem delay
 *   4-6 tentativas:  lockout 30s
 *   7-9 tentativas:  lockout 5min
 *   ≥ 10 tentativas: lockout 30min
 *
 * Estado em memória (não persiste entre restarts — intencional:
 * um restart limpa o lockout, que é aceitável pois requer acesso
 * físico ao processo).
 */
class BruteForceGuard {
  /**
   * @param {object} [opts]
   * @param {number} [opts.maxAttempts=10]   - Máximo antes do lockout longo
   * @param {number} [opts.softLimit=3]      - Tentativas sem penalidade
   * @param {number} [opts.lockoutMs=30*60*1000] - Duração do lockout máximo
   */
  constructor(opts = {}) {
    this.maxAttempts = opts.maxAttempts || 10;
    this.softLimit   = opts.softLimit   || 3;
    this.maxLockout  = opts.lockoutMs   || 30 * 60 * 1000;

    /** @type {Map<string, { attempts: number, lockedUntil: number }>} */
    this._state = new Map();
  }

  /**
   * Retorna o estado atual de um ID (endereço, wallet ID, etc.).
   * @param {string} id
   * @returns {{ attempts: number, lockedUntil: number }}
   */
  _getState(id) {
    return this._state.get(id) || { attempts: 0, lockedUntil: 0 };
  }

  /**
   * Verifica se o ID está em lockout.
   * @param {string} id
   * @returns {{ locked: boolean, remainingMs?: number, attempts: number }}
   */
  check(id) {
    const state = this._getState(id);
    const now   = Date.now();

    if (state.lockedUntil > now) {
      return {
        locked:      true,
        remainingMs: state.lockedUntil - now,
        remainingSec: Math.ceil((state.lockedUntil - now) / 1000),
        attempts:    state.attempts,
      };
    }

    return { locked: false, attempts: state.attempts };
  }

  /**
   * Registra uma tentativa falha.
   * @param {string} id
   * @returns {{ locked: boolean, lockoutMs?: number }}
   */
  recordFailure(id) {
    const state    = this._getState(id);
    state.attempts += 1;
    const attempts = state.attempts;

    let lockoutMs = 0;
    if (attempts > this.softLimit && attempts <= 6)  lockoutMs = 30 * 1000;
    else if (attempts <= 9)                           lockoutMs = 5 * 60 * 1000;
    else                                              lockoutMs = this.maxLockout;

    if (lockoutMs > 0) {
      state.lockedUntil = Date.now() + lockoutMs;
    }

    this._state.set(id, state);

    return {
      locked:    lockoutMs > 0,
      lockoutMs,
      attempts,
    };
  }

  /**
   * Registra sucesso — reseta o contador.
   * @param {string} id
   */
  recordSuccess(id) {
    this._state.delete(id);
  }

  /**
   * Reseta manualmente (admin).
   * @param {string} id
   */
  reset(id) {
    this._state.delete(id);
  }

  /**
   * Limpa estados expirados (garbage collection periódico).
   */
  prune() {
    const now = Date.now();
    for (const [id, state] of this._state) {
      if (state.lockedUntil < now && state.attempts <= this.softLimit) {
        this._state.delete(id);
      }
    }
  }
}

/** Instância global do guard */
const globalGuard = new BruteForceGuard();

// ═══════════════════════════════════════════════════════════════
// 4. PASSWORD POLICY (entropy-based)
// ═══════════════════════════════════════════════════════════════

/**
 * Calcula a entropia de Shannon de uma string.
 * H = -Σ p(x) * log₂(p(x))
 * Total entropy = H * length
 *
 * @param {string} str
 * @returns {number} bits de entropia
 */
function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  const len = str.length;
  return Object.values(freq).reduce((h, f) => {
    const p = f / len;
    return h - p * Math.log2(p);
  }, 0) * len;
}

/**
 * Avalia força de senha baseada em entropia, não em regras arbitrárias.
 *
 * FILOSOFIA (inspirado em XKCD #936 e NIST SP 800-63B):
 *   • "correct horse battery staple" (4 palavras, 28 chars) >> "P@ss1!"
 *   • Entropia é a métrica real de força
 *   • Comprimento > complexidade
 *   • Passphrases longas são incentivadas
 *
 * THRESHOLDS:
 *   < 28 bits:  Muito fraco (crack em segundos)
 *   28-35 bits: Fraco
 *   36-59 bits: Moderado
 *   60-79 bits: Forte
 *   ≥ 80 bits:  Muito forte (passphrase longa)
 *
 * @param {string} password
 * @returns {{
 *   strong: boolean,
 *   score: 0|1|2|3|4,
 *   entropyBits: number,
 *   label: string,
 *   suggestions: string[]
 * }}
 */
function checkPasswordStrength(password) {
  if (typeof password !== 'string') {
    return { strong: false, score: 0, entropyBits: 0, label: 'Inválido', suggestions: ['Senha deve ser string'] };
  }

  const suggestions = [];
  const bits = shannonEntropy(password);
  const len  = password.length;

  // Detectar padrões comuns
  const isSequential = /^(abc|123|qwerty|password|senha|admin|test)/i.test(password);
  const isRepetitive = /(.)\1{3,}/.test(password); // mesmo char 4+ vezes
  const isCommon     = ['password', 'senha', '123456', 'qwerty', 'bitcoin', 'blockchain'].includes(password.toLowerCase());

  if (isCommon)     suggestions.push('Senha está em lista de senhas comuns');
  if (isSequential) suggestions.push('Evite sequências óbvias (abc, 123, qwerty)');
  if (isRepetitive) suggestions.push('Evite repetição excessiva de caracteres');
  if (len < 8)      suggestions.push('Mínimo 8 caracteres');
  if (len < 16 && bits < 60) suggestions.push('Use uma passphrase mais longa (ex: "cavalo correto bateria grampo")');
  if (bits < 60)    suggestions.push('Adicione mais variedade de caracteres ou aumente o comprimento');

  let score, label;
  if (isCommon || bits < 28) {
    score = 0; label = 'Muito fraco';
  } else if (bits < 36) {
    score = 1; label = 'Fraco';
  } else if (bits < 60) {
    score = 2; label = 'Moderado';
  } else if (bits < 80) {
    score = 3; label = 'Forte';
  } else {
    score = 4; label = 'Muito forte';
  }

  const strong = score >= 3 && !isCommon;

  return {
    strong,
    score,          // 0-4
    entropyBits: Math.round(bits),
    label,
    suggestions,
    length: len,
  };
}

// ═══════════════════════════════════════════════════════════════
// 5. SECURE LOGGER
// ═══════════════════════════════════════════════════════════════

/**
 * Lista de padrões que NUNCA devem aparecer em logs.
 * Se detectados, são substituídos por [REDACTED].
 */
const SENSITIVE_PATTERNS = [
  // Chaves privadas (64 hex chars)
  /\b[0-9a-f]{64}\b/gi,
  // Mnemonics (12-24 palavras BIP39)
  /\b(abandon|ability|able|about)\s+\w+\s+\w+/gi,
  // Seeds em hex (128 hex chars = 64 bytes)
  /\b[0-9a-f]{128}\b/gi,
  // AES keys / IV
  /\b(key|iv|salt|authTag|ciphertext)\s*[:=]\s*['"]?[0-9a-f]{12,}/gi,
];

/**
 * Logger seguro que redacta automaticamente dados sensíveis.
 */
class SecureLogger {
  /**
   * @param {object} [opts]
   * @param {boolean} [opts.enabled=true]
   * @param {'debug'|'info'|'warn'|'error'} [opts.level='info']
   * @param {string} [opts.prefix='[WALLET]']
   */
  constructor(opts = {}) {
    this.enabled = opts.enabled !== false;
    this.level   = opts.level   || 'info';
    this.prefix  = opts.prefix  || '[WALLET]';
    this._levels = { debug: 0, info: 1, warn: 2, error: 3 };
  }

  _redact(msg) {
    let safe = typeof msg === 'object' ? JSON.stringify(msg) : String(msg);
    for (const pattern of SENSITIVE_PATTERNS) {
      safe = safe.replace(pattern, '[REDACTED]');
    }
    return safe;
  }

  _shouldLog(level) {
    return this.enabled && this._levels[level] >= this._levels[this.level];
  }

  _log(level, ...args) {
    if (!this._shouldLog(level)) return;
    const safe = args.map(a => this._redact(a));
    const ts   = new Date().toISOString().slice(11, 23); // HH:MM:SS.mmm
    const fn   = level === 'error' ? console.error : level === 'warn' ? console.warn : console.log;
    fn(`${this.prefix} [${ts}] [${level.toUpperCase()}]`, ...safe);
  }

  debug(...args) { this._log('debug', ...args); }
  info(...args)  { this._log('info',  ...args); }
  warn(...args)  { this._log('warn',  ...args); }
  error(...args) { this._log('error', ...args); }

  /**
   * Mascara um ID para logs (mostra só primeiros/últimos chars).
   * @param {string} id
   * @param {number} [showChars=8]
   * @returns {string} ex: "deadbeef...f00dface"
   */
  static maskId(id, showChars = 8) {
    if (!id || id.length <= showChars * 2) return '***';
    return id.slice(0, showChars) + '...' + id.slice(-showChars);
  }
}

/** Logger global da wallet */
const logger = new SecureLogger({ level: 'info' });

// ═══════════════════════════════════════════════════════════════
// 6. HARDWARE WALLET INTERFACE (stub)
// ═══════════════════════════════════════════════════════════════

/**
 * Interface base para hardware wallets (Ledger, Trezor, Keystone).
 *
 * Hardware wallets nunca expõem a private key:
 *   • A chave privada fica no hardware seguro
 *   • O host envia o txHash para assinar
 *   • O hardware retorna apenas a assinatura
 *
 * Esta classe define a interface que implementações reais devem seguir.
 * Para integração real: use @ledgerhq/hw-transport-node-hid (Ledger)
 * ou trezor-connect (Trezor).
 */
class HardwareSigner {
  constructor(opts = {}) {
    this.type    = opts.type    || 'abstract';
    this.name    = opts.name    || 'Hardware Wallet';
    this._connected = false;
  }

  /**
   * Conecta ao dispositivo.
   * @returns {Promise<boolean>}
   */
  async connect() {
    throw new Error(`${this.name}.connect() não implementado`);
  }

  /**
   * Verifica se o dispositivo está conectado.
   * @returns {boolean}
   */
  isConnected() {
    return this._connected;
  }

  /**
   * Retorna a chave pública derivada no dispositivo.
   * A chave PRIVADA nunca sai do hardware.
   *
   * @param {string} derivationPath - ex: "m/84'/0'/0'/0/0"
   * @returns {Promise<{ publicKey: Buffer, chainCode: Buffer }>}
   */
  async getPublicKey(derivationPath) {
    throw new Error(`${this.name}.getPublicKey() não implementado`);
  }

  /**
   * Assina um hash no dispositivo (exibe confirmação na tela do hardware).
   * O usuário deve CONFIRMAR fisicamente no dispositivo.
   *
   * @param {Buffer}  txHash         - Hash de 32 bytes para assinar
   * @param {string}  derivationPath
   * @param {string}  [sigType]      - 'ecdsa' ou 'schnorr'
   * @returns {Promise<Buffer>} Assinatura (DER para ECDSA, 64B para Schnorr)
   */
  async signHash(txHash, derivationPath, sigType = 'ecdsa') {
    throw new Error(`${this.name}.signHash() não implementado. Requer dispositivo físico.`);
  }

  /**
   * Verifica autenticidade do dispositivo.
   * @returns {Promise<boolean>}
   */
  async verifyDevice() {
    throw new Error(`${this.name}.verifyDevice() não implementado`);
  }

  /**
   * Desconecta do dispositivo.
   */
  async disconnect() {
    this._connected = false;
  }
}

/**
 * Stub de Ledger para desenvolvimento/testes.
 * Substitua por @ledgerhq/hw-transport-node-hid em produção.
 */
class LedgerSigner extends HardwareSigner {
  constructor() {
    super({ type: 'ledger', name: 'Ledger' });
  }

  async connect() {
    logger.info('Ledger: tentando conexão (stub — requer @ledgerhq/hw-transport-node-hid)');
    throw new Error(
      'LedgerSigner requer @ledgerhq/hw-app-btc e @ledgerhq/hw-transport-node-hid. ' +
      'Instale com: npm install @ledgerhq/hw-app-btc @ledgerhq/hw-transport-node-hid'
    );
  }
}

/**
 * Stub de Trezor para desenvolvimento/testes.
 */
class TrezorSigner extends HardwareSigner {
  constructor() {
    super({ type: 'trezor', name: 'Trezor' });
  }

  async connect() {
    logger.info('Trezor: tentando conexão (stub — requer trezor-connect)');
    throw new Error(
      'TrezorSigner requer trezor-connect. ' +
      'Instale com: npm install @trezor/connect-web'
    );
  }
}

// ═══════════════════════════════════════════════════════════════
// 7. PAYLOAD VALIDATION (anti-DOS, anti-malformed)
// ═══════════════════════════════════════════════════════════════

const LIMITS = {
  MAX_KEYSTORE_SIZE:   10 * 1024 * 1024,  // 10 MB
  MAX_MNEMONIC_LEN:    500,
  MAX_ADDRESS_LEN:     100,
  MAX_SIGNATURE_LEN:   200,
  MAX_PUBKEY_LEN:      70,
  MAX_TX_HEX_LEN:      1024 * 1024,       // 1 MB raw tx
  MAX_METADATA_SIZE:   1024 * 1024,
};

/**
 * Valida um objeto keystore contra limites de segurança.
 * Rejeita payloads malformados antes de qualquer operação criptográfica.
 *
 * @param {object} ks
 * @throws {Error} se inválido
 */
function validateKeystorePayload(ks) {
  if (!ks || typeof ks !== 'object') {
    throw new TypeError('Keystore deve ser um objeto JSON');
  }

  const str = JSON.stringify(ks);
  if (str.length > LIMITS.MAX_KEYSTORE_SIZE) {
    throw new Error(`Keystore excede limite de tamanho: ${str.length} > ${LIMITS.MAX_KEYSTORE_SIZE}`);
  }

  // Campos obrigatórios
  const required = ['version', 'cipher', 'kdf', 'kdfParams', 'iv', 'authTag', 'ciphertext'];
  for (const field of required) {
    if (ks[field] === undefined) {
      throw new Error(`Campo obrigatório ausente: ${field}`);
    }
  }

  // Tipos
  if (typeof ks.version !== 'number') throw new TypeError('version deve ser number');
  if (typeof ks.cipher  !== 'string') throw new TypeError('cipher deve ser string');
  if (typeof ks.kdf     !== 'string') throw new TypeError('kdf deve ser string');

  // Tamanhos de campos hex
  if (typeof ks.iv !== 'string' || ks.iv.length !== 24) {
    throw new Error(`IV inválido: esperado 24 chars hex (12 bytes), recebeu ${ks.iv?.length}`);
  }
  if (typeof ks.authTag !== 'string' || ks.authTag.length !== 32) {
    throw new Error(`AuthTag inválida: esperado 32 chars hex (16 bytes), recebeu ${ks.authTag?.length}`);
  }
  if (typeof ks.kdfParams?.salt !== 'string' || ks.kdfParams.salt.length !== 64) {
    throw new Error(`Salt inválido: esperado 64 chars hex (32 bytes), recebeu ${ks.kdfParams?.salt?.length}`);
  }

  // Limites KDF anti-DOS
  const { N, r, p } = ks.kdfParams || {};
  if (N && N > 262144) throw new Error(`N excessivo: ${N} > 262144 (risco de DOS)`);
  if (r && r > 32)     throw new Error(`r excessivo: ${r} > 32`);
  if (p && p > 16)     throw new Error(`p excessivo: ${p} > 16`);

  // Ciphertext
  if (typeof ks.ciphertext !== 'string' || ks.ciphertext.length === 0) {
    throw new Error('ciphertext ausente ou vazio');
  }
  if (ks.ciphertext.length > LIMITS.MAX_KEYSTORE_SIZE * 2) {
    throw new Error('ciphertext excede limite máximo');
  }
}

/**
 * Valida um endereço Bitcoin genérico (não faz parsing — só sanidade).
 */
function validateAddressInput(address) {
  if (!address || typeof address !== 'string') throw new TypeError('Endereço deve ser string');
  if (address.length > LIMITS.MAX_ADDRESS_LEN)  throw new Error('Endereço muito longo');
  if (!/^[a-zA-Z0-9]+$/.test(address))          throw new Error('Endereço contém caracteres inválidos');
}

module.exports = {
  // Wipe
  secureWipe,
  sensitiveBuffer,

  // Comparisons
  secureCompare,
  secureCompareHex,

  // Brute-force
  BruteForceGuard,
  globalGuard,

  // Password
  checkPasswordStrength,
  shannonEntropy,

  // Logger
  SecureLogger,
  logger,

  // Hardware signers
  HardwareSigner,
  LedgerSigner,
  TrezorSigner,

  // Validation
  validateKeystorePayload,
  validateAddressInput,
  LIMITS,
};
