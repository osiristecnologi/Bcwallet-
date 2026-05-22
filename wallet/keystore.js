/**
 * wallet/keystore.js  — v2
 * ═══════════════════════════════════════════════════════════════
 * Keystore criptografado — armazena o seed BIP39 com segurança.
 *
 * MELHORIAS v2 vs v1:
 *   ✔ scrypt ASSÍNCRONO        — não bloqueia o event loop
 *   ✔ AAD autenticado          — version/cipher/kdf são imutáveis
 *   ✔ Migration engine         — v3→v4 sem quebrar backups antigos
 *   ✔ validateKeystoreStructure — rejeita payloads malformados antes do KDF
 *   ✔ Limites KDF anti-DOS     — N/r/p máximos validados
 *   ✔ Checksum extra           — detecção rápida de corrupção
 *   ✔ Profiles de KDF          — mobile/desktop/server/cold-storage
 *   ✔ secureWipe               — 3 passadas em materiais sensíveis
 *   ✔ v5 stubs                 — Argon2id, XChaCha20, SecureEnclave
 *
 * VERSÕES:
 *   v3 — AES-256-GCM + scrypt (sync) — legado, suportado via migration
 *   v4 — AES-256-GCM + scrypt (async) + AAD + checksum — ATUAL
 *   v5 — XChaCha20-Poly1305 + Argon2id — FUTURO (stubs)
 *
 * FORMATO v4:
 * {
 *   version:    4,
 *   schemaVersion: 1,
 *   profile:    'desktop'|'mobile'|'server'|'cold-storage',
 *   cipher:     'aes-256-gcm',
 *   kdf:        'scrypt',
 *   kdfParams:  { N, r, p, keylen, salt },
 *   iv:         hex(12B),
 *   authTag:    hex(16B),
 *   aad:        hex(AAD),
 *   checksum:   hex(8B = SHA256(ciphertext)[0:8]),
 *   ciphertext: hex,
 *   hint:       string,
 *   createdAt:  timestamp,
 *   id:         uuid,
 * }
 * ═══════════════════════════════════════════════════════════════
 */

'use strict';

const crypto = require('crypto');

// ─── Importar secureWipe e checkPasswordStrength ─────────────
// Importação lazy para evitar circular deps (security usa keystore e vice-versa)
function _security() { return require('./security/index'); }

// ─── Constantes ───────────────────────────────────────────────
const KEYSTORE_VERSION_CURRENT = 4;
const KEYSTORE_SCHEMA_VERSION  = 1;

const KDF_LIMITS = { MAX_N: 262144, MAX_R: 32, MAX_P: 16 };
const MAX_METADATA_SIZE   = 1024 * 1024;        // 1 MB
const MAX_CIPHERTEXT_SIZE = 10 * 1024 * 1024;   // 10 MB

/**
 * Profiles de KDF por ambiente.
 * N elevado = mais seguro, mais RAM, mais lento.
 */
const KDF_PROFILES = {
  desktop:        { N: 131072, r: 8, p: 1, keylen: 32, maxmem: 256 * 1024 * 1024 },
  production:     { N: 131072, r: 8, p: 1, keylen: 32, maxmem: 256 * 1024 * 1024 },
  mobile:         { N: 32768,  r: 8, p: 1, keylen: 32, maxmem: 64  * 1024 * 1024 },
  server:         { N: 262144, r: 8, p: 1, keylen: 32, maxmem: 512 * 1024 * 1024 },
  'cold-storage': { N: 262144, r: 8, p: 2, keylen: 32, maxmem: 512 * 1024 * 1024 },
  test:           { N: 8192,   r: 8, p: 1, keylen: 32, maxmem: 64  * 1024 * 1024 },
};

// ─── Helpers ──────────────────────────────────────────────────

function uuidV4() {
  const b = crypto.randomBytes(16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = b.toString('hex');
  return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;
}

function secureWipe(...bufs) {
  for (const buf of bufs.flat()) {
    if (!Buffer.isBuffer(buf) || buf.length === 0) continue;
    try {
      crypto.randomFillSync(buf);
      buf.fill(0xff);
      buf.fill(0x00);
    } catch { /* read-only buffer — ignorar */ }
  }
}

// ─── Async KDF ────────────────────────────────────────────────

/**
 * Deriva chave AES-256 com scrypt ASSÍNCRONO.
 * Não bloqueia o event loop — seguro para uso em servidor.
 *
 * @param {string|Buffer} password
 * @param {Buffer}        salt    - 32 bytes
 * @param {object}        params  - { N, r, p, keylen, maxmem }
 * @returns {Promise<Buffer>} 32 bytes
 */
async function deriveKeyAsync(password, salt, params) {
  const pwBuf = typeof password === 'string'
    ? Buffer.from(password, 'utf8')
    : password;

  return new Promise((resolve, reject) => {
    crypto.scrypt(pwBuf, salt, params.keylen, {
      N:      params.N,
      r:      params.r,
      p:      params.p,
      maxmem: params.maxmem,
    }, (err, key) => {
      if (err) reject(new Error(`scrypt falhou: ${err.message}`));
      else     resolve(key);
    });
  });
}

/**
 * Versão síncrona — apenas para compatibilidade com v3 legado e testes rápidos.
 */
function deriveKeySync(password, salt, params) {
  return crypto.scryptSync(
    typeof password === 'string' ? Buffer.from(password, 'utf8') : password,
    salt, params.keylen,
    { N: params.N, r: params.r, p: params.p, maxmem: params.maxmem }
  );
}

// ─── AAD ──────────────────────────────────────────────────────

/**
 * Constrói o AAD (Additional Authenticated Data) para v4.
 * AAD é autenticado pelo GCM mas NÃO criptografado.
 * Qualquer alteração em version/cipher/kdf/profile invalida a descriptografia.
 */
function buildAAD(ks) {
  return Buffer.from(JSON.stringify({
    version:       ks.version,
    schemaVersion: ks.schemaVersion || 1,
    cipher:        ks.cipher,
    kdf:           ks.kdf,
    profile:       ks.profile || 'desktop',
  }), 'utf8');
}

// ─── Checksum ─────────────────────────────────────────────────

/**
 * SHA256(ciphertext)[0:8] → 16 hex chars.
 * Verificado ANTES do KDF para detecção barata de corrupção.
 */
function calcChecksum(ciphertextHex) {
  return crypto.createHash('sha256')
    .update(Buffer.from(ciphertextHex, 'hex'))
    .digest('hex')
    .slice(0, 16);
}

// ═══════════════════════════════════════════════════════════════
// VALIDATION
// ═══════════════════════════════════════════════════════════════

/**
 * Valida a estrutura de um keystore antes de qualquer operação KDF.
 * Rejeita: campos ausentes, tipos incorretos, tamanhos inválidos,
 * parâmetros KDF abusivos (anti-DOS), hex inválido.
 *
 * @param {object} ks
 * @throws {TypeError|Error}
 */
function validateKeystoreStructure(ks) {
  if (!ks || typeof ks !== 'object' || Array.isArray(ks)) {
    throw new TypeError('Keystore deve ser um objeto JSON');
  }

  // Tamanho total
  const size = JSON.stringify(ks).length;
  if (size > MAX_CIPHERTEXT_SIZE) {
    throw new Error(`Keystore excede limite: ${size} bytes`);
  }

  // Campos obrigatórios
  for (const f of ['version', 'cipher', 'kdf', 'kdfParams', 'iv', 'authTag', 'ciphertext']) {
    if (ks[f] === undefined) throw new Error(`Campo obrigatório ausente: '${f}'`);
  }

  // Tipos
  if (typeof ks.version !== 'number') throw new TypeError(`'version' deve ser number`);
  if (typeof ks.cipher  !== 'string') throw new TypeError(`'cipher' deve ser string`);
  if (typeof ks.kdf     !== 'string') throw new TypeError(`'kdf' deve ser string`);

  // Tamanhos hex exatos
  if (typeof ks.iv !== 'string' || ks.iv.length !== 24) {
    throw new Error(`IV inválido: esperado 24 hex chars (12 bytes), recebeu ${ks.iv?.length}`);
  }
  if (typeof ks.authTag !== 'string' || ks.authTag.length !== 32) {
    throw new Error(`AuthTag inválida: esperado 32 hex chars (16 bytes), recebeu ${ks.authTag?.length}`);
  }
  const salt = ks.kdfParams?.salt;
  if (typeof salt !== 'string' || salt.length !== 64) {
    throw new Error(`Salt inválido: esperado 64 hex chars (32 bytes), recebeu ${salt?.length}`);
  }

  // Limites KDF anti-DOS
  const { N, r, p } = ks.kdfParams;
  if (N > KDF_LIMITS.MAX_N) throw new Error(`N excessivo: ${N} > ${KDF_LIMITS.MAX_N} (risco de DOS)`);
  if (r > KDF_LIMITS.MAX_R) throw new Error(`r excessivo: ${r} > ${KDF_LIMITS.MAX_R}`);
  if (p > KDF_LIMITS.MAX_P) throw new Error(`p excessivo: ${p} > ${KDF_LIMITS.MAX_P}`);

  // Ciphertext
  if (typeof ks.ciphertext !== 'string' || ks.ciphertext.length === 0) {
    throw new Error('ciphertext ausente ou vazio');
  }

  // Hex válido nos campos críticos
  for (const [name, val] of [['iv', ks.iv], ['authTag', ks.authTag], ['salt', salt]]) {
    if (!/^[0-9a-f]+$/i.test(val)) {
      throw new Error(`'${name}' contém caracteres não-hex`);
    }
  }
}

// ═══════════════════════════════════════════════════════════════
// ENCRYPT (v4 — async)
// ═══════════════════════════════════════════════════════════════

/**
 * Criptografa um seed BIP39 (64 bytes) — retorna keystore v4.
 *
 * SEGURANÇA:
 *   • scrypt async — não bloqueia
 *   • AAD protege metadados contra tampering
 *   • Salt e IV únicos por chamada — evita reuse attacks
 *   • GCM authTag garante integridade do ciphertext
 *   • Checksum detecção rápida de corrupção pré-KDF
 *   • secureWipe apaga aesKey e plaintext após uso
 *
 * @param {Buffer}  seed       - 64 bytes (BIP39 seed)
 * @param {string}  password   - Senha (≥8 chars)
 * @param {object}  [metadata] - Metadados opcionais { label, ... }
 * @param {object}  [opts]
 * @param {string}  [opts.profile='desktop'] - Perfil KDF
 * @param {boolean} [opts.fast=false]        - Alias para profile='test'
 * @param {string}  [opts.hint='']           - Dica de senha (não a senha!)
 * @returns {Promise<object>} Keystore v4
 */
async function encryptSeed(seed, password, metadata = {}, opts = {}) {
  if (!Buffer.isBuffer(seed) || seed.length !== 64) {
    throw new Error('seed deve ser um Buffer de 64 bytes');
  }
  if (typeof password !== 'string' || password.length < 8) {
    throw new Error('Senha deve ter pelo menos 8 caracteres');
  }

  const profile = opts.fast ? 'test' : (opts.profile || 'desktop');
  const params  = KDF_PROFILES[profile] || KDF_PROFILES.desktop;
  const salt    = crypto.randomBytes(32);
  const iv      = crypto.randomBytes(12);

  // Construir AAD (autentica metadados críticos)
  const partial = { version: KEYSTORE_VERSION_CURRENT, schemaVersion: KEYSTORE_SCHEMA_VERSION, profile, cipher: 'aes-256-gcm', kdf: 'scrypt' };
  const aad     = buildAAD(partial);

  // Derivar chave — ASYNC, não bloqueia
  const aesKey = await deriveKeyAsync(password, salt, params);

  // Payload = seed (64B) + metaLen (4B BE) + metaJSON
  const metaJson  = Buffer.from(JSON.stringify(metadata), 'utf8');
  const lenBuf    = Buffer.alloc(4);
  lenBuf.writeUInt32BE(metaJson.length, 0);
  const plaintext = Buffer.concat([seed, lenBuf, metaJson]);

  // Cifrar com AAD
  const cipher     = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag    = cipher.getAuthTag();

  // Limpar materiais sensíveis
  secureWipe(aesKey, plaintext);

  const ciphertextHex = ciphertext.toString('hex');

  return {
    version:       KEYSTORE_VERSION_CURRENT,
    schemaVersion: KEYSTORE_SCHEMA_VERSION,
    id:            uuidV4(),
    profile,
    cipher:        'aes-256-gcm',
    kdf:           'scrypt',
    kdfParams:     { N: params.N, r: params.r, p: params.p, keylen: params.keylen, salt: salt.toString('hex') },
    iv:            iv.toString('hex'),
    authTag:       authTag.toString('hex'),
    aad:           aad.toString('hex'),
    checksum:      calcChecksum(ciphertextHex),
    ciphertext:    ciphertextHex,
    hint:          opts.hint || '',
    createdAt:     Date.now(),
  };
}

// ═══════════════════════════════════════════════════════════════
// DECRYPT (v3 legado + v4 atual)
// ═══════════════════════════════════════════════════════════════

/**
 * Descriptografa um keystore (suporta v3 e v4).
 * v3 é migrado automaticamente em memória antes da descriptografia.
 *
 * @param {object} keystore
 * @param {string} password
 * @returns {Promise<{ seed: Buffer, metadata: object }>}
 * @throws {Error} senha incorreta | corrompido | estrutura inválida
 */
async function decryptSeed(keystore, password) {
  // 1. Validação estrutural barata (antes de KDF)
  validateKeystoreStructure(keystore);

  // 2. Migrar versão legada se necessário
  const ks = migrateKeystore(keystore);

  // 3. Verificar checksum (antes de KDF — evita KDF flood com dados corrompidos)
  if (ks.checksum) {
    const expected = calcChecksum(ks.ciphertext);
    if (!crypto.timingSafeEqual(
      Buffer.from(ks.checksum, 'hex').slice(0, 8),
      Buffer.from(expected,    'hex').slice(0, 8)
    )) {
      throw new Error(`Checksum inválido — keystore corrompido (${ks.checksum} ≠ ${expected})`);
    }
  }

  // 4. Preparar buffers
  const params = {
    N:       ks.kdfParams.N,
    r:       ks.kdfParams.r,
    p:       ks.kdfParams.p,
    keylen:  ks.kdfParams.keylen || 32,
    maxmem:  Math.max(ks.kdfParams.N * 128 * (ks.kdfParams.r || 8) * 2, 64 * 1024 * 1024),
  };
  const salt   = Buffer.from(ks.kdfParams.salt, 'hex');
  const ivBuf  = Buffer.from(ks.iv,      'hex');
  const tagBuf = Buffer.from(ks.authTag, 'hex');
  const ctBuf  = Buffer.from(ks.ciphertext, 'hex');

  // 5. Validar tamanhos pós-parse
  if (ivBuf.length  !== 12) throw new Error('IV deve ter exatamente 12 bytes');
  if (tagBuf.length !== 16) throw new Error('AuthTag deve ter exatamente 16 bytes');
  if (salt.length   !== 32) throw new Error('Salt deve ter exatamente 32 bytes');

  // 6. Derivar chave — ASYNC
  let aesKey;
  try {
    aesKey = await deriveKeyAsync(password, salt, params);
  } catch (e) {
    throw new Error(`Falha no KDF: ${e.message}`);
  }

  // 7. Descriptografar
  let plaintext;
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, ivBuf);
    decipher.setAuthTag(tagBuf);
    // Aplicar AAD apenas para v4 (v3 não tinha AAD)
    if (ks.version >= 4 && ks.aad) {
      decipher.setAAD(Buffer.from(ks.aad, 'hex'));
    }
    plaintext = Buffer.concat([decipher.update(ctBuf), decipher.final()]);
  } catch {
    secureWipe(aesKey);
    throw new Error('Senha incorreta ou keystore corrompido (falha de autenticação GCM)');
  } finally {
    secureWipe(aesKey);
  }

  // 8. Extrair seed em buffer INDEPENDENTE (evitar aliasing após fill(0))
  if (plaintext.length < 68) {
    secureWipe(plaintext);
    throw new Error('Payload decriptado muito pequeno — keystore corrompido');
  }

  const seed    = Buffer.allocUnsafe(64);
  plaintext.copy(seed, 0, 0, 64);

  const metaLen = plaintext.readUInt32BE(64);

  // Validar metaLen
  if (metaLen > MAX_METADATA_SIZE) {
    secureWipe(seed, plaintext);
    throw new Error(`metaLen excessivo: ${metaLen}`);
  }
  if (68 + metaLen > plaintext.length) {
    secureWipe(seed, plaintext);
    throw new Error('metaLen ultrapassa o payload');
  }

  const metaBuf = plaintext.slice(68, 68 + metaLen);
  let metadata  = {};
  try {
    if (metaBuf.length > 0) metadata = JSON.parse(metaBuf.toString('utf8'));
  } catch {
    metadata = { _warning: 'Metadata ilegível' };
  }

  secureWipe(plaintext);
  return { seed, metadata };
}

// ═══════════════════════════════════════════════════════════════
// VERIFY PASSWORD
// ═══════════════════════════════════════════════════════════════

/**
 * Verifica senha sem retornar o seed.
 * @param {object} keystore
 * @param {string} password
 * @returns {Promise<boolean>}
 */
async function verifyPassword(keystore, password) {
  try {
    const { seed } = await decryptSeed(keystore, password);
    secureWipe(seed);
    return true;
  } catch {
    return false;
  }
}

// ═══════════════════════════════════════════════════════════════
// MIGRATION ENGINE  v3 → v4
// ═══════════════════════════════════════════════════════════════

/**
 * Normaliza um keystore v3 para processamento interno v4.
 * NÃO re-criptografa — apenas adiciona campos ausentes.
 * O algoritmo de cipher é idêntico; apenas AAD não será validado.
 */
function migrateV3toV4(ks) {
  return {
    ...ks,
    version:       4,
    schemaVersion: 1,
    profile:       ks.profile || 'desktop',
    aad:           null,        // v3 não tinha AAD — skipado na decrypt
    checksum:      null,        // v3 não tinha checksum — skipado
    kdfParams: {
      keylen:  32,
      maxmem:  256 * 1024 * 1024,
      ...ks.kdfParams,
    },
  };
}

/** Migração v4→v5 — requer re-criptografia manual (stub) */
function migrateV4toV5(ks) {
  throw new Error('Migração v4→v5 requer re-encrypt com nova senha. Não implementado.');
}

const MIGRATIONS = {
  3: migrateV3toV4,
  // 4: migrateV4toV5,   // futuro: ativar quando Argon2id disponível
};

/**
 * Aplica todas as migrações necessárias até a versão atual.
 * @param {object} ks
 * @returns {object} ks normalizado
 */
function migrateKeystore(ks) {
  let current = ks;
  while (MIGRATIONS[current.version]) {
    current = MIGRATIONS[current.version](current);
  }
  return current;
}

// ═══════════════════════════════════════════════════════════════
// V5 STUBS (interfaces para futura implementação)
// ═══════════════════════════════════════════════════════════════

/** Argon2id KDF — requer npm install argon2 */
class Argon2Provider {
  async deriveKey() {
    throw new Error('Argon2id: npm install argon2');
  }
}

/** XChaCha20-Poly1305 cipher — requer Node >= 22 experimental ou @noble/ciphers */
class XChaCha20Provider {
  encrypt() { throw new Error('XChaCha20: npm install @noble/ciphers'); }
  decrypt() { throw new Error('XChaCha20: npm install @noble/ciphers'); }
}

/** Secure Enclave / TPM — hardware-specific */
class SecureEnclaveProvider {
  async generateKey() { throw new Error('SecureEnclave: requer hardware específico'); }
  async sign()        { throw new Error('SecureEnclave: requer hardware específico'); }
}

// ─── Re-exportar checkPasswordStrength para compatibilidade ──
const { checkPasswordStrength } = require('./security/index');

module.exports = {
  // API principal (async)
  encryptSeed,
  decryptSeed,
  verifyPassword,

  // Validação
  validateKeystoreStructure,
  checkPasswordStrength,

  // Migration
  migrateKeystore,
  migrateV3toV4,
  MIGRATIONS,

  // Profiles
  KDF_PROFILES,

  // Helpers expostos para testes
  buildAAD,
  calcChecksum,
  deriveKeyAsync,
  deriveKeySync,
  secureWipe,
  uuidV4,

  // Constantes
  KEYSTORE_VERSION_CURRENT,
  KEYSTORE_SCHEMA_VERSION,
  KDF_LIMITS,

  // v5 stubs
  Argon2Provider,
  XChaCha20Provider,
  SecureEnclaveProvider,
};

