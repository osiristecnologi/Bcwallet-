/**
 * wallet/HDWallet.js
 * ═══════════════════════════════════════════════════════════════
 * HD Wallet principal — orquestra BIP39, BIP32, BIP44, keystore.
 *
 * ARQUITETURA:
 *
 *   HDWallet
 *     ├── _encryptedKeystore  (AES-256-GCM + scrypt — nunca em texto puro)
 *     ├── _masterNode         (HDNode — só em memória quando desbloqueado)
 *     ├── accounts[]          (Account — derivados do master)
 *     └── chains{}            (ChainAdapter — adaptadores por rede)
 *
 *   Account
 *     ├── index               (BIP44 account index)
 *     ├── label               (nome legível)
 *     └── addresses[]         (derivados do account)
 *
 * CICLO DE VIDA:
 *   1. HDWallet.create(password)     → nova wallet com mnemonic 24 palavras
 *   2. HDWallet.fromMnemonic(m, pw)  → importar mnemonic existente
 *   3. HDWallet.fromKeystore(ks, pw) → restaurar de backup criptografado
 *   4. wallet.lock()                 → apagar seed da memória
 *   5. wallet.unlock(pw)             → descriptografar e carregar seed
 *
 * SEGURANÇA:
 *   • Seed nunca em disco sem criptografia
 *   • Master node apagado ao chamar lock()
 *   • Private keys não enumeráveis nas estruturas
 *   • Auto-lock após inatividade (configurável)
 *   • Mnemonic exibido APENAS no momento da criação
 *
 * Futuro:
 *   - BIP85 (derivar mnemonics filho a partir de master)
 *   - SLIP39 Shamir's Secret Sharing
 *   - Hardware wallet bridge (Ledger/Trezor)
 *   - Multi-sig accounts
 * ═══════════════════════════════════════════════════════════════
 */

'use strict';

const crypto  = require('crypto');

const bip39      = require('./bip39/index');
const bip32      = require('./bip32');
const keystore   = require('./keystore');
const mineChain  = require('./chains/mine');
const ethChain   = require('./chains/ethereum');
const btcChains  = require('./chains/bitcoin');
const solChain   = require('./chains/solana');
const { sign, verify, nonceTracker } = require('../utils/crypto');

// ─── Registro de chains ─────────────────────────────────────
const CHAINS = {
  BC:   mineChain,
  ETH:  ethChain,
  BTC:  btcChains.bitcoin,
  LTC:  btcChains.litecoin,
  DOGE: btcChains.dogecoin,
  SOL:  solChain,
};

// ─── Auto-lock padrão: 30 minutos ───────────────────────────
const DEFAULT_AUTO_LOCK_MS = 30 * 60 * 1000;

// ─── Challenge TTL: 5 minutos ────────────────────────────────
const CHALLENGE_TTL_MS = 5 * 60 * 1000;

// ════════════════════════════════════════════════════════════════
// ACCOUNT
// ════════════════════════════════════════════════════════════════

class Account {
  /**
   * @param {object} params
   * @param {number} params.accountIndex  - BIP44 account (0, 1, 2...)
   * @param {string} params.label         - Nome legível
   * @param {object} params.chainAdapters - { BC, ETH, ... }
   */
  constructor({ accountIndex, label, chainAdapters }) {
    this.index    = accountIndex;
    this.label    = label || `Account ${accountIndex}`;
    this._chains  = chainAdapters;

    /** Cache de endereços gerados: chainSymbol → { index → address } */
    this._addressCache = {};
  }

  /**
   * Retorna o endereço de índice `i` para a chain especificada.
   * O HDNode correspondente deve ser fornecido (do master node).
   *
   * @param {string} chainSymbol  - 'BC', 'ETH', 'BTC', etc.
   * @param {number} [index=0]    - Address index
   * @param {HDNode} accountNode  - Nó derivado m/44'/coinType'/accountIndex'
   * @returns {{ address: string, publicKey: string, path: string }}
   */
  getAddressInfo(chainSymbol, index = 0, accountNode) {
    const chain = this._chains[chainSymbol];
    if (!chain) throw new Error(`Chain não suportada: ${chainSymbol}`);

    // Derivar m/.../0/index (change=0, external)
    const addrNode = accountNode.derive(0).derive(index);
    const address  = chain.getAddress(addrNode.publicKey);
    const path     = chain.derivationPath(this.index, 0, index);

    return { address, publicKey: addrNode.publicKeyHex, path };
  }

  toJSON() {
    return {
      index: this.index,
      label: this.label,
    };
  }
}

// ════════════════════════════════════════════════════════════════
// HDWALLET
// ════════════════════════════════════════════════════════════════

class HDWallet {
  /**
   * Construtor interno — use os factory methods estáticos.
   */
  constructor() {
    /** Keystore criptografado (salvo em disco) */
    this._keystore         = null;

    /** Master HDNode — só em memória quando desbloqueado */
    this._masterNode       = null;

    /** Seed — apagado após derivar master node */
    this._seedBuffer       = null;

    /** Mnemonic — disponível apenas no momento da criação */
    this._mnemonic         = null;

    /** Contas criadas */
    this.accounts          = [];

    /** Labels e metadata */
    this.label             = null;
    this.createdAt         = null;
    this.id                = null;

    /** Chain adapters */
    this.chains            = CHAINS;

    /** Auto-lock timer */
    this._autoLockTimer    = null;
    this.autoLockMs        = DEFAULT_AUTO_LOCK_MS;

    /** Challenges pendentes: nonce → { address, expires } */
    this._challenges       = new Map();

    /** Flag */
    this._locked           = true;
  }

  // ═══════════════════════════════════════════════════════════
  // FACTORY METHODS
  // ═══════════════════════════════════════════════════════════

  /**
   * Cria uma nova HD wallet com mnemonic de 24 palavras.
   *
   * ⚠️ O mnemonic é retornado APENAS aqui.
   * Após este ponto, só pode ser acessado via decryptSeed + passphrase.
   *
   * @param {string} password     - Senha para criptografar o keystore
   * @param {object} [opts]
   * @param {string} [opts.label] - Nome da wallet
   * @param {string} [opts.passphrase=''] - BIP39 passphrase (extra proteção)
   * @param {boolean} [opts.fast=false]   - KDF rápido (só testes)
   * @returns {{ wallet: HDWallet, mnemonic: string }}
   */
  static create(password, opts = {}) {
    const { label = 'My Wallet', passphrase = '', fast = false } = opts;

    // Verificar força da senha
    const pwCheck = keystore.checkPasswordStrength(password);
    if (!pwCheck.strong && !fast) {
      console.warn(
        `[HDWallet] Senha fraca (score: ${pwCheck.score}/8). ` +
        `Problemas: ${pwCheck.issues.join(', ')}`
      );
    }

    // Gerar mnemonic BIP39 de 24 palavras
    const mnemonic = bip39.generateMnemonic(256);
    const seed     = bip39.mnemonicToSeed(mnemonic, passphrase);

    const wallet = new HDWallet();
    wallet.label     = label;
    wallet.createdAt = Date.now();
    wallet.id        = crypto.randomBytes(16).toString('hex');

    // Criptografar seed
    wallet._keystore = keystore.encryptSeed(seed, password, {
      label,
      passphrase: passphrase ? '(definida)' : '(nenhuma)',
      createdAt:  wallet.createdAt,
      id:         wallet.id,
    }, { fast });

    // Carregar master node em memória
    wallet._loadMasterFromSeed(seed, passphrase);

    // Criar conta padrão
    wallet._addAccount(0, 'Account 0');

    // Limpar seed da memória após derivar master
    seed.fill(0);

    // Mnemonic disponível APENAS durante a criação
    // Será apagado da propriedade após retorno
    wallet._mnemonic = mnemonic;

    console.log('\n  🔑 Nova HD Wallet criada!');
    console.log(`  ID: ${wallet.id}`);
    console.log(`  ⚠️  SALVE O MNEMONIC AGORA — não será exibido novamente!\n`);

    return { wallet, mnemonic };
  }

  /**
   * Importa uma wallet a partir de um mnemonic existente.
   *
   * @param {string} mnemonic
   * @param {string} password
   * @param {object} [opts]
   * @returns {HDWallet}
   */
  static fromMnemonic(mnemonic, password, opts = {}) {
    const { passphrase = '', label = 'Imported Wallet', fast = false } = opts;

    const validation = bip39.validateMnemonic(mnemonic);
    if (!validation.valid) {
      throw new Error(`Mnemonic inválido: ${validation.error}`);
    }

    const seed   = bip39.mnemonicToSeed(mnemonic, passphrase);
    const wallet = new HDWallet();
    wallet.label     = label;
    wallet.createdAt = Date.now();
    wallet.id        = crypto.randomBytes(16).toString('hex');

    wallet._keystore = keystore.encryptSeed(seed, password, {
      label, passphrase: passphrase ? '(definida)' : '(nenhuma)',
      createdAt: wallet.createdAt, id: wallet.id,
    }, { fast });

    wallet._loadMasterFromSeed(seed, passphrase);
    wallet._addAccount(0, 'Account 0');
    seed.fill(0);

    return wallet;
  }

  /**
   * Restaura uma wallet de um keystore criptografado.
   * A wallet começa BLOQUEADA — chame wallet.unlock(password) para usar.
   *
   * @param {object} keystoreObj
   * @returns {HDWallet}
   */
  static fromKeystore(keystoreObj) {
    const wallet      = new HDWallet();
    wallet._keystore  = keystoreObj;
    wallet.label      = keystoreObj.metadata?.label || 'Restored Wallet';
    wallet.createdAt  = keystoreObj.metadata?.createdAt || Date.now();
    wallet.id         = keystoreObj.metadata?.id || crypto.randomBytes(16).toString('hex');
    wallet._locked    = true;
    return wallet;
  }

  // ═══════════════════════════════════════════════════════════
  // LOCK / UNLOCK
  // ═══════════════════════════════════════════════════════════

  /**
   * Desbloqueia a wallet descriptografando o seed.
   * Carrega o master node em memória.
   *
   * @param {string} password
   * @returns {boolean} true se desbloqueado com sucesso
   */
  unlock(password) {
    if (!this._locked) return true;
    if (!this._keystore) throw new Error('Nenhum keystore disponível');

    let seed, metadata;
    try {
      ({ seed, metadata } = keystore.decryptSeed(this._keystore, password));
    } catch (e) {
      throw new Error(`Falha ao desbloquear: ${e.message}`);
    }

    const passphrase = ''; // Passphrase BIP39 não é armazenada — deve ser fornecida separadamente
    this._loadMasterFromSeed(seed, passphrase);
    seed.fill(0);

    this._locked = false;
    this._resetAutoLock();

    console.log(`  🔓 Wallet desbloqueada: ${this.label || this.id}`);
    return true;
  }

  /**
   * Bloqueia a wallet apagando chaves da memória.
   * Após lock(), derivações não são possíveis sem unlock().
   */
  lock() {
    this.wipeSensitiveData();
    this._locked = true;
    this._clearAutoLock();
    console.log(`  🔒 Wallet bloqueada: ${this.label || this.id}`);
  }

  /**
   * Apaga dados sensíveis da memória (best-effort).
   * Node.js não garante GC imediato, mas preenchemos os buffers.
   */
  wipeSensitiveData() {
    if (this._masterNode?.privateKey) {
      this._masterNode.privateKey.fill(0);
    }
    if (this._masterNode?.chainCode) {
      this._masterNode.chainCode.fill(0);
    }
    this._masterNode = null;
    if (this._seedBuffer) {
      this._seedBuffer.fill(0);
      this._seedBuffer = null;
    }
    this._mnemonic = null;
  }

  get isLocked() {
    return this._locked;
  }

  // ═══════════════════════════════════════════════════════════
  // ACCOUNT MANAGEMENT
  // ═══════════════════════════════════════════════════════════

  /**
   * Cria uma nova conta BIP44.
   *
   * @param {string} [label]
   * @returns {Account}
   */
  createAccount(label) {
    this._requireUnlocked();
    const index = this.accounts.length;
    return this._addAccount(index, label || `Account ${index}`);
  }

  /**
   * Lista todas as contas.
   * @returns {Account[]}
   */
  listAccounts() {
    return this.accounts.map(a => a.toJSON());
  }

  /**
   * Renomeia uma conta.
   * @param {number} accountIndex
   * @param {string} newLabel
   */
  renameAccount(accountIndex, newLabel) {
    const account = this.accounts[accountIndex];
    if (!account) throw new Error(`Conta ${accountIndex} não encontrada`);
    account.label = newLabel;
  }

  /**
   * Retorna informações de endereço para uma conta+chain+índice.
   *
   * @param {string} chainSymbol  - 'BC', 'ETH', 'BTC', etc.
   * @param {number} [accountIdx=0]
   * @param {number} [addressIdx=0]
   * @returns {{ address, publicKey, path, chain }}
   */
  getAddress(chainSymbol, accountIdx = 0, addressIdx = 0) {
    this._requireUnlocked();

    const chain   = this.chains[chainSymbol];
    if (!chain)   throw new Error(`Chain não suportada: ${chainSymbol}. Disponíveis: ${Object.keys(this.chains).join(', ')}`);

    const account = this.accounts[accountIdx];
    if (!account) throw new Error(`Conta ${accountIdx} não encontrada`);

    const path        = chain.derivationPath(accountIdx, 0, addressIdx);
    const accountNode = this._masterNode.derivePath(`m/44'/${chain.coinType}'/${accountIdx}'`);
    const addrNode    = accountNode.derive(0).derive(addressIdx);

    const address     = chain.getAddress(addrNode.publicKey);

    this._resetAutoLock();

    return {
      address,
      publicKey: addrNode.publicKeyHex,
      path,
      chain:     chainSymbol,
      account:   account.label,
    };
  }

  /**
   * Retorna múltiplos endereços consecutivos para uma chain.
   *
   * @param {string} chainSymbol
   * @param {number} [count=5]
   * @param {number} [accountIdx=0]
   * @param {number} [startIdx=0]
   * @returns {Array}
   */
  getAddresses(chainSymbol, count = 5, accountIdx = 0, startIdx = 0) {
    this._requireUnlocked();
    const results = [];
    for (let i = startIdx; i < startIdx + count; i++) {
      results.push(this.getAddress(chainSymbol, accountIdx, i));
    }
    return results;
  }

  // ═══════════════════════════════════════════════════════════
  // SIGNING
  // ═══════════════════════════════════════════════════════════

  /**
   * Assina uma transação para a chain especificada.
   * Deriva a chave privada inline — nunca exposta fora deste método.
   *
   * @param {object} tx          - Dados da transação
   * @param {string} chainSymbol - 'BC', 'ETH', etc.
   * @param {number} [accountIdx=0]
   * @param {number} [addressIdx=0]
   * @returns {{ signature: string, publicKey: string, payload: string }}
   */
  signTransaction(tx, chainSymbol, accountIdx = 0, addressIdx = 0) {
    this._requireUnlocked();

    const chain   = this.chains[chainSymbol];
    if (!chain)   throw new Error(`Chain não suportada: ${chainSymbol}`);

    // Derivar nó do endereço
    const addrNode = this._masterNode
      .derivePath(`m/44'/${chain.coinType}'/${accountIdx}'`)
      .derive(0)
      .derive(addressIdx);

    // Calcular payload canônico com chainId
    const payload   = chain.signingPayload(tx);

    // Assinar — privKey usada inline, nunca retornada
    const signature = sign(payload, addrNode.privateKeyHex);

    this._resetAutoLock();

    return {
      signature,
      publicKey: addrNode.publicKeyHex,
      payload,
      chainId:   chain.chainId,
    };
  }

  /**
   * Verifica uma assinatura sem precisar de private key.
   */
  verifySignature(payload, signature, publicKey) {
    return verify(payload, signature, publicKey);
  }

  // ═══════════════════════════════════════════════════════════
  // CHALLENGE AUTH (login via assinatura)
  // ═══════════════════════════════════════════════════════════

  /**
   * Gera um challenge para autenticação sem senha.
   * O usuário assina o challenge com sua wallet para provar identidade.
   *
   * @param {string} address   - Endereço que está autenticando
   * @param {string} [context] - Contexto (nome do app, URL, etc.)
   * @returns {{ nonce: string, challenge: string, expires: number }}
   */
  createChallenge(address, context = '') {
    // Purge challenges expirados
    this._cleanExpiredChallenges();

    const nonce     = crypto.randomBytes(32).toString('hex');
    const expires   = Date.now() + CHALLENGE_TTL_MS;
    const challenge = [
      'SIGN_CHALLENGE',
      address,
      nonce,
      expires.toString(),
      context,
    ].join(':');

    this._challenges.set(nonce, { address, expires, context });

    return {
      nonce,
      challenge,
      expires,
      expiresIn: CHALLENGE_TTL_MS / 1000 + 's',
    };
  }

  /**
   * Assina um challenge (prova de posse do endereço).
   *
   * @param {string} challenge   - String do challenge
   * @param {string} chainSymbol
   * @param {number} [accountIdx=0]
   * @param {number} [addressIdx=0]
   * @returns {{ signature: string, publicKey: string }}
   */
  signChallenge(challenge, chainSymbol = 'BC', accountIdx = 0, addressIdx = 0) {
    this._requireUnlocked();

    const chain    = this.chains[chainSymbol];
    const addrNode = this._masterNode
      .derivePath(`m/44'/${chain.coinType}'/${accountIdx}'`)
      .derive(0)
      .derive(addressIdx);

    const payload   = crypto.createHash('sha256')
      .update(`CHALLENGE:${challenge}`)
      .digest('hex');

    const signature = sign(payload, addrNode.privateKeyHex);

    this._resetAutoLock();
    return { signature, publicKey: addrNode.publicKeyHex };
  }

  /**
   * Verifica um challenge assinado.
   *
   * @param {string} nonce
   * @param {string} signature
   * @param {string} publicKey
   * @param {string} address
   * @returns {{ valid: boolean, error?: string }}
   */
  verifyChallenge(nonce, signature, publicKey, address) {
    const entry = this._challenges.get(nonce);

    if (!entry) {
      return { valid: false, error: 'Nonce não encontrado ou expirado' };
    }

    if (Date.now() > entry.expires) {
      this._challenges.delete(nonce);
      return { valid: false, error: 'Challenge expirado' };
    }

    if (entry.address !== address) {
      return { valid: false, error: 'Endereço não corresponde ao challenge' };
    }

    const challengeStr = [
      'SIGN_CHALLENGE', address, nonce, entry.expires.toString(), entry.context
    ].join(':');

    const payload = crypto.createHash('sha256')
      .update(`CHALLENGE:${challengeStr}`)
      .digest('hex');

    const sigValid = verify(payload, signature, publicKey);

    if (sigValid) {
      // Consumir nonce — anti-replay
      this._challenges.delete(nonce);
    }

    return sigValid
      ? { valid: true }
      : { valid: false, error: 'Assinatura inválida' };
  }

  // ═══════════════════════════════════════════════════════════
  // EXPORTAÇÃO SEGURA
  // ═══════════════════════════════════════════════════════════

  /**
   * Exporta apenas o keystore criptografado — seguro para backup.
   * NUNCA exporta seed, mnemonic ou private keys.
   *
   * @returns {object} Keystore JSON-serializable
   */
  exportKeystore() {
    if (!this._keystore) throw new Error('Nenhum keystore para exportar');
    return {
      ...this._keystore,
      _warning: '⚠️ Mantenha este arquivo seguro. Protegido por senha.',
      walletId: this.id,
      label:    this.label,
    };
  }

  /**
   * Importa e restaura de um keystore exportado.
   * @param {object} ks
   * @returns {HDWallet} Wallet bloqueada
   */
  static importKeystore(ks) {
    return HDWallet.fromKeystore(ks);
  }

  /**
   * Retorna o xpub da conta para watch-only monitoring.
   * Seguro para compartilhar (sem private keys).
   *
   * @param {string} chainSymbol
   * @param {number} [accountIdx=0]
   * @returns {string} xpub Base58Check
   */
  getXpub(chainSymbol, accountIdx = 0) {
    this._requireUnlocked();
    const chain = this.chains[chainSymbol];
    if (!chain) throw new Error(`Chain não suportada: ${chainSymbol}`);

    const accountNode = this._masterNode
      .derivePath(`m/44'/${chain.coinType}'/${accountIdx}'`);

    this._resetAutoLock();
    return accountNode.toXpub();
  }

  // ═══════════════════════════════════════════════════════════
  // WATCH-ONLY
  // ═══════════════════════════════════════════════════════════

  /**
   * Cria uma wallet watch-only a partir de um xpub.
   * Não pode assinar — apenas gerar endereços e monitorar.
   *
   * @param {string} xpub
   * @param {string} chainSymbol
   * @returns {object} { getAddress, getAddresses }
   */
  static importWatchOnly(xpub, chainSymbol) {
    const { fromXpub } = bip32;
    const chain        = CHAINS[chainSymbol];
    if (!chain)        throw new Error(`Chain não suportada: ${chainSymbol}`);

    const accountNode = fromXpub(xpub);

    return {
      type:    'watch-only',
      chain:   chainSymbol,
      xpub,

      getAddress(addressIdx = 0, change = 0) {
        const addrNode = accountNode.derive(change).derive(addressIdx);
        return {
          address:   chain.getAddress(addrNode.publicKey),
          publicKey: addrNode.publicKeyHex,
          index:     addressIdx,
        };
      },

      getAddresses(count = 5, startIdx = 0) {
        const results = [];
        for (let i = startIdx; i < startIdx + count; i++) {
          results.push(this.getAddress(i));
        }
        return results;
      },
    };
  }

  // ═══════════════════════════════════════════════════════════
  // INFORMAÇÕES PÚBLICAS
  // ═══════════════════════════════════════════════════════════

  /**
   * Retorna informações não-sensíveis da wallet.
   */
  toPublicInfo() {
    return {
      id:          this.id,
      label:       this.label,
      createdAt:   this.createdAt,
      isLocked:    this._locked,
      accounts:    this.listAccounts(),
      chains:      Object.keys(this.chains),
      hasKeystore: !!this._keystore,
    };
  }

  toJSON() {
    return this.toPublicInfo();
  }

  // ═══════════════════════════════════════════════════════════
  // INTERNOS
  // ═══════════════════════════════════════════════════════════

  _requireUnlocked() {
    if (this._locked || !this._masterNode) {
      throw new Error('Wallet bloqueada. Chame wallet.unlock(password) primeiro.');
    }
  }

  _loadMasterFromSeed(seed) {
    this._masterNode = bip32.fromSeed(seed);
    this._locked     = false;
  }

  _addAccount(index, label) {
    const account = new Account({
      accountIndex:  index,
      label,
      chainAdapters: this.chains,
    });
    this.accounts[index] = account;
    return account;
  }

  _resetAutoLock() {
    this._clearAutoLock();
    if (this.autoLockMs > 0) {
      this._autoLockTimer = setTimeout(() => {
        console.log(`  ⏰ Auto-lock: wallet bloqueada por inatividade`);
        this.lock();
      }, this.autoLockMs);
    }
  }

  _clearAutoLock() {
    if (this._autoLockTimer) {
      clearTimeout(this._autoLockTimer);
      this._autoLockTimer = null;
    }
  }

  _cleanExpiredChallenges() {
    const now = Date.now();
    for (const [nonce, entry] of this._challenges) {
      if (now > entry.expires) this._challenges.delete(nonce);
    }
  }
}

module.exports = { HDWallet, Account, CHAINS };
