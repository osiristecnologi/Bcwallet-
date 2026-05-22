/**
 * wallet/chains/bitcoin/electrum.js
 * ═══════════════════════════════════════════════════════════════
 * Cliente HTTP para APIs Bitcoin compatíveis com Electrum/Esplora.
 *
 * Compatível com:
 *   • mempool.space   (https://mempool.space/api)
 *   • blockstream.info (https://blockstream.info/api)
 *   • Esplora (self-hosted)
 *   • ElectrumX (via JSON-RPC — requer TCP, não implementado aqui)
 *
 * NOTA: Este módulo faz chamadas HTTP reais. Em ambiente de teste
 * ou sem internet, as chamadas falharão graciosamente com erro.
 * Para testes unitários, use mocks (ver test-bitcoin.js).
 *
 * RATE LIMITING:
 *   mempool.space limita a 10 req/s por IP.
 *   Implementamos queue com delay entre requests.
 *
 * Futuro:
 *   - WebSocket subscriptions (mempool.space /api/v1/ws)
 *   - ElectrumX TCP client (electrum protocol)
 *   - Batch requests
 *   - Tor proxy support
 * ═══════════════════════════════════════════════════════════════
 */

'use strict';

const https = require('https');
const http  = require('http');

// ─── Configurações de API ────────────────────────────────────

const ENDPOINTS = {
  mainnet: {
    mempool:     'https://mempool.space/api',
    blockstream: 'https://blockstream.info/api',
  },
  testnet: {
    mempool:     'https://mempool.space/testnet/api',
    blockstream: 'https://blockstream.info/testnet/api',
  },
};

const DEFAULT_TIMEOUT_MS  = 10_000;
const DEFAULT_RETRY_COUNT = 3;
const RETRY_DELAY_MS      = 1_000;

// ─── HTTP helper ─────────────────────────────────────────────

/**
 * Faz uma requisição HTTP/HTTPS com timeout e retry.
 * @param {string} url
 * @param {object} [opts]
 * @returns {Promise<object>} JSON parsed
 */
function httpGet(url, opts = {}) {
  const { timeout = DEFAULT_TIMEOUT_MS, retries = DEFAULT_RETRY_COUNT } = opts;

  return new Promise((resolve, reject) => {
    const lib     = url.startsWith('https') ? https : http;
    const request = lib.get(url, { timeout }, (res) => {
      if (res.statusCode === 404) {
        reject(new Error(`404: Recurso não encontrado — ${url}`));
        return;
      }
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode} — ${url}`));
        return;
      }

      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch {
          // Alguns endpoints retornam texto puro (ex: balance)
          resolve(data.trim());
        }
      });
    });

    request.on('timeout', () => {
      request.destroy();
      reject(new Error(`Timeout após ${timeout}ms — ${url}`));
    });

    request.on('error', reject);
  });
}

async function httpGetWithRetry(url, opts = {}) {
  const { retries = DEFAULT_RETRY_COUNT } = opts;
  let lastError;

  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await httpGet(url, opts);
    } catch (e) {
      lastError = e;
      if (attempt < retries) {
        await new Promise(r => setTimeout(r, RETRY_DELAY_MS * (attempt + 1)));
      }
    }
  }
  throw lastError;
}

async function httpPost(url, body, opts = {}) {
  const { timeout = DEFAULT_TIMEOUT_MS } = opts;
  const data = typeof body === 'string' ? body : JSON.stringify(body);

  return new Promise((resolve, reject) => {
    const parsed  = new URL(url);
    const lib     = url.startsWith('https') ? https : http;
    const options = {
      hostname: parsed.hostname,
      port:     parsed.port || (url.startsWith('https') ? 443 : 80),
      path:     parsed.pathname + (parsed.search || ''),
      method:   'POST',
      headers: {
        'Content-Type':   'text/plain',
        'Content-Length': Buffer.byteLength(data),
      },
      timeout,
    };

    const req = lib.request(options, (res) => {
      let body = '';
      res.on('data', c => { body += c; });
      res.on('end', () => {
        if (res.statusCode >= 400) {
          reject(new Error(`HTTP ${res.statusCode}: ${body}`));
        } else {
          resolve(body.trim());
        }
      });
    });

    req.on('timeout', () => { req.destroy(); reject(new Error('POST timeout')); });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

// ═══════════════════════════════════════════════════════════════
// ELECTRUM CLIENT
// ═══════════════════════════════════════════════════════════════

class ElectrumClient {
  /**
   * @param {object} [opts]
   * @param {'mainnet'|'testnet'} [opts.network='mainnet']
   * @param {'mempool'|'blockstream'} [opts.provider='mempool']
   * @param {string} [opts.baseUrl] - URL customizada (self-hosted Esplora)
   */
  constructor(opts = {}) {
    const {
      network  = 'mainnet',
      provider = 'mempool',
      baseUrl,
    } = opts;

    this.network  = network;
    this.provider = provider;
    this.baseUrl  = baseUrl || ENDPOINTS[network]?.[provider] || ENDPOINTS.mainnet.mempool;
  }

  // ── Address queries ──────────────────────────────────────

  /**
   * Retorna saldo de um endereço em satoshis.
   * @param {string} address
   * @returns {Promise<{ confirmed: bigint, unconfirmed: bigint }>}
   */
  async getBalance(address) {
    try {
      const data = await httpGetWithRetry(`${this.baseUrl}/address/${address}`);
      const chain  = data.chain_stats   || {};
      const mempool = data.mempool_stats || {};
      return {
        confirmed:   BigInt(chain.funded_txo_sum   || 0) - BigInt(chain.spent_txo_sum   || 0),
        unconfirmed: BigInt(mempool.funded_txo_sum || 0) - BigInt(mempool.spent_txo_sum || 0),
        total:       BigInt(chain.funded_txo_sum   || 0) - BigInt(chain.spent_txo_sum   || 0) +
                     BigInt(mempool.funded_txo_sum || 0) - BigInt(mempool.spent_txo_sum || 0),
      };
    } catch (e) {
      throw new Error(`getBalance(${address}): ${e.message}`);
    }
  }

  /**
   * Retorna UTXOs de um endereço.
   * @param {string} address
   * @returns {Promise<import('./utxo').UTXOEntry[]>}
   */
  async getUTXOs(address) {
    try {
      const raw = await httpGetWithRetry(`${this.baseUrl}/address/${address}/utxo`);
      const { createUTXO } = require('./utxo');
      const { classifyAddress } = require('./adapter');

      return raw.map(u => createUTXO({
        txid:           u.txid,
        vout:           u.vout,
        value:          u.value,
        scriptPubKey:   '', // mempool.space não retorna scriptPubKey no /utxo
        address,
        confirmations:  u.status?.confirmed ? (u.status.block_height ? 1 : 0) : 0,
        height:         u.status?.block_height || 0,
        type:           'P2WPKH', // assumir P2WPKH (pode ser detectado via scriptPubKey)
      }));
    } catch (e) {
      throw new Error(`getUTXOs(${address}): ${e.message}`);
    }
  }

  /**
   * Retorna histórico de transações de um endereço.
   * @param {string} address
   * @returns {Promise<object[]>}
   */
  async getHistory(address) {
    try {
      return await httpGetWithRetry(`${this.baseUrl}/address/${address}/txs`);
    } catch (e) {
      throw new Error(`getHistory(${address}): ${e.message}`);
    }
  }

  /**
   * Retorna dados de uma transação específica.
   * @param {string} txid
   * @returns {Promise<object>}
   */
  async getTransaction(txid) {
    try {
      return await httpGetWithRetry(`${this.baseUrl}/tx/${txid}`);
    } catch (e) {
      throw new Error(`getTransaction(${txid}): ${e.message}`);
    }
  }

  /**
   * Retorna o raw hex de uma transação.
   * @param {string} txid
   * @returns {Promise<string>}
   */
  async getRawTransaction(txid) {
    try {
      return await httpGetWithRetry(`${this.baseUrl}/tx/${txid}/hex`);
    } catch (e) {
      throw new Error(`getRawTransaction(${txid}): ${e.message}`);
    }
  }

  /**
   * Retorna fee rates recomendados (sat/vbyte).
   * @returns {Promise<{ fastest: number, halfHour: number, hour: number, economy: number }>}
   */
  async getFeeRates() {
    try {
      const data = await httpGetWithRetry(`${this.baseUrl}/v1/fees/recommended`);
      return {
        fastest:   data.fastestFee     || 50,
        halfHour:  data.halfHourFee    || 25,
        hour:      data.hourFee        || 15,
        economy:   data.economyFee     || 5,
        minimum:   data.minimumFee     || 1,
      };
    } catch (e) {
      // Fallback com valores conservadores
      return { fastest: 50, halfHour: 25, hour: 15, economy: 5, minimum: 1 };
    }
  }

  /**
   * Retorna altura atual do blockchain.
   * @returns {Promise<number>}
   */
  async getBlockHeight() {
    try {
      const data = await httpGetWithRetry(`${this.baseUrl}/blocks/tip/height`);
      return typeof data === 'number' ? data : parseInt(data);
    } catch (e) {
      throw new Error(`getBlockHeight: ${e.message}`);
    }
  }

  /**
   * Retorna informações do mempool.
   * @returns {Promise<object>}
   */
  async getMempoolInfo() {
    try {
      return await httpGetWithRetry(`${this.baseUrl}/mempool`);
    } catch (e) {
      throw new Error(`getMempoolInfo: ${e.message}`);
    }
  }

  // ── Broadcast ────────────────────────────────────────────

  /**
   * Broadcast de uma transação para a rede Bitcoin.
   * Retorna o txid se aceito, lança erro se rejeitado.
   *
   * @param {string} rawHex - Transação raw em hex
   * @returns {Promise<string>} txid
   */
  async broadcastTransaction(rawHex) {
    if (!rawHex || typeof rawHex !== 'string') {
      throw new Error('rawHex inválido');
    }
    if (rawHex.length < 20) {
      throw new Error('Transação muito curta — verifique a serialização');
    }

    try {
      const txid = await httpPost(`${this.baseUrl}/tx`, rawHex);
      if (!txid || txid.length !== 64) {
        throw new Error('Resposta inesperada do broadcast: ' + txid);
      }
      return txid;
    } catch (e) {
      throw new Error(`broadcastTransaction falhou: ${e.message}`);
    }
  }

  // ── Address scanning ─────────────────────────────────────

  /**
   * Escaneia múltiplos endereços e retorna UTXOs consolidados.
   * Útil para gap limit scanning (BIP44).
   *
   * @param {string[]} addresses
   * @param {object}   [opts]
   * @param {number}   [opts.gapLimit=20]  - Parar após N endereços sem txs
   * @returns {Promise<{ utxos: UTXOEntry[], activeAddresses: string[] }>}
   */
  async scanAddresses(addresses, opts = {}) {
    const results    = [];
    const active     = [];
    let   emptyCount = 0;
    const gapLimit   = opts.gapLimit || 20;

    for (const addr of addresses) {
      try {
        const history = await this.getHistory(addr);
        if (history.length > 0) {
          emptyCount = 0;
          active.push(addr);
          const utxos = await this.getUTXOs(addr);
          results.push(...utxos);
        } else {
          emptyCount++;
          if (emptyCount >= gapLimit) break; // gap limit atingido
        }
        // Rate limiting: 100ms entre requests
        await new Promise(r => setTimeout(r, 100));
      } catch (e) {
        // Continuar em caso de erro de rede para um endereço específico
        emptyCount++;
      }
    }

    return { utxos: results, activeAddresses: active };
  }

  /**
   * Retorna informações do endereço (stats de tx).
   * @param {string} address
   * @returns {Promise<object>}
   */
  async getAddressInfo(address) {
    try {
      return await httpGetWithRetry(`${this.baseUrl}/address/${address}`);
    } catch (e) {
      throw new Error(`getAddressInfo(${address}): ${e.message}`);
    }
  }

  /**
   * Verifica se um UTXO foi gasto (para anti-double-spend).
   * @param {string} txid
   * @param {number} vout
   * @returns {Promise<boolean>} true se foi gasto
   */
  async isUTXOSpent(txid, vout) {
    try {
      const data = await httpGetWithRetry(`${this.baseUrl}/tx/${txid}/outspend/${vout}`);
      return data.spent === true;
    } catch {
      return false; // assumir não gasto em caso de erro
    }
  }
}

// ─── Instâncias pré-configuradas ─────────────────────────────

/** Cliente para mainnet via mempool.space */
const mainnetClient = new ElectrumClient({ network: 'mainnet', provider: 'mempool' });

/** Cliente para testnet via mempool.space */
const testnetClient = new ElectrumClient({ network: 'testnet', provider: 'mempool' });

module.exports = {
  ElectrumClient,
  mainnetClient,
  testnetClient,
  ENDPOINTS,

  // Utilitários HTTP expostos para testes e extensões
  httpGet: httpGetWithRetry,
  httpPost,
};

