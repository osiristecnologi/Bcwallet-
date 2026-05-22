/**
 * wallet/chains/bitcoin/utxo.js
 * ═══════════════════════════════════════════════════════════════
 * UTXO Engine — gerenciamento de Unspent Transaction Outputs.
 *
 * UTXO (Unspent Transaction Output) é o modelo de saldo do Bitcoin:
 * o saldo de um endereço = soma de todos os UTXOs não gastos.
 * Não existe "conta com saldo" como no Ethereum — cada UTXO é
 * uma "moeda" indivisível que deve ser gasta inteiramente.
 *
 * COIN SELECTION:
 *   Escolher quais UTXOs usar como inputs é crítico para:
 *   • Fee mínimo (menos inputs = tx menor = fee menor)
 *   • Privacidade (não consolidar moedas de fontes diferentes)
 *   • Dust prevention (não criar outputs < dust limit)
 *
 * ALGORITMOS IMPLEMENTADOS:
 *   • LARGEST_FIRST — greedy, minimiza número de inputs
 *   • OLDEST_FIRST  — FIFO, boas práticas de privacidade
 *   • BRANCH_AND_BOUND — Branch and Bound simplificado (minimiza troco)
 *
 * CONSTANTES BITCOIN:
 *   Dust limit (P2WPKH): 294 sat  — abaixo disso o mempool rejeita
 *   Min relay fee:        1 sat/vbyte
 *   Max outputs per tx:  ~3000 (limite de tamanho de bloco)
 *
 * Futuro:
 *   - Privacy coin selection (evitar linking)
 *   - CPFP (Child-Pays-For-Parent)
 *   - RBF (Replace-By-Fee) bump
 *   - Coin freeze (não usar UTXOs marcados)
 * ═══════════════════════════════════════════════════════════════
 */

'use strict';

// ─── Constantes Bitcoin ──────────────────────────────────────

/**
 * Limites de dust por tipo de output.
 * Outputs abaixo destes valores são rejeitados pelo mempool.
 * (Valores em satoshis @ 1 sat/vbyte fee rate)
 */
const DUST_LIMITS = {
  P2PKH:  546,   // 546 sat — legacy
  P2SH:   540,   // 540 sat
  P2WPKH: 294,   // 294 sat — native segwit
  P2WSH:  330,   // 330 sat
  P2TR:   330,   // 330 sat — taproot
};

/** Taxa mínima de relay (sat/vbyte) */
const MIN_RELAY_FEE_RATE = 1n;

/** Tamanho de input em vbytes por tipo (para fee estimation) */
const INPUT_VBYTES = {
  P2PKH:       148,  // Legacy: scriptSig com sig + pubkey
  P2SH_P2WPKH: 91,   // Nested SegWit
  P2WPKH:      68,   // Native SegWit (witness discount)
  P2WSH:       105,  // Native SegWit script
  P2TR:        57.5, // Taproot key-path (witness discount)
};

/** Tamanho de output em vbytes por tipo */
const OUTPUT_VBYTES = {
  P2PKH:  34,
  P2SH:   32,
  P2WPKH: 31,
  P2WSH:  43,
  P2TR:   43,
};

/** Overhead fixo de uma transação (version + locktime + varint counts) */
const TX_OVERHEAD_VBYTES = 10.5; // SegWit: 10 + 0.5 (marker/flag)

// ═══════════════════════════════════════════════════════════════
// UTXO STRUCTURE
// ═══════════════════════════════════════════════════════════════

/**
 * Cria um objeto UTXO normalizado.
 *
 * @param {object} raw
 * @returns {UTXOEntry}
 */
function createUTXO({
  txid, vout, value, scriptPubKey, address,
  confirmations = 0, height = 0, type = 'P2WPKH',
}) {
  if (!txid || typeof txid !== 'string' || txid.length !== 64) {
    throw new Error('txid inválido: ' + txid);
  }
  if (typeof vout !== 'number' || vout < 0) {
    throw new Error('vout inválido: ' + vout);
  }
  const val = BigInt(value);
  if (val < 0n) throw new Error('UTXO value negativo');
  if (val > 21_000_000n * 100_000_000n) throw new Error('UTXO value > supply máximo');

  return {
    txid,
    vout,
    value:         val,
    scriptPubKey:  Buffer.isBuffer(scriptPubKey)
      ? scriptPubKey
      : Buffer.from(scriptPubKey, 'hex'),
    address:       address || '',
    confirmations,
    height,
    type:          type.toUpperCase(),
    spent:         false,
    spentBy:       null,    // txid da tx que gastou este UTXO
    frozen:        false,   // marcado como "não gastar"
    _id:           `${txid}:${vout}`,
  };
}

// ═══════════════════════════════════════════════════════════════
// UTXO POOL
// ═══════════════════════════════════════════════════════════════

class UTXOPool {
  /**
   * @param {string} [label] - Identificador do pool (ex: endereço)
   */
  constructor(label = '') {
    this.label = label;
    /** @type {Map<string, UTXOEntry>} txid:vout → UTXO */
    this._utxos = new Map();
    /** txids localmente confirmados como gastos (mempool lock) */
    this._pendingSpend = new Set();
  }

  // ── CRUD ─────────────────────────────────────────────────

  /**
   * Adiciona ou atualiza um UTXO.
   * @param {UTXOEntry} utxo
   */
  add(utxo) {
    this._utxos.set(utxo._id, utxo);
  }

  /**
   * Adiciona múltiplos UTXOs (resultado de fetchUTXOs).
   * @param {UTXOEntry[]} utxos
   */
  addAll(utxos) {
    for (const u of utxos) this.add(u);
  }

  /**
   * Marca um UTXO como gasto (anti-double-spend local).
   * @param {string} txid
   * @param {number} vout
   * @param {string} [spentByTxid]
   */
  markSpent(txid, vout, spentByTxid = '') {
    const id   = `${txid}:${vout}`;
    const utxo = this._utxos.get(id);
    if (utxo) {
      utxo.spent   = true;
      utxo.spentBy = spentByTxid;
    }
    this._pendingSpend.add(id);
  }

  /**
   * Congela um UTXO (não será selecionado para coin selection).
   */
  freeze(txid, vout) {
    const utxo = this._utxos.get(`${txid}:${vout}`);
    if (utxo) utxo.frozen = true;
  }

  unfree(txid, vout) {
    const utxo = this._utxos.get(`${txid}:${vout}`);
    if (utxo) utxo.frozen = false;
  }

  /**
   * Remove UTXOs gastos e confirmados.
   */
  prune() {
    for (const [id, utxo] of this._utxos) {
      if (utxo.spent && utxo.confirmations > 0) {
        this._utxos.delete(id);
        this._pendingSpend.delete(id);
      }
    }
  }

  // ── Queries ──────────────────────────────────────────────

  /**
   * Retorna UTXOs disponíveis (não gastos, não congelados).
   * @param {number} [minConfirmations=0] - 0 = incluir não confirmados
   * @returns {UTXOEntry[]}
   */
  available(minConfirmations = 0) {
    return Array.from(this._utxos.values()).filter(u =>
      !u.spent &&
      !u.frozen &&
      u.confirmations >= minConfirmations
    );
  }

  /**
   * Saldo total disponível em satoshis.
   * @param {number} [minConfirmations=0]
   * @returns {bigint}
   */
  balance(minConfirmations = 0) {
    return this.available(minConfirmations).reduce((s, u) => s + u.value, 0n);
  }

  /**
   * Saldo confirmado (>= 1 confirmação).
   */
  get confirmedBalance() { return this.balance(1); }

  /**
   * Saldo não confirmado (0 confirmações).
   */
  get unconfirmedBalance() {
    return this.available(0).filter(u => u.confirmations === 0)
      .reduce((s, u) => s + u.value, 0n);
  }

  /** Número de UTXOs disponíveis */
  get size() { return this.available().length; }

  toJSON() {
    return {
      label:    this.label,
      utxos:    this.available().map(u => ({ ...u, value: u.value.toString(), scriptPubKey: u.scriptPubKey.toString('hex') })),
      balance:  this.balance().toString(),
    };
  }
}

// ═══════════════════════════════════════════════════════════════
// FEE ESTIMATION
// ═══════════════════════════════════════════════════════════════

/**
 * Estima o tamanho em virtual bytes de uma transação.
 *
 * @param {object} params
 * @param {number} params.inputCount
 * @param {string} params.inputType   - 'P2WPKH', 'P2PKH', 'P2TR', etc.
 * @param {number} params.outputCount
 * @param {string} params.outputType
 * @param {boolean} [params.hasChange=true]
 * @returns {number} virtual bytes
 */
function estimateTxVbytes({ inputCount, inputType = 'P2WPKH', outputCount, outputType = 'P2WPKH', hasChange = true }) {
  const inputVbytes  = INPUT_VBYTES[inputType]  || INPUT_VBYTES.P2WPKH;
  const outputVbytes = OUTPUT_VBYTES[outputType] || OUTPUT_VBYTES.P2WPKH;
  const changeVbytes = hasChange ? OUTPUT_VBYTES[outputType] : 0;

  return Math.ceil(
    TX_OVERHEAD_VBYTES +
    inputCount  * inputVbytes +
    outputCount * outputVbytes +
    changeVbytes
  );
}

/**
 * Calcula o fee para uma transação.
 *
 * @param {number} vbytes
 * @param {bigint} feeRate - sat/vbyte
 * @returns {bigint} fee em satoshis
 */
function calculateFee(vbytes, feeRate) {
  const rate = BigInt(Math.ceil(Number(feeRate)));
  return BigInt(vbytes) * rate;
}

// ═══════════════════════════════════════════════════════════════
// COIN SELECTION
// ═══════════════════════════════════════════════════════════════

/**
 * Algoritmo LARGEST_FIRST (greedy).
 * Seleciona UTXOs maiores primeiro para minimizar o número de inputs.
 * Rápido mas não ótimo para privacidade.
 *
 * @param {UTXOEntry[]} utxos      - Pool disponível
 * @param {bigint}      targetSats - Valor alvo (inclui fee estimado)
 * @returns {{ selected: UTXOEntry[], total: bigint } | null}
 */
function selectLargestFirst(utxos, targetSats) {
  const sorted  = [...utxos].sort((a, b) => (a.value > b.value ? -1 : 1));
  let total     = 0n;
  const selected = [];

  for (const u of sorted) {
    if (total >= targetSats) break;
    selected.push(u);
    total += u.value;
  }

  if (total < targetSats) return null;
  return { selected, total };
}

/**
 * Algoritmo OLDEST_FIRST (FIFO — confirmações decrescentes).
 * Gasta UTXOs mais antigos primeiro (boas práticas Bitcoin).
 */
function selectOldestFirst(utxos, targetSats) {
  const sorted   = [...utxos].sort((a, b) => b.confirmations - a.confirmations);
  let total      = 0n;
  const selected = [];

  for (const u of sorted) {
    if (total >= targetSats) break;
    selected.push(u);
    total += u.value;
  }

  if (total < targetSats) return null;
  return { selected, total };
}

/**
 * Branch and Bound simplificado.
 * Tenta encontrar uma seleção que resulte em zero troco
 * (ou troco mínimo), minimizando tamanho da tx.
 *
 * @param {UTXOEntry[]} utxos
 * @param {bigint}      targetSats
 * @param {bigint}      [tolerance=1000n] - Excesso máximo aceitável sem troco
 */
function selectBranchAndBound(utxos, targetSats, tolerance = 1000n) {
  // Tentar combinações de UTXOs que satisfaçam target sem troco
  const sorted = [...utxos].sort((a, b) => (a.value > b.value ? -1 : 1));

  // Só tentar BnB com até 20 UTXOs (exponencial)
  const pool = sorted.slice(0, 20);

  function bnb(index, selected, total) {
    if (total >= targetSats && total <= targetSats + tolerance) {
      return { selected: [...selected], total };
    }
    if (index >= pool.length || total > targetSats + tolerance) {
      return null;
    }
    // Incluir este UTXO
    selected.push(pool[index]);
    const withThis = bnb(index + 1, selected, total + pool[index].value);
    selected.pop();
    if (withThis) return withThis;

    // Pular este UTXO
    return bnb(index + 1, selected, total);
  }

  const result = bnb(0, [], 0n);
  if (result) return result;

  // Fallback para LARGEST_FIRST
  return selectLargestFirst(utxos, targetSats);
}

// ═══════════════════════════════════════════════════════════════
// MAIN selectUTXOs API
// ═══════════════════════════════════════════════════════════════

/**
 * Seleciona UTXOs para uma transação com fee calculado.
 *
 * @param {object} params
 * @param {UTXOEntry[]}              params.utxos         - UTXOs disponíveis
 * @param {bigint}                   params.amountSats    - Valor a enviar (sem fee)
 * @param {bigint}                   params.feeRate       - sat/vbyte
 * @param {string}                   [params.inputType]   - Tipo dos UTXOs
 * @param {string}                   [params.outputType]  - Tipo do output destino
 * @param {'LARGEST'|'OLDEST'|'BNB'} [params.algorithm]  - Algoritmo de seleção
 * @param {number}                   [params.outputCount=1]
 *
 * @returns {{
 *   selected: UTXOEntry[],
 *   totalInput: bigint,
 *   fee: bigint,
 *   change: bigint,
 *   vbytes: number,
 * } | { error: string }}
 */
function selectUTXOs({
  utxos,
  amountSats,
  feeRate,
  inputType  = 'P2WPKH',
  outputType = 'P2WPKH',
  algorithm  = 'LARGEST',
  outputCount = 1,
}) {
  if (!utxos || utxos.length === 0) return { error: 'Nenhum UTXO disponível' };

  amountSats = BigInt(amountSats);
  feeRate    = BigInt(feeRate);

  if (amountSats <= 0n)  return { error: 'Valor deve ser > 0' };
  if (feeRate    <= 0n)  return { error: 'Fee rate deve ser > 0' };

  // Verificar se há UTXOs suficientes
  const totalAvailable = utxos.reduce((s, u) => s + u.value, 0n);

  // Estimativa inicial de fee (sem saber quantos inputs ainda)
  // Tentar seleção iterativa
  let selected, total;
  let hasChange = true;
  let attempt   = 0;

  while (attempt < 3) {
    const estimatedVbytes = estimateTxVbytes({
      inputCount:  selected ? selected.length : 1,
      inputType,
      outputCount,
      outputType,
      hasChange,
    });
    const estimatedFee  = calculateFee(estimatedVbytes, feeRate);
    const targetSats    = amountSats + estimatedFee;

    if (targetSats > totalAvailable) {
      return {
        error: `Saldo insuficiente: ${totalAvailable} sat disponível, ${targetSats} sat necessário (${amountSats} + ${estimatedFee} fee)`,
      };
    }

    // Selecionar UTXOs
    let result;
    if (algorithm === 'OLDEST')     result = selectOldestFirst(utxos, targetSats);
    else if (algorithm === 'BNB')   result = selectBranchAndBound(utxos, targetSats);
    else                             result = selectLargestFirst(utxos, targetSats);

    if (!result) return { error: 'Coin selection falhou' };

    selected = result.selected;
    total    = result.total;

    // Recalcular fee com número real de inputs
    const finalVbytes = estimateTxVbytes({
      inputCount:  selected.length,
      inputType,
      outputCount,
      outputType,
      hasChange,
    });
    const finalFee    = calculateFee(finalVbytes, feeRate);
    const change      = total - amountSats - finalFee;
    const dustLimit   = BigInt(DUST_LIMITS[outputType] || 294);

    // Se troco < dust, incluir no fee (sem output de troco)
    if (change < dustLimit) {
      hasChange = false;
      if (change < 0n) { attempt++; continue; } // precisar de mais UTXOs
      return {
        selected, totalInput: total,
        fee:    finalFee + change, // absorver troco no fee
        change: 0n,
        vbytes: finalVbytes,
      };
    }

    return {
      selected, totalInput: total,
      fee:    finalFee,
      change,
      vbytes: finalVbytes,
    };
  }

  return { error: 'Não foi possível montar a transação após 3 tentativas' };
}

/**
 * Verifica se um valor está acima do limite de dust.
 * @param {bigint} value
 * @param {string} [outputType='P2WPKH']
 * @returns {boolean}
 */
function isDust(value, outputType = 'P2WPKH') {
  return BigInt(value) < BigInt(DUST_LIMITS[outputType] || 294);
}

/**
 * Consolida UTXOs de pequeno valor (dust consolidation).
 * Retorna UTXOs de valor abaixo do threshold para consolidação
 * num bloco de fee baixo.
 *
 * @param {UTXOEntry[]} utxos
 * @param {bigint}      [threshold=10000n] - < 10k sat = candidato a consolidação
 * @returns {UTXOEntry[]}
 */
function getDustUTXOs(utxos, threshold = 10000n) {
  return utxos.filter(u => u.value < threshold);
}

module.exports = {
  // Constants
  DUST_LIMITS,
  MIN_RELAY_FEE_RATE,
  INPUT_VBYTES,
  OUTPUT_VBYTES,
  TX_OVERHEAD_VBYTES,

  // UTXO
  createUTXO,
  UTXOPool,

  // Fee
  estimateTxVbytes,
  calculateFee,

  // Coin selection
  selectUTXOs,
  selectLargestFirst,
  selectOldestFirst,
  selectBranchAndBound,
  isDust,
  getDustUTXOs,
};

