const express = require('express');
const { HDWallet } = require('./HDWallet'); // ← ARRUMEI AQUI
const app = express();
app.use(express.json());

// Guarda wallets em memória - SÓ PRA TESTE
const wallets = new Map();

app.post('/create', (req, res) => {
  try {
    const { password, label } = req.body;
    if (!password) return res.status(400).json({ error: 'Password obrigatório' });
    
    const { wallet, mnemonic } = HDWallet.create(password, { label });
    wallets.set(wallet.id, wallet);
    
    res.json({ 
      walletId: wallet.id, 
      mnemonic, // SÓ MOSTRA 1X - SALVA AGORA
      warning: 'Nunca mais vamos mostrar o mnemonic. Salva em lugar seguro.'
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/address', (req, res) => {
  try {
    const { walletId, chain = 'BC', accountIdx = 0, addressIdx = 0 } = req.body;
    const wallet = wallets.get(walletId);
    if (!wallet) return res.status(404).json({ error: 'Wallet não encontrada' });
    if (wallet.isLocked) return res.status(401).json({ error: 'Wallet bloqueada. Desbloqueia primeiro.' });
    
    res.json(wallet.getAddress(chain, accountIdx, addressIdx));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/sign', (req, res) => {
  try {
    const { walletId, tx, chain, accountIdx = 0, addressIdx = 0 } = req.body;
    const wallet = wallets.get(walletId);
    if (!wallet) return res.status(404).json({ error: 'Wallet não encontrada' });
    if (wallet.isLocked) return res.status(401).json({ error: 'Wallet bloqueada' });
    
    const signed = wallet.signTransaction(tx, chain, accountIdx, addressIdx);
    res.json(signed);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/lock', (req, res) => {
  const { walletId } = req.body;
  const wallet = wallets.get(walletId);
  if (!wallet) return res.status(404).json({ error: 'Wallet não encontrada' });
  wallet.lock();
  res.json({ status: 'locked' });
});

app.get('/health', (_, res) => res.send('ok'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Wallet API ON :${PORT}`));
