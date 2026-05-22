const express = require('express');
const { HDWallet } = require('./wallet/HDWallet');
const app = express();
app.use(express.json());

// Guarda wallets em memória - SÓ PRA TESTE
const wallets = new Map();

app.post('/create', (req, res) => {
  const { password } = req.body;
  const { wallet, mnemonic } = HDWallet.create(password);
  wallets.set(wallet.id, wallet);
  res.json({ walletId: wallet.id, mnemonic }); // SÓ MOSTRA 1X
});

app.post('/address', (req, res) => {
  const { walletId, chain = 'BC' } = req.body;
  const wallet = wallets.get(walletId);
  if (!wallet) return res.status(404).send('Wallet não encontrada');
  res.json(wallet.getAddress(chain, 0, 0));
});

app.post('/sign', (req, res) => {
  const { walletId, tx, chain } = req.body;
  const wallet = wallets.get(walletId);
  const signed = wallet.signTransaction(tx, chain);
  res.json(signed);
});

app.get('/health', (_, res) => res.send('ok'));

app.listen(process.env.PORT || 3000, () => console.log('Wallet API ON'));
