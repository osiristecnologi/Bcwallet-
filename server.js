const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bip39 = require('bip39');

const app = express();

app.use(express.static('public'));

app.get('/api/create-wallet', async (req, res) => {

  const mnemonic = bip39.generateMnemonic();

  const privateKey = crypto.randomBytes(32).toString('hex');

  const address = 'BC' + crypto
    .createHash('sha256')
    .update(privateKey)
    .digest('hex')
    .slice(0, 40);

  res.json({
    mnemonic,
    privateKey,
    address,
    balance: 0
  });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/index.html'));
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log('BC Wallet Online');
});
