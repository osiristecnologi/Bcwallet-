const express = require('express');
const path = require('path');
const crypto = require('crypto');

const app = express();

app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/wallet', (req, res) => {

  const wallet = {
    address: 'BC' + crypto.randomBytes(20).toString('hex'),
    privateKey: crypto.randomBytes(32).toString('hex'),
    balance: 0
  };

  res.json(wallet);
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/index.html'));
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log('Servidor rodando');
});
