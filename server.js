const express = require('express');

const app = express();

app.get('/', (req, res) => {
  res.json({
    status: 'online',
    project: 'BC Wallet'
  });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log('Servidor rodando');
});
