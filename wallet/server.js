const express = require('express');
const path = require('path');

const app = express();

app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/health', (req, res) => {
  res.json({
    status: 'online',
    wallet: 'BC Wallet'
  });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log('BC Wallet online on port', PORT);
});
