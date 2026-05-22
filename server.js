const express = require('express');
const path = require('path');
const cors = require('cors');

const app = express();

app.use(cors());
app.use(express.json());

// Frontend wallet
app.use(express.static(path.join(__dirname, 'frontend')));

app.get('/api/health', (req, res) => {
  res.json({
    status: 'online',
    wallet: 'BC Wallet',
    network: 'BC Mainnet'
  });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log('BC Wallet online:', PORT);
});
