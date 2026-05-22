const express = require('express');
const path = require('path');

const HDWallet = require('./wallet/HDWallet');

const app = express();

app.use(express.json());
app.use(express.static('public'));

app.post('/api/create-wallet', async (req, res) => {

    try {

        const wallet = new HDWallet();

        const data = await wallet.createWallet();

        res.json(data);

    } catch (e) {

        res.status(500).json({
            error: e.message
        });

    }

});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/index.html'));
});

const PORT = process.env.PORT || 3000;

app.listen(PORT);
