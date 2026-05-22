document
.getElementById('create')
.onclick = async () => {

    const res = await fetch('/api/create-wallet', {
        method:'POST'
    });

    const data = await res.json();

    document.getElementById('wallet').innerHTML = `
        <p><b>Address:</b><br>${data.address}</p>
        <p><b>Mnemonic:</b><br>${data.mnemonic}</p>
    `;
};
