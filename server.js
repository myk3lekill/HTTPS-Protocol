const https = require('https');
const fs = require('fs');
const path = require('path');
const express = require('express');
const helmet = require('helmet');

const PORT = 3000;

const app = express();

//Secirity Related Middleware
app.use(helmet());

//OAuth Middleware
function checkLoggedIn (req, res, next) {
    const isLoggedIn = true;
    if (!isLoggedIn) {
        return res.status(401).json({
            error:'You must log in!',
        });
    }
    next();
};

app.get('/auth/google', (req, res) => {});

app.get('/auth/google/callback', (req, res) => {})

app.get('/auth/logout', (req, res) => {});

app.get('/secrets', (req, res) => {
    return res.send('Your personal secret value is 42')
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'))
});

https.createServer({
    key:fs.readFileSync('key.pem'),
    cert:fs.readFileSync('cert.pem'),
}, app).listen(PORT, () => {
    console.log(`Listening on port ${PORT}...`)
});