const https = require('https');
const fs = require('fs');
const path = require('path');
const helmet = require('helmet');
const passport = require('passport');
const cookieSession = require('cookie-session');

const { Strategy } = require('passport-google-oauth20');

const express = require('express');
const { verify } = require('crypto');

require('dotenv').config();

const PORT = 3000;

//Dotenv Variables
const config = {
    CLIENT_ID: process.env.CLIENT_ID,
    CLIENT_SECRET: process.env.CLIENT_SECRET,
    COOKIE_KEY_1: process.env.COOKIE_KEY_1,
    COOKIE_KEY_2: process.env.COOKIE_KEY_2,
};

//Passport Strategy (for Google)
const AUTH_OPTIONS = {
    callbackURL: '/auth/google/callback',
    clientID: config.CLIENT_ID,
    clientSecret: config.CLIENT_SECRET
};
function verifyCallback(accessToken, refreshToken, profile, done) {
    console.log('Google Profile', profile);
    done(null, profile);
};
passport.use(new Strategy(AUTH_OPTIONS, verifyCallback));

//Serializing: Save the session to the cookie
passport.serializeUser((user, done) => {
    done(null, user.id);
});

//Deserializing: Read the session from the cookie
passport.deserializeUser((id, done) => {
    done(null, id);
});

const app = express();

//Security Related Middleware
app.use(helmet());

//Cookie Session Middleware
app.use(cookieSession({
    name: 'session',
    maxAge: 24 * 60 * 60 * 1000,
    keys: [config.COOKIE_KEY_1, config.COOKIE_KEY_2]
}));

//Passport Inizialize Middleware
app.use(passport.initialize());

//Passport Session Middleware
app.use(passport.session());

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

//Oauth Endpoints
app.get('/auth/google', passport.authenticate('google', {
    scope: ['email'],
}));
app.get('/auth/google/callback', passport.authenticate('google', {
    failureRedirect: '/failure',
    successRedirect: '/',
    session: true, //True if cookie-session is configured
}), (req, res) => {
    console.log('Google called us back!')
});
app.get('/failure', (req, res) => {
    return res.send('Failed to log in!')
})
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