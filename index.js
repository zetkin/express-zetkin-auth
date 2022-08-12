'use strict';

const crypto = require('crypto');
const url = require('url');
const Z = require('zetkin');


const defaultOpts = {
    tokenCookieName: 'apiAccessToken',
    sessionCookieName: 'apiSession',
    defaultRedirPath: '/',
    logoutRedirPath: null,
    zetkinDomain: 'zetk.in',
    minAuthLevel: undefined,
    secret: null,
    heartbeatMaxAge: 45 * 60, // 45 minutes
};


function initialize(opts) {
    opts = Object.assign({}, defaultOpts, opts);

    if (!opts.secret || opts.secret.length != 24) {
        throw 'Encryption secret must be a 24 character string!';
    }

    return (req, res, next) => {
        req.z = Z.construct({
            clientId: opts.app.id,
            clientSecret: opts.app.secret,
            zetkinDomain: opts.zetkinDomain,
            ssl: opts.ssl,
        });

        let session = req.cookies[opts.sessionCookieName];
        if (req.query.code) {
            const callbackUrl = url.format({
                protocol: opts.ssl? 'https' : 'http',
                host: req.get('host'),
                pathname: req.path,
                query: req.query,
            });

            req.z.authenticate(callbackUrl)
                .then(() => {
                    setTokenCookies(req, res, opts);

                    // Redirect to same URL without the code
                    let query = Object.assign({}, req.query);
                    delete query.code;

                    res.redirect(url.format({
                        protocol: opts.ssl? 'https' : 'http',
                        host: req.get('host'),
                        pathname: req.path,
                        query: query,
                    }));
                })
                .catch(err => {
                    res.redirect(opts.defaultRedirPath);
                });
        }
        else if (session) {
            try {
                const [ encrypted, ivHex ] = session.split('$');
                const ivBuf = Buffer.from(ivHex, 'hex');
                const decipher = crypto.createDecipheriv('aes192', opts.secret, ivBuf);

                let decrypted = decipher.update(encrypted, 'hex', 'utf8');
                decrypted += decipher.final('utf8');

                req.z.setToken(decrypted);
            }
            catch (err) {
                res.clearCookie(opts.tokenCookieName);
                res.clearCookie(opts.sessionCookieName);
            }
            next();
        }
        else {
            next();
        }
    };
}

function login(opts) {
    opts = Object.assign({}, defaultOpts, opts);

    return (req, res, next) => {
        const path = req.query.redirPath || opts.defaultRedirPath;

        const redirUrl = url.format({
            protocol: opts.ssl? 'https' : 'http',
            host: req.get('host'),
            pathname: path,
        });

        res.redirect(req.z.getLoginUrl(redirUrl));
    };
}

function validate(opts, preventRedirect) {
    opts = Object.assign({}, defaultOpts, opts);

    return (req, res, next) => {
        // Try to get session to verify ticket
        req.z.resource('session').get()
            .then(result => {
                req.isZetkinAuthenticated = true;

                // While validating, the token may have been updated, e.g. if
                // the previous token had expired. Store new ticket in cookie.
                setTokenCookies(req, res, opts);

                if (opts.minAuthLevel) {
                    let session = result.data.data;
                    if (session.level < opts.minAuthLevel) {
                        const redirUrl = url.format({
                            protocol: opts.ssl? 'https' : 'http',
                            host: req.get('host'),
                            pathname: req.baseUrl? (req.baseUrl + req.path) : req.path,
                            query: req.query,
                        });

                        const level = 'level' + opts.minAuthLevel;
                        const scopes = [ level ];

                        res.redirect(req.z.getLoginUrl(redirUrl, scopes));

                        return;
                    }
                }

                next();
            })
            .catch(() => {
                res.clearCookie(opts.tokenCookieName);
                res.clearCookie(opts.sessionCookieName);

                if (preventRedirect) {
                    next();
                }
                else {
                    const redirUrl = url.format({
                        protocol: opts.ssl? 'https' : 'http',
                        host: req.get('host'),
                        pathname: req.baseUrl? (req.baseUrl + req.path) : req.path,
                        query: req.query,
                    });

                    const scopes = [];

                    if (opts.minAuthLevel) {
                        scopes.push('level' + opts.minAuthLevel);
                    }

                    res.redirect(req.z.getLoginUrl(redirUrl, scopes));
                }
            });
    }
}

function heartbeat(opts) {
    opts = Object.assign({}, defaultOpts, opts);

    return async (req, res) => {
        try {
            await req.z.resource('session');
            const tokenData = req.z.getTokenData();

            const payload64 = Buffer.from(tokenData.access_token.split('.')[1], 'base64');
            const payloadJson = payload64.toString('ascii');
            const payload = JSON.parse(payloadJson);
            const iat = new Date(payload.iat * 1000);
            const now = new Date();
            const age = now - iat;

            const MAX_AGE = opts.heartbeatMaxAge * 1000;

            if (age > MAX_AGE) {
                await req.z.refresh();

                setTokenCookies(req, res, opts);
            }

            res.status(200).end();
        } catch (err) {
            console.error(err);
            res.status(200).end();
        }
    };
}

function logout(opts) {
    opts = Object.assign({}, defaultOpts, opts);

    return (req, res, next) => {
        res.clearCookie(opts.tokenCookieName);
        res.clearCookie(opts.sessionCookieName);
        req.z.resource('session').del()
            .then(() => {
                res.redirect(opts.logoutRedirPath || opts.defaultRedirPath);
            })
            .catch(() => {
                res.redirect(opts.defaultRedirPath);
            });
    }
}

function setTokenCookies(req, res, opts) {
    const cookieOpts = {
        secure: opts.ssl,
    };

    const ivBuf = Buffer.alloc(16);
    crypto.randomFillSync(ivBuf);

    const cipher = crypto.createCipheriv('aes192', opts.secret, ivBuf);
    let encryptedTokenData = cipher.update(req.z.getToken(), 'utf8', 'hex');
    encryptedTokenData += cipher.final('hex');
    encryptedTokenData += '$' + ivBuf.toString('hex');

    let tokenData = req.z.getTokenData();
    res.cookie(opts.tokenCookieName, tokenData.access_token, cookieOpts);
    res.cookie(opts.sessionCookieName, encryptedTokenData, cookieOpts);
}

module.exports = {
    heartbeat,
    initialize,
    login,
    logout,
    validate,
};
