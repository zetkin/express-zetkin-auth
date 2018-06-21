'use strict';

const Z = require('zetkin');
const url = require('url');


const defaultOpts = {
    cookieName: 'apiToken',
    defaultRedirPath: '/',
    logoutRedirPath: null,
    zetkinDomain: 'zetk.in',
    minAuthLevel: undefined,
};


function initialize(opts) {
    opts = Object.assign({}, defaultOpts, opts);

    return (req, res, next) => {
        req.z = Z.construct({
            clientId: opts.app.id,
            clientSecret: opts.app.secret,
            zetkinDomain: opts.zetkinDomain,
        });

        let cookie = req.cookies[opts.cookieName];
        if (cookie) {
            try {
                req.z.setToken(cookie);
            }
            catch (err) {
                res.clearCookie(opts.cookieName);
            }
            next();
        }
        else if (req.query.code) {
            const callbackUrl = url.format({
                protocol: opts.ssl? 'https' : 'http',
                host: req.get('host'),
                pathname: req.path,
                query: req.query,
            });

            req.z.authenticate(callbackUrl)
                .then(() => {
                    res.cookie(opts.cookieName, req.z.getToken());

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
        else {
            next();
        }
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
                res.cookie(opts.cookieName, req.z.getToken());

                if (opts.minAuthLevel) {
                    let session = result.data.data;
                    if (session.level < opts.minAuthLevel) {
                        const redirUrl = encodeURIComponent(url.format({
                            protocol: opts.ssl? 'https' : 'http',
                            host: req.get('host'),
                            pathname: req.originalUrl,
                        }));

                        let loginUrl = '//login.' + process.env.ZETKIN_DOMAIN + '/upgrade'
                            + '?token=' + req.z.getToken()
                            + '&redirect_uri=' + redirUrl;

                        res.redirect(loginUrl);

                        return;
                    }
                }

                next();
            })
            .catch(() => {
                res.clearCookie(opts.cookieName);

                if (preventRedirect) {
                    next();
                }
                else {
                    const redirUrl = encodeURIComponent(url.format({
                        protocol: opts.ssl? 'https' : 'http',
                        host: req.get('host'),
                        pathname: req.originalUrl,
                    }));

                    res.redirect(req.z.getLoginUrl(redirUrl));
                }
            });
    }
}

function logout(opts) {
    opts = Object.assign({}, defaultOpts, opts);

    return (req, res, next) => {
        res.clearCookie(opts.cookieName);
        req.z.resource('session').del()
            .then(() => {
                res.redirect(opts.logoutRedirPath || opts.defaultRedirPath);
            })
            .catch(() => {
                res.redirect(opts.defaultRedirPath);
            });
    }
}


module.exports = {
    initialize, validate, logout,
};
