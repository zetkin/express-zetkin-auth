'use strict';

const Z = require('zetkin');
const url = require('url');


const defaultOpts = {
    cookieName: 'apiToken',
    defaultRedirPath: '/',
    logoutRedirPath: null,
    zetkinDomain: 'zetk.in',
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
            req.z.setToken(cookie);
            next();
        }
        else if (req.query.code) {
            const callbackUrl = url.format({
                protocol: req.protocol,
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
                        protocol: req.protocol,
                        host: req.get('host'),
                        pathname: req.path,
                        query: query,
                    }));
                })
                .catch(err => {
                    // Redirect to same URL but without the code
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
            .then(() => {
                req.isZetkinAuthenticated = true;

                // While validating, the ticket may have been updated, e.g. if
                // the previous ticket had expired. Store new ticket in cookie.
                res.cookie(opts.cookieName, req.z.getToken());

                next();
            })
            .catch(() => {
                res.clearCookie(opts.cookieName);

                if (preventRedirect) {
                    next();
                }
                else {
                    const redirUrl = encodeURIComponent(url.format({
                        protocol: req.protocol,
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
