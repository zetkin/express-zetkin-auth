'use strict';

const Z = require('zetkin');


const defaultOpts = {
    cookieName: 'apiTicket',
    defaultRedirPath: '/',
    logoutRedirPath: null,
    loginUrl: 'https://login.zetk.in',
};


function initialize(opts) {
    opts = Object.assign({}, defaultOpts, opts);

    return (req, res, next) => {
        req.z = Z.construct();

        let cookie = req.cookies[opts.cookieName];
        if (cookie) {
            req.z.setTicket(JSON.parse(cookie));
        }

        next();
    };
}

function callback(opts) {
    opts = Object.assign({}, defaultOpts, opts);

    if (!opts.app || !opts.app.id || !opts.app.key) {
        throw 'auth.callback() requires app ID and key';
    }

    return (req, res, next) => {
        let app = opts.app;
        if (req.query.rsvp) {
            req.z.init(app.id, app.key, req.query.rsvp, ticket => {
                res.cookie(opts.cookieName, JSON.stringify(ticket));

                // Redirect to specified redirection path, or to the default
                // redirection path if no redirection path has been defined
                res.redirect(req.query.redirPath || opts.defaultRedirPath);
            });
        }
        else if (opts.defaultRedirPath != req.path) {
            res.redirect(opts.defaultRedirPath);
        }
        else {
            next();
        }
    }
}

function validate(opts) {
    opts = Object.assign({}, defaultOpts, opts);

    if (!opts.app || !opts.app.id || !opts.app.key) {
        throw 'auth.validate() requires app ID';
    }

    return (req, res, next) => {
        // Try to get session to verify ticket
        req.z.resource('session').get()
            .then(() => {
                req.isZetkinAuthenticated = true;

                // While validating, the ticket may have been updated, e.g. if
                // the previous ticket had expired. Store new ticket in cookie.
                res.cookie(opts.cookieName, JSON.stringify(req.z.getTicket()));

                next();
            })
            .catch(() => {
                res.clearCookie(opts.cookieName);
                res.redirect(opts.loginUrl
                    + '?appId=' + opts.app.id
                    + '&redirPath=' + req.path);
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
    initialize, callback, validate, logout,
};
