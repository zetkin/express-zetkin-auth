# express-zetkin-auth
Express middleware for dealing with common tasks related to authentication and
authorization with the Zetkin Platform. It contains middleware functions and
endpoint handlers for:

* Storing and retrieving Zetkin API token from cookies
* Validating token ahead of endpoints that require it
* Redirecting to, and handling redirects back from Zetkin Platform login flow
* Logging out, destroying session and clearing cookie

Note that this middleware is closely related to, but not the same as, the
[Zetkin javascript SDK](https://github.com/zetkin/zetkin-js). This piece of
documentation repeatedly refers to the Zetkin SDK or it's main `Z` class.

## Example
The below example contains all the code necessary to set up authentication with
the Zetkin API.

```javascript
import auth from 'express-zetkin-auth';

const authOpts = {
    app: {
        id: "myAppId",
        secret: "mySecretAppKey"
    }
};

app.use(auth.initialize(authOpts));
app.get('/logout', auth.logout());

// Uses validate() to make sure user is logged in
app.get('/my/page', auth.validate(authOpts), (req, res) => {
    // Because initialize() ran earlier, req.z exists
    req.z.resource('users', 'me')
        .get()
        .then(res => {
            res.send('Hello ' + res.data.email);
        });
});
```

An anonymous user that tries to access /my/page will be redirected to the Zetkin
Platform login flow where they will be asked to log in and authorize access to
the Zetkin API to our application. The user will then be redirected back to
/my/page where they will now be able to access the data retrieved using the
Zetkin SDK.

## Options
All functions accept a single attribute which should be an object with the
following format.

```javascript
const authOpts = {
    cookieName: "apiToken",                 // Optional
    defaultRedirPath: "",                   // Optional
    logoutRedirPath: "",                    // Optional
    zetkinDomain: "zetk.in",                // Optional
    app: {                                  // Required
        id: "myAppId",
        secret: "myAppSecret"
    }
};
```
The only required option, for which there are no default values, is the `app`
object containing application credentials.

### App credentials (`app`)
The application credentials are defined as an object with attributes `id` and
`key` for the application ID and secret key respectively. If you do not have
any application credentials, first register your application with the Zetkin
Platform.

The key should be kept secret. Avoid storing it in code that could be accessed
by others, e.g. on GitHub. Instead, store your app key elsewhere and inject it
using an environment variable (via e.g. `process.env.ZETKIN_APP_KEY`) or some
other means.

### Cookie name (`cookieName`)
This is the name used to store the serialized user ticket in a browser cookie,
which can then be accessed on the client to make requests directly.

### Zetkin domain (`zetkinDomain`)
This is the domain on which Zetkin is running, by default this is the normal
Zetkin instance at zetk.in (api.zetk.in, login.zetk.in etc).

This attribute should only be used explicitly in Zetkin development when the log
in portal is running on the Zetkin development server or locally. The default
value zetk.in is correct for any other case.

### Paths for redirects (`defaultRedirPath` and `logoutRedirPath`)
These values define where a user should be redirected after a successful logout
or login operation (unless the login flow was initiated automatically by
`validate()` in which case the user will be redirected back to the originally
requested path).

If no `logoutRedirPath` is defined, users will be redirected to the
`defaultRedirPath` after logging out.

## API reference
### `initialize(options)`
This function creates a Zetkin SDK `Z` instance on the express `req` object and
looks for a Zetkin API token in the cookies, using the name in the `cookieName`
attribute on the options object. It also handles redirects back from the login
flow.

```javascript
app.use(initialize(authOpts));
```

Adding the `initialize()` middleware like this makes an instance of the Zetkin
SDK `Z` class, configured with any ticket found in the cookies, available to all
subsequent handlers as `req.z`.

### `validate(options)`
This function creates a middleware suitable for validating user authentication.
It does not deal with authorization at all, instead only validating that a
ticket exists and that it is valid in the sense that it has not expired and
represents a user signed into the Zetkin Platform.

If no ticket exists, or the ticket is not valid for access to the Zetkin API,
this middleware redirects the user to the login page as defined by the
`loginUrl` option, sending along the application ID as defined by `app.id` as
well as the requested path from `req.path`.

```javascript
let opts = {
    app: {
        id: 'myAppId'
    }
};

app.all([ '/a/protected/path', '/another/protected/path' ], validate(opts));
```

The user will be required to log in before returning to the application, where
the `callback()` endpoint can be used to finish the login flow.

### `login(options)`
This function creates an endpoint that will redirect the user to the correct
login URL, and then back to whatever is submitted as `redirPath` in the query
string. This lets you easily create login links.

```javascript
app.get('/login', login(opts));
```

A login link could then point to _/login?redirPath=/restricted_.

### `logout(options)`
This function creates an endpoint that instantly logs the current user out and
redirects them to the path given by `logoutRedirPath`, or `defaultRedirPath` as
a fallback.

```javascript
app.all('/logout', logout());
```
