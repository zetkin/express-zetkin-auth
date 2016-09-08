# express-zetkin-auth
Express middleware for dealing with common tasks related to authentication and
authorization with the Zetkin Platform. It contains middleware functions and
endpoint handlers for:

* Cookie handling for Zetkin API ticket
* Validating ticket ahead of endpoints that require it
* Redirecting to, and handling redirects back from login flow
* Logging out
