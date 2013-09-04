# WebID middleware for express/connect

A WebID authentication middleware module for express/connect applications. 

See also:

* [WebID specifications](https://dvcs.w3.org/hg/WebID/raw-file/tip/spec/index.html)

## Usage

Example code:

`var expressWebId = require('express-webid');`
`var options = {'getCertificateCallback': expressWebId.getCertificateFromConnection, 'defaultAgent': 'http://example.com/card#me'};`
`app.use(expressWebId.login(options));`

This code registers the middleware to the express application.
The certificate will be read from the connection.
If the authentication fails the agent `http://example.com/card#me` will be used for the session.

## API

### login(options)

Returns the middleware function.
The following options are accepted:

* `getCertificateCallback` The function which should be used to fetch the certificate (default: `getCertificateFromConnection`)
* `defaultAgent` The default agent if the authentication process fails (default: '_:anonymous')
* `doRenegotiation` Use renegotiation to ask for a certificate (currently not supported by Node.js, default: false)

### getCertificateFromConnection(req)

Returns the certificate bind to the connection.

### getCertificateFromHeader(req)

Returns the certificate from the header field `ssl_client_cert`.
This should be used only for applications behind reverse proxies!
Currently this is the only workaround to use renegotiation for a single resource.

Example Apache configuration:

    <Location /login-webid>
      SSLOptions +ExportCertData
      SSLVerifyClient optional_no_ca

      # clear header field -> prevent injection!
      RequestHeader set SSL_CLIENT_CERT ""
      RequestHeader set SSL_CLIENT_CERT "%{SSL_CLIENT_CERT}s"
    </Location>
