# Keycloak Node.js Adapter With Support for multiple realms

Express Middleware that allows authentication / authorization using [Keycloak](http://keycloak.org/). It's similar to the [official adapter](https://github.com/keycloak/keycloak-nodejs-connect), but it allows the application to work with **any** keycloak realm.

Uses the official [Keycloak Node.js Adapter](https://github.com/keycloak/keycloak-nodejs-connect) under the hood.

## Installation

`npm install keycloak-connect keycloak-connect-multirealm`

or

`yarn add keycloak-connect keycloak-connect-multirealm`

Starting from version 1.1.0, `keycloak-connect` is required as a peer dependency. That way you can update `keycloak-connect` module independently from this module.

## Usage

The usage is very similar to the official module:

```javascript

const express = require('express');
const KeycloakMultirealm = require('keycloak-connect-multirealm');

const app = express();

const config = {};

keycloakConfig = {
  'auth-server-url': 'http://localhost:8080/auth',
  'bearer-only': true,
  'ssl-required': 'external',
  'resource': 'my-node-app',
};

// Instantiate the class just as the official module. If no keycloakConfig
// is provided, it will read the configuration from keycloak.json file.

const keycloak = new KeycloakMultirealm(config, keycloakConfig);

// add the middleware

app.use(keycloak.middleware());

// protect any endpoint

app.get('/files', keycloak.protect(), filesEndpointHandler);

```

As you can see, you don't need to set the `realm` in your keycloak configuration. Any of the realms will be accepted.

You can see the official [documentation](http://www.keycloak.org/docs/latest/securing_apps/index.html#_nodejs_adapter) for more examples and options.

### Implementing getRealmNameFromRequest

For requests without token to work (anonymous requests), you must implement the `getRealmNameFromRequest` method. This is required for admin and logout endpoints to work.

The implementation will depend on your specific use case:

```
keycloak.getRealmNameFromRequest = (req) => {
  // for example, you could get the realmName from the path
  return req.originalUrl.split('/')[0];
};

keycloak.getRealmNameFromRequest = (req) => {
  // or from the host
  return req.get('host').split('.')[0];
};

keycloak.getRealmNameFromRequest = (req) => {
  // or from a query string
  return req.query.realm;
};
```

Obviously, for admin endpoints to work, you might need to change the admin URL in the client settings in Keycloak.

## How it works

If the request contains a valid token, it tries to get the realm name from the token.
If the request doesn't contain a valid token, it tries to get the realm name from the `getRealmNameFromRequest` method. (Which by default is empty, and should be implemented if needed)

Then, based on the realm name, uses under the hood the official keycloak-connect module.

When found, this middleware adds the realm name to the request: `req.kauth.realm`.

## Status

Tested on bearer-only applications. If `getRealmNameFromRequest` is properly implemented, it *should* work for public clients as well, but I haven't tested it.

## License and Credits

Copyright 2018, by the [NodeJS Team](https://devsu.com) at Devsu

Apache 2.0 License
