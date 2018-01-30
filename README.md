# Keycloak Node.js Adapter With Support for multiple realms

Express Middleware that allows authentication / authorization of requests against any realm in a Keycloak server.

**Important: It works only for `bearer only` clients!**

Uses the official [Keycloak Node.js Adapter](https://github.com/keycloak/keycloak-nodejs-connect) under the hood.

## Usage

Instantiate the class passing the options, the methods `middleware` and `protect` are available. Use them in a similar manner as the official connector. You don't need to set the `realm` in the `keycloak.json` file, since any of the realms in the keycloak server will be accepted.

## License and Credits

Copyright 2017, by the [NodeJS Experts](https://devsu.com) at Devsu

Apache 2.0 License