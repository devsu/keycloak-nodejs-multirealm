const Keycloak = require('keycloak-connect');
const NodeCache = require('node-cache');
const composable = require('composable-middleware');
const jwt = require('jsonwebtoken');

const Setup = require('../node_modules/keycloak-connect/middleware/setup');
const Admin = require('../node_modules/keycloak-connect/middleware/admin');
const Logout = require('../node_modules/keycloak-connect/middleware/logout');
const PostAuth = require('../node_modules/keycloak-connect/middleware/post-auth');
const GrantAttacher = require('../node_modules/keycloak-connect/middleware/grant-attacher');
const Protect = require('../node_modules/keycloak-connect/middleware/protect');

const cache = new NodeCache();

const defaultOptions = {
  'admin': '/',
  'logout': '/logout',
};

module.exports = class {
  constructor(config, keycloakConfig) {
    this.config = config;
    this.keycloakConfig = keycloakConfig;
  }

  middleware(customOptions) {
    const options = Object.assign({}, defaultOptions, customOptions);
    return (req, res, next) => {
      let realm = this.getRealmName(req);
      if (!realm) {
        return next();
      }
      let keycloakObject = this._getKeycloakObject(realm);
      const middleware = composable(
        Setup,
        PostAuth(keycloakObject),
        Admin(keycloakObject, options.admin),
        GrantAttacher(keycloakObject),
        Logout(keycloakObject, options.logout),
      );
      middleware(req, res, next);
    };
  }

  getRealmName(req) {
    const token = this._decodeTokenString(this._getTokenStringFromRequest(req));
    if (token && token.payload && token.payload.iss && token.payload.iss.startsWith(this.keycloakConfig['auth-server-url'])) {
      return this.getRealmNameFromToken(token);
    }
    return this.getRealmNameFromRequest(req);
  }

  getRealmNameFromToken(token) {
    return token.payload.iss.split('/').pop();
  }

  /**
   * Method that should return the realm name for the given request.
   *
   * It will be called when the request doesn't have a valid token.
   *
   * By default it's empty, so it must be implemented by the user for admin and logout endpoints to work.
   *
   * @param {Object} request The HTTP request.
   */
  getRealmNameFromRequest(req) {
    // should be implemented by user
  }

  protect() {

  }

  _getKeycloakObject(realm) {
    let keycloakObject = cache.get(realm);
    if (keycloakObject) {
      return keycloakObject;
    }
    const keycloakConfig = Object.assign({}, this.keycloakConfig, {realm});
    keycloakObject = new Keycloak(this.config, keycloakConfig);
    cache.set(realm, keycloakObject);
    return keycloakObject;
  }

  _decodeTokenString(tokenString) {
    return jwt.decode(tokenString, {'complete': true});
  }

  _getTokenStringFromRequest(req) {
    const authorization = req.headers.authorization || req.headers.Authorization;
    if (!authorization) {
      return;
    }
    if (authorization.toLowerCase().startsWith('bearer')) {
      return authorization.split(' ').pop();
    }
    return authorization;
  }
};