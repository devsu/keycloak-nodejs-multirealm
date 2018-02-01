const Keycloak = require('keycloak-connect');
const NodeCache = require('node-cache');
const composable = require('composable-middleware');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

const Admin = require(path.join(process.cwd(), './node_modules/keycloak-connect/middleware/admin'));
const Logout = require(path.join(process.cwd(), './node_modules/keycloak-connect/middleware/logout'));
const PostAuth = require(path.join(process.cwd(), './node_modules/keycloak-connect/middleware/post-auth'));
const GrantAttacher = require(path.join(process.cwd(), './node_modules/keycloak-connect/middleware/grant-attacher'));
const Protect = require(path.join(process.cwd(), './node_modules/keycloak-connect/middleware/protect'));

const cache = new NodeCache();

const defaultOptions = {
  'admin': '/',
  'logout': '/logout',
};

module.exports = class {
  constructor(config, keycloakConfig) {
    if (!config) {
      throw new Error('Adapter configuration must be provided.');
    }
    this.config = config;
    this.keycloakConfig = this._getKeycloakConfig(keycloakConfig);
  }

  middleware(customOptions) {
    const options = Object.assign({}, defaultOptions, customOptions);
    return (req, res, next) => {
      const realm = this.getRealmName(req);
      if (!realm) {
        return next();
      }
      req.kauth = {realm};
      const keycloakObject = this.getKeycloakObjectForRealm(realm);
      /* eslint-disable new-cap */
      const middleware = composable(
        PostAuth(keycloakObject),
        Admin(keycloakObject, options.admin),
        GrantAttacher(keycloakObject),
        Logout(keycloakObject, options.logout),
      );
      /* eslint-enable new-cap */
      middleware(req, res, next);
    };
  }

  protect(spec) {
    return (req, res, next) => {
      const realm = this.getRealmName(req);
      if (!realm) {
        return this.accessDenied(req, res);
      }
      const keycloakObject = this.getKeycloakObjectForRealm(realm);
      // eslint-disable-next-line new-cap
      Protect(keycloakObject, spec)(req, res, next);
    };
  }

  getRealmName(req) {
    const token = this._decodeTokenString(this._getTokenStringFromRequest(req));
    if (token && token.payload && token.payload.iss &&
      token.payload.iss.startsWith(this.keycloakConfig['auth-server-url'])) {
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
   * By default it's empty, so it must be implemented by the user.
   * If not implemented, the admin and logout endpoints won't work.
   *
   * @param {Object} request The HTTP request.
   */
  // eslint-disable-next-line no-unused-vars
  getRealmNameFromRequest(req) {
    // should be implemented by user
  }

  /**
   * It creates a (or returns a cached) keycloak object for the given realm.
   *
   * @param {string} realm The realm name
   * @returns {Object} The keycloak object
   */
  getKeycloakObjectForRealm(realm) {
    let keycloakObject = cache.get(realm);
    if (keycloakObject) {
      return keycloakObject;
    }
    const keycloakConfig = Object.assign({}, this.keycloakConfig, {realm});
    keycloakObject = new Keycloak(this.config, keycloakConfig);
    keycloakObject.authenticated = this.authenticated;
    keycloakObject.deauthenticated = this.deauthenticated;
    cache.set(realm, keycloakObject);
    return keycloakObject;
  }

  /**
   * Replaceable function to handle access-denied responses.
   *
   * In the event the Keycloak middleware decides a user may
   * not access a resource, or has failed to authenticate at all,
   * this function will be called.
   *
   * By default, a simple string of "Access denied" along with
   * an HTTP status code for 403 is returned.  Chances are an
   * application would prefer to render a fancy template.
   */
  accessDenied(req, res) {
    res.status(403).send('Access Denied');
  }

  /**
   * Callback made upon successful authentication of a user.
   *
   * By default, this a no-op, but may assigned to another
   * function for application-specific login which may be useful
   * for linking authentication information from Keycloak to
   * application-maintained user information.
   *
   * The `request.kauth.grant` object contains the relevant tokens
   * which may be inspected.
   *
   * For instance, to obtain the unique subject ID:
   *
   *     request.kauth.grant.id_token.sub => bf2056df-3803-4e49-b3ba-ff2b07d86995
   *
   * @param {Object} request The HTTP request.
   */
  // eslint-disable-next-line no-unused-vars
  authenticated(req) {
    // no-op
  }

  /**
   * Callback made upon successful de-authentication of a user.
   *
   * By default, this is a no-op, but may be used by the application
   * in the case it needs to remove information from the user's session
   * or otherwise perform additional logic once a user is logged out.
   *
   * @param {Object} request The HTTP request.
   */
  // eslint-disable-next-line no-unused-vars
  deauthenticated(req) {
    // no-op
  }

  _getKeycloakConfig(keycloakConfig) {
    if (typeof keycloakConfig === 'string') {
      return JSON.parse(fs.readFileSync(keycloakConfig));
    }
    if (keycloakConfig) {
      return keycloakConfig;
    }
    return JSON.parse(fs.readFileSync(path.join(process.cwd(), 'keycloak.json')));
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
