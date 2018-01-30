const Keycloak = require('keycloak-connect');
const jwt = require('jsonwebtoken');
const NodeCache = require('node-cache');
const composable = require('composable-middleware');

jest.mock('../node_modules/keycloak-connect/middleware/setup');
jest.mock('../node_modules/keycloak-connect/middleware/admin');
jest.mock('../node_modules/keycloak-connect/middleware/logout');
jest.mock('../node_modules/keycloak-connect/middleware/post-auth');
jest.mock('../node_modules/keycloak-connect/middleware/grant-attacher');
jest.mock('../node_modules/keycloak-connect/middleware/protect');

const Setup = require('../node_modules/keycloak-connect/middleware/setup');
const Admin = require('../node_modules/keycloak-connect/middleware/admin');
const Logout = require('../node_modules/keycloak-connect/middleware/logout');
const PostAuth = require('../node_modules/keycloak-connect/middleware/post-auth');
const GrantAttacher = require('../node_modules/keycloak-connect/middleware/grant-attacher');
const Protect = require('../node_modules/keycloak-connect/middleware/protect');

const KeycloakMultiRealm = require('./KeycloakMultiRealm');

describe('KeycloakMultiRealm', () => {
  let keycloakMultiRealm, config, keycloakConfig, req, res, next, userId, keycloakMock, cache, composedMiddleware,
    postAuthMiddleware, adminMiddleware, logoutMiddleware, grantAttacherMiddleware, protectMiddleware, options;

  beforeEach(() => {
    options = {};
    config = {};
    keycloakConfig = {
      'auth-server-url': "http://localhost:8080/auth",
      'bearer-only': true,
      'ssl-required': 'external',
      'resource': 'my-node-app',
    };
    req = {'obj': 'req', 'headers': {}, 'url': 'url'};
    res = {
      'obj': 'res',
      'status': jest.fn(() => {
        return res;
      }),
      'send': jest.fn(() => {
        return res;
      }),
    };
    next = jest.fn();
    userId = 'me';
    keycloakMock = new Keycloak();
    keycloakMock.constructorCount = 0;
    delete keycloakMock.constructorArguments;
    keycloakMultiRealm = new KeycloakMultiRealm(config, keycloakConfig);

    cache = new NodeCache();
    cache.get = jest.fn();
    cache.get.mockClear();
    cache.set.mockClear();

    composedMiddleware = composable();
    composable.mockClear();
    composedMiddleware.mockClear();

    Setup.mockClear();

    postAuthMiddleware = jest.fn();
    PostAuth.mockReturnValue(postAuthMiddleware);
    PostAuth.mockClear();

    adminMiddleware = jest.fn();
    Admin.mockReturnValue(adminMiddleware);
    Admin.mockClear();

    logoutMiddleware = jest.fn();
    Logout.mockReturnValue(logoutMiddleware);
    Logout.mockClear();

    grantAttacherMiddleware = jest.fn();
    GrantAttacher.mockReturnValue(grantAttacherMiddleware);
    GrantAttacher.mockClear();

    protectMiddleware = jest.fn();
    Protect.mockReturnValue(protectMiddleware);
    Protect.mockClear();
  });

  describe('middleware()', () => {
    it('should return a middleware function', () => {
      expect(keycloakMultiRealm.middleware()).toEqual(expect.any(Function));
    });

    describe('middleware function', () => {
      let middleware;

      beforeEach(() => {
        keycloakMultiRealm.getRealmNameFromRequest = jest.fn().mockReturnValue('master');
        keycloakMultiRealm.getRealmNameFromToken = jest.fn();
        middleware = keycloakMultiRealm.middleware();
      });

      const runCommonTests = () => {
        it('should call next once, without error', () => {
          middleware(req, res, next);
          expect(next).toHaveBeenCalledTimes(1);
          expect(next).toHaveBeenCalledWith();
        });

        describe('no realm found', () => {
          beforeEach(() => {
            keycloakMultiRealm.getRealmNameFromRequest = jest.fn().mockReturnValue(null);
          });

          it('should not set req.kauth object', () => {
            middleware(req, res, next);
            expect(req.kauth).toBeUndefined();
          });
        });

        describe('realm found', () => {
          const realm = 'master';

          beforeEach(() => {
            keycloakMultiRealm.getRealmNameFromRequest = jest.fn().mockReturnValue(realm);
          });

          describe('when keycloakObject not cached', () => {
            it('should create a keycloak object and save it to cache', () => {
              const expectedKeycloakConfig = Object.assign({}, keycloakConfig, {realm});
              middleware(req, res, next);
              expect(keycloakMock.constructorCount).toEqual(1);
              expect(keycloakMock.constructorArguments).toEqual([config, expectedKeycloakConfig]);
              expect(cache.get).toHaveBeenCalledTimes(1);
              expect(cache.get).toHaveBeenCalledWith(realm);
              expect(cache.set).toHaveBeenCalledTimes(1);
              expect(cache.set).toHaveBeenCalledWith(realm, keycloakMock);
            });
          });

          describe('when keycloakObject cached', () => {
            let myInstance;

            beforeEach(() => {
              myInstance = {};
              cache.get = jest.fn().mockReturnValue(myInstance);
            });

            it('should use keycloak object from cache', () => {
              middleware(req, res, next);
              expect(cache.get).toHaveBeenCalledTimes(1);
              expect(cache.get).toHaveBeenCalledWith(realm);
              expect(cache.set).not.toHaveBeenCalled();
            });
          });

          it('should call keycloak middleware', () => {
            middleware(req, res, next);
            expect(composable).toHaveBeenCalledTimes(1);
            expect(composable).toHaveBeenCalledWith(Setup, postAuthMiddleware, adminMiddleware, grantAttacherMiddleware, logoutMiddleware);
            expect(composedMiddleware).toHaveBeenCalledTimes(1);
            expect(composedMiddleware).toHaveBeenCalledWith(req, res, next);
          });

          it('should get keycloak middleware using the right arguments', () => {
            middleware(req, res, next);
            expect(PostAuth).toHaveBeenCalledTimes(1);
            expect(PostAuth).toHaveBeenCalledWith(keycloakMock);
            expect(Admin).toHaveBeenCalledTimes(1);
            expect(Admin).toHaveBeenCalledWith(keycloakMock, '/'); // default options.admin
            expect(GrantAttacher).toHaveBeenCalledTimes(1);
            expect(GrantAttacher).toHaveBeenCalledWith(keycloakMock);
            expect(Logout).toHaveBeenCalledTimes(1);
            expect(Logout).toHaveBeenCalledWith(keycloakMock, '/logout'); // default options.logout
          });

          describe('when no options passed', () => {
            it('should use default options', () => {
              middleware(req, res, next);
              expect(Admin).toHaveBeenCalledWith(keycloakMock, '/'); // default options.admin
              expect(Logout).toHaveBeenCalledWith(keycloakMock, '/logout'); // default options.logout
            });
          });

          describe('when passing options.admin', () => {
            it('should use given options.admin', () => {
              middleware = keycloakMultiRealm.middleware({'admin': '/duck'});
              middleware(req, res, next);
              expect(Admin).toHaveBeenCalledWith(keycloakMock, '/duck');
              expect(Logout).toHaveBeenCalledWith(keycloakMock, '/logout');
            });
          });

          describe('when passing options.logout', () => {
            it('should use given options.logout', () => {
              middleware = keycloakMultiRealm.middleware({'logout': '/cat'});
              middleware(req, res, next);
              expect(Admin).toHaveBeenCalledWith(keycloakMock, '/');
              expect(Logout).toHaveBeenCalledWith(keycloakMock, '/cat');
            });
          });
        });
      };

      const runCommonTestsForRequestsWithoutOrWithInvalidToken = () => {
        it('should try to get the realm name using the getRealmNameFromRequest() method', () => {
          middleware(req, res, next);
          expect(keycloakMultiRealm.getRealmNameFromRequest).toHaveBeenCalledTimes(1);
          expect(keycloakMultiRealm.getRealmNameFromRequest).toHaveBeenCalledWith(req);
          expect(keycloakMultiRealm.getRealmNameFromToken).not.toHaveBeenCalled();

        });
      };

      const runCommonTestsForRequestWithValidToken = () => {
        it('should try to get the realm name using the getRealmNameFromToken() method', () => {
          middleware(req, res, next);
          expect(keycloakMultiRealm.getRealmNameFromToken).toHaveBeenCalledTimes(1);
          expect(keycloakMultiRealm.getRealmNameFromRequest).not.toHaveBeenCalled();
        });
      };

      describe('without token', () => {
        beforeEach(() => {
          delete res.authorization;
        });

        runCommonTests();
        runCommonTestsForRequestsWithoutOrWithInvalidToken();
      });

      describe('with invalid token', () => {
        describe('invalid iss', () => {
          let invalidIss;

          beforeEach(() => {
            invalidIss = 'http://invalid.iss/auth/realms/anyRealm';
            const payload = {
              'sub': userId,
              'iss': invalidIss,
            };
            const token = jwt.sign(payload, 'secret!');
            const authorization = `Bearer ${token}`;
            req.headers.Authorization = authorization;
          });

          runCommonTestsForRequestsWithoutOrWithInvalidToken();
          runCommonTests();
        });

        describe('invalid iss - 2', () => {
          let invalidIss;

          beforeEach(() => {
            invalidIss = 'http://invalid.iss/auth/realms/anyRealm?securityHole=http://auth.sm.localhost/auth';
            const payload = {
              'sub': userId,
              'iss': invalidIss,
            };
            const token = jwt.sign(payload, 'secret!');
            const authorization = `Bearer ${token}`;
            req.headers.Authorization = authorization;
          });

          runCommonTestsForRequestsWithoutOrWithInvalidToken();
          runCommonTests();
        });
      });

      describe('with valid token', () => {
        let serverUrl, payload, token, realm, iss, decodedToken;

        beforeEach(() => {
          serverUrl = 'http://localhost:8080/auth';
          realm = 'devsu';
          iss = `${serverUrl}/auth/realms/${realm}`;
          payload = {
            'sub': userId,
            'iss': iss,
          };
          token = jwt.sign(payload, 'secret!');
          decodedToken = jwt.decode(token, {'complete': true});
          keycloakMultiRealm.getRealmNameFromToken = jest.fn().mockReturnValue('master');
        });

        describe('with bearer prefix', () => {
          beforeEach(() => {
            const authorization = `Bearer ${token}`;
            req.headers.Authorization = authorization;
          });

          runCommonTests();
          runCommonTestsForRequestWithValidToken();
        });

        describe('without bearer prefix', () => {
          beforeEach(() => {
            req.headers.Authorization = token;
          });

          runCommonTests();
          runCommonTestsForRequestWithValidToken();
        });
      });
    });
  });

  describe('getRealmNameFromToken()', () => {
    let token;

    beforeEach(() => {
      token = {'payload': {'iss': 'http://localhost:8080/auth/realms/pepito'}};
    });

    it('should return the realm name from the given token', () => {
      expect(keycloakMultiRealm.getRealmNameFromToken(token)).toEqual('pepito');
    });
  });

  describe('getRealmNameFromRequest()', () => {
    it('should return undefined (user should provide implementation)', () => {
      expect(keycloakMultiRealm.getRealmNameFromRequest({})).toBeUndefined();
    });
  });
});