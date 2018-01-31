const Keycloak = require('keycloak-connect');
const jwt = require('jsonwebtoken');
const NodeCache = require('node-cache');
const composable = require('composable-middleware');

jest.mock('../node_modules/keycloak-connect/middleware/admin');
jest.mock('../node_modules/keycloak-connect/middleware/logout');
jest.mock('../node_modules/keycloak-connect/middleware/post-auth');
jest.mock('../node_modules/keycloak-connect/middleware/grant-attacher');
jest.mock('../node_modules/keycloak-connect/middleware/protect');

const Admin = require('../node_modules/keycloak-connect/middleware/admin');
const Logout = require('../node_modules/keycloak-connect/middleware/logout');
const PostAuth = require('../node_modules/keycloak-connect/middleware/post-auth');
const GrantAttacher = require('../node_modules/keycloak-connect/middleware/grant-attacher');
const Protect = require('../node_modules/keycloak-connect/middleware/protect');

const KeycloakMultiRealm = require('./KeycloakMultiRealm');

const keycloakJsonFile = require('../keycloak');
const anotherKeycloakJsonFile = require('../another-keycloak');

describe('KeycloakMultiRealm', () => {
  let keycloakMultiRealm, config, keycloakConfig, req, res, next, userId, keycloakMock, cache, composedMiddleware,
    postAuthMiddleware, adminMiddleware, logoutMiddleware, grantAttacherMiddleware, protectMiddleware;

  // eslint-disable-next-line max-statements
  beforeEach(() => {
    config = {};
    keycloakConfig = {
      'auth-server-url': 'http://localhost:8080/auth',
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

  describe('constructor', () => {
    describe('when no config provided', () => {
      it('should fail (just to maintain consistency with the official module behavior)', () => {
        expect(() => {
          keycloakMultiRealm = new KeycloakMultiRealm(null, keycloakConfig);
        }).toThrow('Adapter configuration must be provided.');
      });
    });

    describe('when no keycloakConfig provided', () => {
      beforeEach(() => {
        keycloakMultiRealm = new KeycloakMultiRealm(config);
      });

      it('should read config from keycloak.json', () => {
        expect(keycloakMultiRealm.keycloakConfig).toEqual(keycloakJsonFile);
      });
    });

    describe('keycloakConfig is a path string', () => {
      beforeEach(() => {
        keycloakMultiRealm = new KeycloakMultiRealm(config, 'another-keycloak.json');
      });

      it('should get config from the given path', () => {
        expect(keycloakMultiRealm.keycloakConfig).toEqual(anotherKeycloakJsonFile);
      });
    });
  });

  describe('middleware()', () => {
    it('should return a middleware function', () => {
      expect(keycloakMultiRealm.middleware()).toEqual(expect.any(Function));
    });

    describe('middleware function', () => {
      let middleware;

      beforeEach(() => {
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
            keycloakMultiRealm.getRealmNameFromRequest = jest.fn().mockReturnValue();
            keycloakMultiRealm.getRealmNameFromToken = jest.fn().mockReturnValue();
          });

          it('should not set req.kauth object', () => {
            middleware(req, res, next);
            expect(req.kauth).toBeUndefined();
          });
        });

        describe('realm found', () => {
          const realm = 'devsu';

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

            it('should add the authenticated and deauthenticated callbacks to the keycloak object', () => {
              middleware(req, res, next);
              expect(keycloakMock.authenticated).toBe(keycloakMultiRealm.authenticated);
              expect(keycloakMock.deauthenticated).toBe(keycloakMultiRealm.deauthenticated);
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
            expect(composable).toHaveBeenCalledWith(
              postAuthMiddleware, adminMiddleware, grantAttacherMiddleware, logoutMiddleware
            );
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

          it('should set kauth.realm with the realm name', () => {
            middleware(req, res, next);
            expect(req.kauth.realm).toEqual(realm);
          });
        });
      };

      const runCommonTestsForRequestsWithoutTokenOrWithInvalidToken = () => {
        it('should try to get the realm name using the getRealmNameFromRequest() method', () => {
          keycloakMultiRealm.getRealmNameFromRequest = jest.fn().mockReturnValue();
          keycloakMultiRealm.getRealmNameFromToken = jest.fn();
          middleware(req, res, next);
          expect(keycloakMultiRealm.getRealmNameFromRequest).toHaveBeenCalledTimes(1);
          expect(keycloakMultiRealm.getRealmNameFromRequest).toHaveBeenCalledWith(req);
          expect(keycloakMultiRealm.getRealmNameFromToken).not.toHaveBeenCalled();
        });
      };

      const runCommonTestsForRequestWithValidToken = () => {
        it('should try to get the realm name using the getRealmNameFromToken() method', () => {
          keycloakMultiRealm.getRealmNameFromRequest = jest.fn().mockReturnValue();
          keycloakMultiRealm.getRealmNameFromToken = jest.fn();
          middleware(req, res, next);
          expect(keycloakMultiRealm.getRealmNameFromToken).toHaveBeenCalledTimes(1);
          expect(keycloakMultiRealm.getRealmNameFromRequest).not.toHaveBeenCalled();
        });
      };

      describe('without token', () => {
        runCommonTests();
        runCommonTestsForRequestsWithoutTokenOrWithInvalidToken();
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

          runCommonTestsForRequestsWithoutTokenOrWithInvalidToken();
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

          runCommonTestsForRequestsWithoutTokenOrWithInvalidToken();
          runCommonTests();
        });
      });

      describe('with valid token', () => {
        let serverUrl, payload, token, realm, iss;

        beforeEach(() => {
          serverUrl = 'http://localhost:8080/auth';
          realm = 'devsu';
          iss = `${serverUrl}/auth/realms/${realm}`;
          payload = {
            'sub': userId,
            'iss': iss,
          };
          token = jwt.sign(payload, 'secret!');
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

  describe('protect()', () => {
    it('should return a function', () => {
      expect(keycloakMultiRealm.protect()).toEqual(expect.any(Function));
    });

    describe('protect middleware function', () => {
      let protect, spec;

      beforeEach(() => {
        spec = 'whatever';
        protect = keycloakMultiRealm.protect(spec);
      });

      const runCommonTestsForRequestWithoutTokenOrWithInvalidToken = () => {
        beforeEach(() => {
          keycloakMultiRealm.accessDenied = jest.fn();
        });

        it('should call accessDenied method', () => {
          protect(req, res, next);
          expect(keycloakMultiRealm.accessDenied).toHaveBeenCalledTimes(1);
          expect(keycloakMultiRealm.accessDenied).toHaveBeenCalledWith(req, res);
        });

        it('should not call Protect method', () => {
          protect(req, res, next);
          expect(Protect).not.toHaveBeenCalled();
        });

        it('should not call next', () => {
          protect(req, res, next);
          expect(next).not.toHaveBeenCalled();
        });
      };

      const runCommonTestsForRequestsWithValidToken = () => {
        it('should call the protect method on the corresponding keycloak object, with the right arguments', () => {
          protect(req, res, next);
          expect(Protect).toHaveBeenCalledTimes(1);
          expect(Protect).toHaveBeenCalledWith(keycloakMock, spec);
          expect(protectMiddleware).toHaveBeenCalledTimes(1);
          expect(protectMiddleware).toHaveBeenCalledWith(req, res, next);
        });
      };

      describe('without token', () => {
        runCommonTestsForRequestWithoutTokenOrWithInvalidToken();
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

          runCommonTestsForRequestWithoutTokenOrWithInvalidToken();
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

          runCommonTestsForRequestWithoutTokenOrWithInvalidToken();
        });
      });

      describe('with valid token', () => {
        let serverUrl, payload, token, realm, iss;

        beforeEach(() => {
          serverUrl = 'http://localhost:8080/auth';
          realm = 'devsu';
          iss = `${serverUrl}/auth/realms/${realm}`;
          payload = {
            'sub': userId,
            'iss': iss,
          };
          token = jwt.sign(payload, 'secret!');
        });

        describe('with bearer prefix', () => {
          beforeEach(() => {
            const authorization = `Bearer ${token}`;
            req.headers.Authorization = authorization;
          });

          runCommonTestsForRequestsWithValidToken();
        });

        describe('without bearer prefix', () => {
          beforeEach(() => {
            req.headers.Authorization = token;
          });

          runCommonTestsForRequestsWithValidToken();
        });
      });
    });
  });

  describe('accessDenied()', () => {
    it('should return 403 with "access denied" message', () => {
      keycloakMultiRealm.accessDenied(req, res);
      expect(res.status).toHaveBeenCalledTimes(1);
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.send).toHaveBeenCalledTimes(1);
      expect(res.send).toHaveBeenCalledWith('Access Denied');
    });
  });
});
