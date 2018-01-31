const index = require('./index');
const KeycloakMultirealm = require('./src/KeycloakMultiRealm');

describe('keycloak-nodejs-multirealm', () => {
  it('must expose the KeycloakMultirealm class', () => {
    expect(index).toBe(KeycloakMultirealm);
  });
});
