const myKeycloak = {
  'accessDenied': jest.fn(),
};

class Keycloak {
  constructor() {
    myKeycloak.constructorArguments = Array.prototype.slice.call(arguments);
    myKeycloak.constructorCount++;
    return myKeycloak;
  }
}

module.exports = Keycloak;
