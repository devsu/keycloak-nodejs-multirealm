const myCache = {
  'get': jest.fn(() => {
    return undefined; // eslint-disable-line no-undefined
  }),
  'set': jest.fn(() => {
    return true;
  }),
};

class NodeCache {
  constructor() {
    return myCache;
  }
}

module.exports = NodeCache;
