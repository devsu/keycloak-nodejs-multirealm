const middleware = jest.fn((req, res, next) => {
  next();
});

module.exports = jest.fn(() => {
  return middleware;
});
