module.exports = function registerOrders(r) {
  r.get('/orders', listOrders);
  r.post('/orders/:id/cancel', cancelOrder);
};
