const request = require('supertest');
const { app } = require('../server');

test('lists orders', async () => {
  await request(app).get('/api/orders');
});

test('closes an account', async () => {
  await request(app).delete('/api/accounts/42');
});
