module.exports = (srv) => {
  srv.get('/health', (req, res) => res.send('ok'));
};
