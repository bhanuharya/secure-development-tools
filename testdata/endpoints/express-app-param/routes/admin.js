const { requireRole } = require('../auth');

exports.register = (target) => {
  target.delete('/admin/users/:id', requireRole('admin'), deleteUser);
};
