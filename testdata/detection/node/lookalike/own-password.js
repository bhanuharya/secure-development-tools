const router = require('express').Router();

// The account in the URL must be the caller's own.
router.put('/users/:id/change-password', authenticate, async (req, res) => {
  if (req.user.id !== req.params.id) return res.status(403).end();
  await users.changePassword(req.params.id, req.body.oldPassword, req.body.password);
  res.json({ ok: true });
});
