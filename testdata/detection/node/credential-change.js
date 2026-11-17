const router = require('express').Router();

// Any logged-in caller resets the password of the account in the URL.
router.put('/users/:id/reset-password', authenticate, async (req, res) => {
  await users.updatePassword(req.params.id, req.body.password);
  res.json({ ok: true });
});
