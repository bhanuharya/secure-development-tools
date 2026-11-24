async function createUserSafe(req, res, prisma) {
  const { displayName, bio } = req.body;
  const user = await prisma.user.create({ data: { displayName, bio } });
  res.json(user);
}
