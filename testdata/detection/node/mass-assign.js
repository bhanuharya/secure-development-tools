async function createUser(req, res, prisma) {
  const user = await prisma.user.create({ data: req.body });
  res.json(user);
}
