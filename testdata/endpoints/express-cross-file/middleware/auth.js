exports.requireLogin = (req, res, next) => next();
exports.requireRole = (role) => (req, res, next) => next();
