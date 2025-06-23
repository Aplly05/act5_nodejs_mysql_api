const jwt = require('jsonwebtoken');
const config = require('config.json');
const db = require('_helpers/db');

module.exports = authorize;

function authorize(roles = []) {
  if (typeof roles === 'string') {
    roles = [roles];
  }

  return [
    // custom JWT auth middleware
    async (req, res, next) => {
      const authHeader = req.headers.authorization;
      const token = authHeader && authHeader.split(' ')[1];

      if (!token) {
        console.log('No token found in Authorization header.');
        return res.status(401).json({ message: 'Missing token' });
      }

      try {
        // Verify token and attach user to request
        const decoded = jwt.verify(token, config.secret);
        req.user = decoded;

        console.log('Decoded JWT:', decoded);

        const account = await db.Account.findByPk(req.user.id);
        if (!account || (roles.length && !roles.includes(account.role))) {
          console.log('Role check failed or account not found');
          return res.status(401).json({ message: 'Unauthorized' });
        }

        req.user.role = account.role;
        const refreshTokens = await account.getRefreshTokens();
        req.user.ownsToken = token => !!refreshTokens.find(x => x.token === token);
        next();
      } catch (err) {
        console.error('JWT verification error:', err.message);
        return res.status(401).json({ message: 'Invalid token', error: err.message });
      }
    }
  ];
}

//MAY-ANN DURA BSIT 2ND YEAR IRREGULAR SUMMER INTPROG2025