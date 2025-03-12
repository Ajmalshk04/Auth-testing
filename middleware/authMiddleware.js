const { verifyAccessToken } = require('../utils/jwt');

const authMiddleware = async (req, res, next) => {
  try {
    const token = req.cookies.access_token;
    if (!token) {
      return res.status(401).json({ message: 'No access token provided' });
    }

    const decoded = verifyAccessToken(token);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid or expired access token' });
  }
};

module.exports = authMiddleware;