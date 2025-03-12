const User = require('../models/User');
const { 
  generateAccessToken, 
  generateRefreshToken, 
  verifyRefreshToken 
} = require('../utils/jwt');
const crypto = require('node:crypto');

const setTokens = (res, accessToken, refreshToken) => {
  res.cookie('access_token', accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 15 * 60 * 1000, // 15 minutes
  });
  res.cookie('refresh_token', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });
  // CSRF token for refresh endpoint
  const csrfToken = crypto.randomBytes(16).toString('hex');
  res.cookie('csrf_token', csrfToken, {
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
  return csrfToken;
};

exports.register = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email and password required' });

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'Email already exists' });

    const user = new User({ email, password });
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    user.refreshToken = refreshToken;
    await user.save();

    const csrfToken = setTokens(res, accessToken, refreshToken);
    res.status(201).json({ message: 'User registered successfully', csrfToken });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email and password required' });

    const user = await User.findOne({ email });
    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    user.refreshToken = refreshToken;
    await user.save();

    const csrfToken = setTokens(res, accessToken, refreshToken);
    res.json({ message: 'Logged in successfully', csrfToken,email:user.email });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

exports.refresh = async (req, res) => {
  try {
    const refreshToken = req.cookies.refresh_token;
    const csrfToken = req.cookies.csrf_token;
    const providedCsrf = req.headers['x-csrf-token'];

    if (!refreshToken || !csrfToken || providedCsrf !== csrfToken) {
      return res.status(401).json({ message: 'Invalid refresh or CSRF token' });
    }

    const decoded = verifyRefreshToken(refreshToken);
    const user = await User.findById(decoded.id);
    if (!user || user.refreshToken !== refreshToken) {
      return res.status(401).json({ message: 'Invalid refresh token' });
    }

    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);
    user.refreshToken = newRefreshToken;
    await user.save();

    const newCsrfToken = setTokens(res, newAccessToken, newRefreshToken);
    res.json({ message: 'Token refreshed', csrfToken: newCsrfToken });
  } catch (error) {
    res.status(401).json({ message: 'Invalid refresh token' });
  }
};

exports.logout = async (req, res) => {
  try {
    const refreshToken = req.cookies.refresh_token;
    if (refreshToken) {
      const user = await User.findOne({ refreshToken });
      if (user) {
        user.refreshToken = null;
        await user.save();
      }
    }

    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
    res.clearCookie('csrf_token');
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

exports.getUser = (req, res) => {
  res.json({ user: req.user });
};